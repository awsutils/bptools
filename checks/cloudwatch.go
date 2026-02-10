package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// RegisterCloudWatchChecks registers CloudWatch checks.
func RegisterCloudWatchChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"cloudwatch-alarm-action-check",
		"This rule checks cloudwatch alarm action check.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			alarms, err := d.CloudWatchAlarms.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, a := range alarms {
				id := alarmID(a)
				hasActions := len(a.AlarmActions) > 0 || len(a.OKActions) > 0 || len(a.InsufficientDataActions) > 0
				res = append(res, ConfigResource{ID: id, Passing: hasActions, Detail: "Alarm actions configured"})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloudwatch-alarm-action-enabled-check",
		"This rule checks cloudwatch alarm action enabled.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			alarms, err := d.CloudWatchAlarms.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, a := range alarms {
				id := alarmID(a)
				enabled := a.ActionsEnabled != nil && *a.ActionsEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudwatch-alarm-resource-check",
		"This rule checks cloudwatch alarm resource check.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			alarms, err := d.CloudWatchAlarms.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, a := range alarms {
				id := alarmID(a)
				ok := len(a.Dimensions) > 0 || a.Metrics != nil
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Alarm has dimensions or metric math"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudwatch-alarm-settings-check",
		"This rule checks cloudwatch alarm settings check.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			alarms, err := d.CloudWatchAlarms.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, a := range alarms {
				id := alarmID(a)
				ok := a.EvaluationPeriods != nil && *a.EvaluationPeriods > 0 && a.Threshold != nil
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "EvaluationPeriods and Threshold configured"})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"cloudwatch-log-group-encrypted",
		"This rule checks cloudwatch log group encrypted.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			groups, err := d.CloudWatchLogGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, g := range groups {
				id := logGroupID(g.LogGroupName)
				encrypted := g.KmsKeyId != nil && *g.KmsKeyId != ""
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cw-loggroup-retention-period-check",
		"This rule checks cw loggroup retention period.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.CloudWatchLogGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, g := range groups {
				id := logGroupID(g.LogGroupName)
				ok := g.RetentionInDays != nil && *g.RetentionInDays > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("RetentionInDays: %v", valueOrZero(g.RetentionInDays))})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"cloudwatch-metric-stream-tagged",
		"This rule checks tagging for CloudWatch metric stream exist.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			streams, err := d.CloudWatchMetricStreams.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.CloudWatchMetricStreamTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, s := range streams {
				id := "unknown"
				if s.Arn != nil {
					id = *s.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}

func alarmID(a cloudwatchtypes.MetricAlarm) string {
	if a.AlarmArn != nil {
		return *a.AlarmArn
	}
	if a.AlarmName != nil {
		return *a.AlarmName
	}
	return "unknown"
}

func logGroupID(name *string) string {
	if name != nil {
		return *name
	}
	return "unknown"
}

func valueOrZero(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}
