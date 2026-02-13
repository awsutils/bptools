package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// RegisterCloudWatchChecks registers CloudWatch checks.
func RegisterCloudWatchChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"cloudwatch-alarm-action-check",
		"Checks if CloudWatch alarms have an action configured for the ALARM, INSUFFICIENT_DATA, or OK state. Optionally checks if any actions match a named ARN. The rule is NON_COMPLIANT if there is no action specified for the alarm or optional parameter.",
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
				hasAlarmAction := len(a.AlarmActions) > 0
				hasInsufficientDataAction := len(a.InsufficientDataActions) > 0
				hasOKAction := len(a.OKActions) > 0
				ok := hasAlarmAction || hasInsufficientDataAction || hasOKAction
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail:  fmt.Sprintf("AlarmActions: %d, InsufficientDataActions: %d, OKActions: %d", len(a.AlarmActions), len(a.InsufficientDataActions), len(a.OKActions)),
				})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloudwatch-alarm-action-enabled-check",
		"Checks if Amazon CloudWatch alarms actions are in enabled state. The rule is NON_COMPLIANT if the CloudWatch alarms actions are not in enabled state.",
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
		"Checks if a resource type has a CloudWatch alarm for the named metric. For resource type, you can specify EBS volumes, EC2 instances, Amazon RDS clusters, or S3 buckets. The rule is COMPLIANT if the named metric has a resource ID and CloudWatch alarm.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			alarms, err := d.CloudWatchAlarms.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			targetMetric := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_RESOURCE_METRIC_NAME"))
			targetNamespace := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_RESOURCE_NAMESPACE"))
			targetDimension := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_RESOURCE_DIMENSION"))
			targetResourceIDs := cloudwatchParseCSV(strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_RESOURCE_IDS")))
			if targetMetric == "" {
				targetMetric = "CPUUtilization"
			}
			if targetNamespace == "" {
				targetNamespace = "AWS/EC2"
			}
			if targetDimension == "" {
				targetDimension = "InstanceId"
			}
			matched := 0
			for _, a := range alarms {
				if !cloudwatchAlarmMatchesTarget(a, targetMetric, targetNamespace) {
					continue
				}
				matched++
				id := alarmID(a)
				ok := len(a.Dimensions) > 0 && cloudwatchAlarmHasDimension(a, targetDimension)
				if ok && len(targetResourceIDs) > 0 {
					ok = cloudwatchAlarmHasDimensionValueIn(a, targetDimension, targetResourceIDs)
				}
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail:  fmt.Sprintf("Dimensions configured: %v, target resource match: %v", len(a.Dimensions) > 0, ok),
				})
			}
			if matched == 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "No alarms matched configured metric scope"}}, nil
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudwatch-alarm-settings-check",
		"Checks whether CloudWatch alarms with the given metric name have the specified settings.",
		"cloudwatch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			alarms, err := d.CloudWatchAlarms.Get()
			if err != nil {
				return nil, err
			}
			targetMetric := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_SETTINGS_METRIC_NAME"))
			targetNamespace := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_SETTINGS_NAMESPACE"))
			if targetMetric == "" {
				targetMetric = "CPUUtilization"
			}
			if targetNamespace == "" {
				targetNamespace = "AWS/EC2"
			}
			minEvalRaw := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_SETTINGS_EVALUATION_PERIODS_MIN"))
			maxPeriodRaw := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_SETTINGS_PERIOD_SECONDS_MAX"))
			allowedComparisons := cloudwatchParseCSV(strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_SETTINGS_COMPARISON_OPERATORS")))
			if minEvalRaw == "" {
				minEvalRaw = "2"
			}
			if maxPeriodRaw == "" {
				maxPeriodRaw = "300"
			}
			if len(allowedComparisons) == 0 {
				allowedComparisons = []string{
					"GreaterThanOrEqualToThreshold",
					"GreaterThanThreshold",
					"LessThanThreshold",
					"LessThanOrEqualToThreshold",
				}
			}
			minEvaluationPeriods := int32(0)
			if parsed, err := strconv.Atoi(minEvalRaw); err == nil && parsed > 0 {
				minEvaluationPeriods = int32(parsed)
			}
			maxPeriodSeconds := int32(0)
			if parsed, err := strconv.Atoi(maxPeriodRaw); err == nil && parsed > 0 {
				maxPeriodSeconds = int32(parsed)
			}
			if minEvaluationPeriods == 0 || maxPeriodSeconds == 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "Invalid settings parameters (evaluation periods / period max)"}}, nil
			}
			minThreshold := 0.0
			hasMinThreshold := false
			if v := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_SETTINGS_THRESHOLD_MIN")); v != "" {
				if parsed, err := strconv.ParseFloat(v, 64); err == nil {
					minThreshold = parsed
					hasMinThreshold = true
				}
			}
			maxThreshold := 0.0
			hasMaxThreshold := false
			if v := strings.TrimSpace(os.Getenv("BPTOOLS_CW_ALARM_SETTINGS_THRESHOLD_MAX")); v != "" {
				if parsed, err := strconv.ParseFloat(v, 64); err == nil {
					maxThreshold = parsed
					hasMaxThreshold = true
				}
			}
			var res []ConfigResource
			matched := 0
			for _, a := range alarms {
				if !cloudwatchAlarmMatchesTarget(a, targetMetric, targetNamespace) {
					continue
				}
				matched++
				id := alarmID(a)
				ok := a.EvaluationPeriods != nil && *a.EvaluationPeriods >= minEvaluationPeriods && a.Threshold != nil
				if ok && maxPeriodSeconds > 0 {
					ok = a.Period != nil && *a.Period <= maxPeriodSeconds
				}
				if ok && hasMinThreshold {
					ok = *a.Threshold >= minThreshold
				}
				if ok && hasMaxThreshold {
					ok = *a.Threshold <= maxThreshold
				}
				if ok && len(allowedComparisons) > 0 {
					operator := strings.ToLower(strings.TrimSpace(string(a.ComparisonOperator)))
					allowed := false
					for _, item := range allowedComparisons {
						if operator == strings.ToLower(strings.TrimSpace(item)) {
							allowed = true
							break
						}
					}
					ok = allowed
				}
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail:  fmt.Sprintf("EvalPeriods: %v, Period: %v, Threshold: %v", valueOrZero(a.EvaluationPeriods), valueOrZero(a.Period), valueOrFloat(a.Threshold)),
				})
			}
			if matched == 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "No alarms matched configured metric scope"}}, nil
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"cloudwatch-log-group-encrypted",
		"Checks if Amazon CloudWatch Log Groups are encrypted with any AWS KMS key or a specified AWS KMS key Id. The rule is NON_COMPLIANT if a CloudWatch Log Group is not encrypted with a KMS key or is encrypted with a KMS key not supplied in the rule parameter.",
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
		"Checks if an Amazon CloudWatch LogGroup retention period is set to greater than 365 days or else a specified retention period. The rule is NON_COMPLIANT if the retention period is less than MinRetentionTime, if specified, or else 365 days.",
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
				ok := g.RetentionInDays == nil || *g.RetentionInDays >= 365
				detail := "RetentionInDays: Never Expire"
				if g.RetentionInDays != nil {
					detail = fmt.Sprintf("RetentionInDays: %d", *g.RetentionInDays)
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"cloudwatch-metric-stream-tagged",
		"Checks if Amazon CloudWatch metric streams have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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

func valueOrFloat(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func cloudwatchAlarmMatchesTarget(a cloudwatchtypes.MetricAlarm, metricName, namespace string) bool {
	if metricName != "" {
		if a.MetricName == nil || !strings.EqualFold(*a.MetricName, metricName) {
			return false
		}
	}
	if namespace != "" {
		if a.Namespace == nil || !strings.EqualFold(*a.Namespace, namespace) {
			return false
		}
	}
	return true
}

func cloudwatchAlarmHasDimension(a cloudwatchtypes.MetricAlarm, dimensionName string) bool {
	if dimensionName == "" {
		return len(a.Dimensions) > 0
	}
	for _, d := range a.Dimensions {
		if d.Name != nil && strings.EqualFold(*d.Name, dimensionName) {
			return true
		}
	}
	return false
}

func cloudwatchAlarmHasDimensionValueIn(a cloudwatchtypes.MetricAlarm, dimensionName string, allowedValues []string) bool {
	if len(allowedValues) == 0 {
		return true
	}
	allowedSet := make(map[string]struct{}, len(allowedValues))
	for _, v := range allowedValues {
		allowedSet[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	for _, d := range a.Dimensions {
		if d.Name == nil || d.Value == nil {
			continue
		}
		if dimensionName != "" && !strings.EqualFold(*d.Name, dimensionName) {
			continue
		}
		if _, ok := allowedSet[strings.ToLower(strings.TrimSpace(*d.Value))]; ok {
			return true
		}
	}
	return false
}

func cloudwatchParseCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
