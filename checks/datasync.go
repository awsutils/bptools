package checks

import (
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterDataSyncChecks registers DataSync checks.
func RegisterDataSyncChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"datasync-location-object-storage-using-https",
		"Checks if AWS DataSync location object storage servers use the HTTPS protocol to communicate. The rule is NON_COMPLIANT if configuration.ServerProtocol is not 'HTTPS'.",
		"datasync",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			locs, err := d.DataSyncLocationObjectStorageDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, loc := range locs {
				ok := strings.EqualFold(string(loc.ServerProtocol), "HTTPS")
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Server protocol HTTPS"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"datasync-task-data-verification-enabled",
		"Checks if AWS DataSync tasks have data verification enabled to perform additional verification at the end of your transfer. The rule is NON_COMPLIANT if configuration.Options.VerifyMode is 'NONE'.",
		"datasync",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.DataSyncTaskDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, t := range tasks {
				mode := ""
				if t.Options != nil {
					mode = string(t.Options.VerifyMode)
				}
				ok := mode != "NONE" && mode != ""
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "VerifyMode not NONE"})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"datasync-task-logging-enabled",
		"Checks if an AWS DataSync task has Amazon CloudWatch logging enabled. The rule is NON_COMPLIANT if an AWS DataSync task does not have Amazon CloudWatch logging enabled or if the logging level is not equivalent to the logging level that you specify.",
		"datasync",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			tasks, err := d.DataSyncTaskDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for arn, t := range tasks {
				logging := t.CloudWatchLogGroupArn != nil && *t.CloudWatchLogGroupArn != ""
				res = append(res, LoggingResource{ID: arn, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"datasync-task-tagged",
		"Checks if AWS DataSync tasks have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"datasync",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			tasks, err := d.DataSyncTasks.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.DataSyncTaskTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, t := range tasks {
				id := "unknown"
				if t.TaskArn != nil {
					id = *t.TaskArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
