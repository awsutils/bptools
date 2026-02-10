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
		"This rule checks datasync location object storage using HTTPS.",
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
		"This rule checks datasync task data verification enabled.",
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
		"This rule checks datasync task logging enabled.",
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
		"This rule checks datasync task tagged.",
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
