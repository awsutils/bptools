package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterFISChecks registers FIS checks.
func RegisterFISChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"fis-experiment-template-log-configuration-exists",
		"This rule checks fis experiment template log configuration exists.",
		"fis",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			templates, err := d.FISExperimentTemplateDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, t := range templates {
				hasLog := t.LogConfiguration != nil && (t.LogConfiguration.CloudWatchLogsConfiguration != nil || t.LogConfiguration.S3Configuration != nil)
				res = append(res, ConfigResource{ID: id, Passing: hasLog, Detail: "Log configuration configured"})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"fis-experiment-template-tagged",
		"This rule checks fis experiment template tagged.",
		"fis",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			templates, err := d.FISExperimentTemplateDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for id, t := range templates {
				res = append(res, TaggedResource{ID: id, Tags: t.Tags})
			}
			return res, nil
		},
	))
}
