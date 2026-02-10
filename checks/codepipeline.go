package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterCodePipelineChecks registers CodePipeline checks.
func RegisterCodePipelineChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"codepipeline-deployment-count-check",
		"This rule checks configuration for codepipeline deployment count.",
		"codepipeline",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			pipes, err := d.CodePipelineDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, p := range pipes {
				count := 0
				if p.Pipeline != nil {
					for _, s := range p.Pipeline.Stages {
						for _, a := range s.Actions {
							if a.ActionTypeId != nil && a.ActionTypeId.Category == "Deploy" {
								count++
							}
						}
					}
				}
				ok := count > 0
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Deploy actions: %d", count)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codepipeline-region-fanout-check",
		"This rule checks configuration for codepipeline region fanout.",
		"codepipeline",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			pipes, err := d.CodePipelineDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, p := range pipes {
				regions := make(map[string]bool)
				if p.Pipeline != nil {
					for _, s := range p.Pipeline.Stages {
						for _, a := range s.Actions {
							if a.Region != nil && *a.Region != "" {
								regions[*a.Region] = true
							}
						}
					}
				}
				ok := len(regions) > 1
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Regions: %d", len(regions))})
			}
			return res, nil
		},
	))
}
