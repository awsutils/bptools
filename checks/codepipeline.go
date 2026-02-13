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
		"Checks if the first deployment stage of AWS CodePipeline performs more than one deployment. Optionally checks if each of the subsequent remaining stages deploy to more than the specified number of deployments (deploymentLimit).",
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
		"Checks if each stage in the AWS CodePipeline deploys to more than N times the number of the regions the AWS CodePipeline has deployed in all the previous combined stages, where N is the region fanout number. The first deployment stage can deploy to a maximum of one region and the second deployment stage can deploy to a maximum number specified in the regionFanoutFactor. If you do not provide a regionFanoutFactor, by default the value is three. For example: If 1st deployment stage deploys to one region and 2nd deployment stage deploys to three regions, 3rd deployment stage can deploy to 12 regions, that is, sum of previous stages multiplied by the region fanout (three) number. The rule is NON_COMPLIANT if the deployment is in more than one region in 1st stage or three regions in 2nd stage or 12 regions in 3rd stage.",
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
