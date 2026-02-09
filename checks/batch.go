package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
)

func RegisterBatchChecks(d *awsdata.Data) {
	// batch-compute-environment-enabled
	checker.Register(EnabledCheck(
		"batch-compute-environment-enabled",
		"This rule checks Batch compute environment enabled.",
		"batch",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, e := range envs {
				id := "unknown"
				if e.ComputeEnvironmentArn != nil {
					id = *e.ComputeEnvironmentArn
				}
				enabled := e.State == batchtypes.CEStateEnabled && e.Status == batchtypes.CEStatusValid
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// batch-compute-environment-managed
	checker.Register(ConfigCheck(
		"batch-compute-environment-managed",
		"This rule checks Batch compute environment managed.",
		"batch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range envs {
				id := "unknown"
				if e.ComputeEnvironmentArn != nil {
					id = *e.ComputeEnvironmentArn
				}
				ok := e.Type == batchtypes.CETypeManaged
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Type: %s", e.Type)})
			}
			return res, nil
		},
	))

	// batch-compute-environment-tagged
	checker.Register(TaggedCheck(
		"batch-compute-environment-tagged",
		"This rule checks tagging for Batch compute environment.",
		"batch",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.BatchComputeEnvTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, e := range envs {
				if e.ComputeEnvironmentArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *e.ComputeEnvironmentArn, Tags: tags[*e.ComputeEnvironmentArn]})
			}
			return res, nil
		},
	))

	// batch-job-queue-enabled
	checker.Register(EnabledCheck(
		"batch-job-queue-enabled",
		"This rule checks Batch job queue enabled.",
		"batch",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			qs, err := d.BatchJobQueues.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, q := range qs {
				id := "unknown"
				if q.JobQueueArn != nil {
					id = *q.JobQueueArn
				}
				enabled := q.State == batchtypes.JQStateEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// batch-job-queue-tagged
	checker.Register(TaggedCheck(
		"batch-job-queue-tagged",
		"This rule checks tagging for Batch job queue.",
		"batch",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			qs, err := d.BatchJobQueues.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.BatchJobQueueTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, q := range qs {
				if q.JobQueueArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *q.JobQueueArn, Tags: tags[*q.JobQueueArn]})
			}
			return res, nil
		},
	))

	// batch-managed-compute-environment-using-launch-template
	checker.Register(ConfigCheck(
		"batch-managed-compute-environment-using-launch-template",
		"This rule checks Batch managed compute environment using launch template.",
		"batch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range envs {
				id := "unknown"
				if e.ComputeEnvironmentArn != nil {
					id = *e.ComputeEnvironmentArn
				}
				ok := e.Type != batchtypes.CETypeManaged || (e.ComputeResources != nil && e.ComputeResources.LaunchTemplate != nil)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "LaunchTemplate configured"})
			}
			return res, nil
		},
	))

	// batch-managed-compute-env-allocation-strategy-check
	checker.Register(ConfigCheck(
		"batch-managed-compute-env-allocation-strategy-check",
		"This rule checks Batch managed compute environment allocation strategy.",
		"batch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range envs {
				id := "unknown"
				if e.ComputeEnvironmentArn != nil {
					id = *e.ComputeEnvironmentArn
				}
				if e.Type != batchtypes.CETypeManaged || e.ComputeResources == nil {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Not managed"})
					continue
				}
				alloc := e.ComputeResources.AllocationStrategy
				ok := alloc != "BEST_FIT"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AllocationStrategy: %s", alloc)})
			}
			return res, nil
		},
	))

	// batch-managed-compute-env-compute-resources-tagged
	checker.Register(TaggedCheck(
		"batch-managed-compute-env-compute-resources-tagged",
		"This rule checks Batch managed compute env compute resources tagged.",
		"batch",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, e := range envs {
				id := "unknown"
				if e.ComputeEnvironmentArn != nil {
					id = *e.ComputeEnvironmentArn
				}
				tags := map[string]string{}
				if e.ComputeResources != nil {
					tags = e.ComputeResources.Tags
				}
				res = append(res, TaggedResource{ID: id, Tags: tags})
			}
			return res, nil
		},
	))

	// batch-managed-spot-compute-environment-max-bid
	checker.Register(ConfigCheck(
		"batch-managed-spot-compute-environment-max-bid",
		"This rule checks Batch managed spot compute environment max bid.",
		"batch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range envs {
				id := "unknown"
				if e.ComputeEnvironmentArn != nil {
					id = *e.ComputeEnvironmentArn
				}
				if e.ComputeResources == nil || e.ComputeResources.Type != batchtypes.CRTypeSpot {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Not spot"})
					continue
				}
				bid := int32(0)
				if e.ComputeResources.BidPercentage != nil {
					bid = *e.ComputeResources.BidPercentage
				}
				ok := bid > 0 && bid <= 100
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("BidPercentage: %d", bid)})
			}
			return res, nil
		},
	))

	// batch-scheduling-policy-tagged
	checker.Register(TaggedCheck(
		"batch-scheduling-policy-tagged",
		"This rule checks tagging for Batch scheduling policy.",
		"batch",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			pols, err := d.BatchSchedulingPolicies.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.BatchSchedulingPolicyTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, p := range pols {
				if p.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *p.Arn, Tags: tags[*p.Arn]})
			}
			return res, nil
		},
	))
}
