package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
)

func RegisterBatchChecks(d *awsdata.Data) {
	// batch-compute-environment-enabled
	checker.Register(EnabledCheck(
		"batch-compute-environment-enabled",
		"Checks if AWS Batch compute environments are enabled. The rule is NON_COMPLIANT if configuration.State is 'DISABLED'.",
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
				enabled := e.State == batchtypes.CEStateEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// batch-compute-environment-managed
	checker.Register(ConfigCheck(
		"batch-compute-environment-managed",
		"Checks if AWS Batch compute environments are managed. The rule is NON_COMPLIANT if configuration.Type is 'UNMANAGED'.",
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
		"Checks if AWS Batch compute environments have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if AWS Batch job queues are enabled. The rule is NON_COMPLIANT if configuration.State is 'DISABLED'.",
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
		"Checks if AWS Batch job queues have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if AWS Batch managed compute environments are configured using a launch template. The rule is NON_COMPLIANT if configuration.ComputeResources.LaunchTemplate does not exist.",
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
				ok := false
				if e.ComputeResources != nil && e.ComputeResources.LaunchTemplate != nil {
					lt := e.ComputeResources.LaunchTemplate
					ok = (lt.LaunchTemplateId != nil && strings.TrimSpace(*lt.LaunchTemplateId) != "") ||
						(lt.LaunchTemplateName != nil && strings.TrimSpace(*lt.LaunchTemplateName) != "")
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Type: %s, LaunchTemplate reference configured: %v", e.Type, ok)})
			}
			return res, nil
		},
	))

	// batch-managed-compute-env-allocation-strategy-check
	checker.Register(ConfigCheck(
		"batch-managed-compute-env-allocation-strategy-check",
		"Checks if an AWS Batch managed compute environment is configured with a specified allocation strategy. The rule is NON_COMPLIANT if the compute environment is not configured with an allocation strategy specified in the required rule parameter.",
		"batch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			allowedStrategies := batchAllowedAllocationStrategies()
			for _, e := range envs {
				id := "unknown"
				if e.ComputeEnvironmentArn != nil {
					id = *e.ComputeEnvironmentArn
				}
				if e.Type != batchtypes.CETypeManaged || e.ComputeResources == nil {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Not managed"})
					continue
				}
				alloc := strings.ToUpper(strings.TrimSpace(string(e.ComputeResources.AllocationStrategy)))
				ok := allowedStrategies[alloc]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AllocationStrategy: %s", alloc)})
			}
			return res, nil
		},
	))

	// batch-managed-compute-env-compute-resources-tagged
	checker.Register(TaggedCheck(
		"batch-managed-compute-env-compute-resources-tagged",
		"Checks if AWS Batch managed compute environments compute resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. Tags starting with 'aws:' are not checked.",
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
		"Checks if an AWS Batch managed Spot compute environment is configured to have a bid percentage less than or equal to the specified value. The rule is NON_COMPLIANT if the bid percentage is greater than the value specified in the required rule parameter.",
		"batch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			envs, err := d.BatchComputeEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			maxBid := batchMaxBidPercentage()
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
				ok := bid > 0 && bid <= maxBid
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("BidPercentage: %d, max allowed: %d", bid, maxBid)})
			}
			return res, nil
		},
	))

	// batch-scheduling-policy-tagged
	checker.Register(TaggedCheck(
		"batch-scheduling-policy-tagged",
		"Checks if AWS Batch scheduling policies have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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

func batchAllowedAllocationStrategies() map[string]bool {
	raw := strings.TrimSpace(os.Getenv("BPTOOLS_BATCH_ALLOWED_ALLOCATION_STRATEGIES"))
	values := []string{
		string(batchtypes.CRAllocationStrategyBestFitProgressive),
		string(batchtypes.CRAllocationStrategySpotCapacityOptimized),
		string(batchtypes.CRAllocationStrategySpotPriceCapacityOptimized),
	}
	if raw != "" {
		parts := strings.Split(raw, ",")
		values = make([]string, 0, len(parts))
		for _, part := range parts {
			item := strings.ToUpper(strings.TrimSpace(part))
			if item != "" {
				values = append(values, item)
			}
		}
	}
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[strings.ToUpper(strings.TrimSpace(value))] = true
	}
	return out
}

func batchMaxBidPercentage() int32 {
	raw := strings.TrimSpace(os.Getenv("BPTOOLS_BATCH_MAX_BID_PERCENTAGE"))
	if raw == "" {
		return 100
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 100
	}
	if value > 100 {
		value = 100
	}
	return int32(value)
}
