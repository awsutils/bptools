package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch26(d *awsdata.Data) {
	_ = d

	id := "ecs-task-definition-linux-user-non-root"
	if fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{
			checkID: id,
			reason:  "Changing Linux container runtime user across ECS task definitions requires workload-specific permission and rollout validation.",
		})
	}
}
