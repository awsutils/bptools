package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch22(d *awsdata.Data) {
	_ = d

	unsupported := map[string]string{
		"dynamodb-autoscaling-enabled":                 "Enabling or tuning DynamoDB auto scaling can change capacity behavior and cost; thresholds and policies must be validated per table/workload.",
		"dynamodb-in-backup-plan":                      "Attaching DynamoDB tables to AWS Backup plans requires organization-specific plan, retention, and vault selection decisions.",
		"dynamodb-last-backup-recovery-point-created":  "Creating recovery points on demand requires backup cadence and retention decisions that must be aligned with workload RPO requirements.",
		"dynamodb-meets-restore-time-target":           "Meeting restore-time targets requires workload-specific backup architecture and restore validation that cannot be inferred safely.",
		"dynamodb-throughput-limit-check":              "Adjusting DynamoDB throughput strategy and account limits can affect application performance and cost; remediation needs workload-specific review.",
		"ebs-in-backup-plan":                           "Adding EBS volumes to AWS Backup plans requires organization-specific plan, retention, and vault selection decisions.",
		"ebs-last-backup-recovery-point-created":       "Creating EBS recovery points on demand requires backup cadence and retention decisions aligned with workload RPO requirements.",
		"ebs-meets-restore-time-target":                "Meeting EBS restore-time targets requires workload-specific backup architecture and restore validation that cannot be inferred safely.",
		"ebs-optimized-instance":                       "Enabling EBS optimization can change instance cost/performance characteristics and should be validated against workload baselines.",
		"ebs-resources-in-logically-air-gapped-vault":  "Copying recovery points to a logically air-gapped vault requires vault, key, and retention policy decisions tied to organizational controls.",
		"ec2-client-vpn-not-authorize-all":             "Restricting Client VPN authorization rules requires validated user/group access scopes to avoid unintended connectivity loss.",
		"ec2-instance-multiple-eni-check":              "Detaching secondary ENIs can disrupt network paths and appliances; remediation requires workload-specific network design review.",
		"ec2-instance-no-public-ip":                    "Removing public IP reachability requires workload-specific ingress design and migration planning to private access paths.",
		"ec2-instances-in-vpc":                         "Moving EC2 instances into a VPC requires coordinated rebuild/migration and networking changes; safe in-place automation is not possible.",
		"ec2-last-backup-recovery-point-created":       "Creating EC2 recovery points on demand requires backup cadence and retention decisions aligned with workload RPO requirements.",
		"ec2-managedinstance-applications-required":    "Installing required applications on managed instances requires workload-specific package, version, and compatibility validation.",
		"ec2-managedinstance-inventory-blacklisted":    "Changing SSM inventory collection for blacklisted types requires operations policy decisions and instance-management coordination.",
		"ec2-meets-restore-time-target":                "Meeting EC2 restore-time targets requires workload-specific backup architecture and recovery testing that cannot be inferred safely.",
		"ec2-paravirtual-instance-check":               "Migrating paravirtual instances requires instance rebuild/replacement planning and compatibility validation.",
		"ec2-resources-in-logically-air-gapped-vault":  "Copying EC2 recovery points to a logically air-gapped vault requires vault, key, and retention policy decisions tied to organizational controls.",
		"ec2-resources-protected-by-backup-plan":       "Attaching EC2 instances to AWS Backup plans requires organization-specific plan, retention, and vault selection decisions.",
		"ec2-security-group-attached-to-eni":           "Re-associating or deleting unattached security groups requires ownership and dependency validation across ENIs and instances.",
		"ec2-security-group-attached-to-eni-periodic":  "Re-associating or deleting unattached security groups requires ownership and dependency validation across ENIs.",
		"ec2-spot-fleet-request-ct-encryption-at-rest": "Changing Spot Fleet launch parameters for EBS encryption requires coordinated template/config updates and rollout validation.",
		"ec2-stopped-instance":                         "Automatically starting or terminating stopped instances can impact maintenance, forensics, and cost-control workflows.",
		"ec2-traffic-mirror-filter-description":        "Updating traffic mirror filter metadata is low risk but requires naming/description standards that are organization-specific.",
		"ec2-traffic-mirror-target-description":        "Updating traffic mirror target metadata is low risk but requires naming/description standards that are organization-specific.",
		"ec2-volume-inuse-check":                       "Attaching or deleting unattached EBS volumes requires workload and data-retention validation to avoid data loss.",
		"ecr-repository-cmk-encryption-enabled":        "Switching ECR repositories to customer-managed KMS keys requires key policy, grants, and replication compatibility decisions.",
		"ecs-awsvpc-networking-enabled":                "Changing ECS task networking mode requires task definition updates and service/network architecture validation.",
		"ecs-capacity-provider-termination-check":      "Enabling ECS capacity provider managed termination protection requires Auto Scaling and draining-policy validation.",
		"ecs-no-environment-secrets":                   "Automatically rewriting task definitions to remove secret-like environment variables requires secret source mapping and app compatibility validation.",
		"ecs-task-definition-efs-encryption-enabled":   "Enforcing EFS transit encryption in ECS task definitions requires mount compatibility and rollout planning.",
		"ecs-task-definition-log-configuration":        "Adding or changing ECS container log configuration requires destination, retention, and permissions decisions.",
		"ecs-task-definition-memory-hard-limit":        "Setting container hard memory limits requires workload profiling to avoid OOM failures.",
		"ecs-task-definition-network-mode-not-host":    "Changing ECS network mode away from host requires port, service-discovery, and connectivity redesign.",
		"ecs-task-definition-pid-mode-check":           "Changing ECS PID mode can alter runtime behavior and observability; remediation requires workload validation.",
		"ecs-task-definition-user-for-host-mode-check": "Adjusting user/privilege settings for host-mode tasks requires workload-specific runtime and permission validation.",
		"ecs-task-definition-windows-user-non-admin":   "Changing Windows container runtime user requires application permission validation and rollout planning.",
		"efs-access-point-enforce-root-directory":      "Changing EFS access point root directories can break application file paths and requires coordinated rollout.",
		"efs-access-point-enforce-user-identity":       "Enforcing EFS access point POSIX user identity requires workload-specific UID/GID mapping decisions.",
		"efs-encrypted-check":                          "Enabling EFS encryption at rest generally requires creating a new file system and migrating data, which cannot be safely automated in place.",
		"efs-filesystem-ct-encrypted":                  "Enforcing EFS transport/security policy requires workload-specific mount behavior validation and policy design.",
		"efs-in-backup-plan":                           "Attaching EFS file systems to AWS Backup plans requires organization-specific plan, retention, and vault selection decisions.",
		"efs-last-backup-recovery-point-created":       "Creating EFS recovery points on demand requires backup cadence and retention decisions aligned with workload RPO requirements.",
	}

	aliases := map[string]string{
		"dynamodb-resources-protected-by-backup-plan": "dynamodb-in-backup-plan",
		"ebs-resources-protected-by-backup-plan":      "ebs-in-backup-plan",
		"ecs-task-definition-nonroot-user":            "ecs-task-definition-linux-user-non-root",
	}

	for id, reason := range unsupported {
		if fix.Lookup(id) == nil {
			fix.Register(&unsupportedFix{checkID: id, reason: reason})
		}
	}

	for id, target := range aliases {
		if fix.Lookup(id) == nil {
			fix.Register(&aliasFix{checkID: id, target: target})
		}
	}
}
