package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch21(d *awsdata.Data) {
	if id := "cognito-identity-pool-unauth-access-check"; fix.Lookup(id) == nil {
		fix.Register(&aliasFix{checkID: id, target: "cognito-identity-pool-unauthenticated-logins"})
	}

	unsupported := map[string]string{
		"alb-internal-scheme-check":                          "Changing ALB scheme can break ingress paths and requires network and DNS cutover planning.",
		"appconfig-deployment-strategy-replicate-to-ssm":     "Replicating AppConfig strategy data to SSM requires parameter hierarchy and access model decisions.",
		"appconfig-freeform-profile-config-storage":          "Moving freeform AppConfig profiles requires choosing a validated storage backend and migration flow.",
		"appconfig-hosted-configuration-version-description": "Hosted configuration version descriptions require team-specific release metadata conventions.",
		"appflow-flow-trigger-type-check":                    "Changing AppFlow trigger type can alter execution behavior and requires schedule/event design validation.",
		"appsync-associated-with-waf":                        "Associating AppSync with WAF requires environment-specific web ACL selection and rule tuning.",
		"appsync-authorization-check":                        "Changing AppSync authorization modes requires client auth-flow compatibility validation.",
		"appsync-cache-ct-encryption-at-rest":                "AppSync cache at-rest encryption context settings are service-managed and not safely mutable in place.",
		"appsync-cache-ct-encryption-in-transit":             "AppSync cache in-transit encryption context settings are service-managed and not safely mutable in place.",
		"appsync-cache-encryption-at-rest":                   "Enabling AppSync cache encryption at rest requires cache lifecycle planning and potential cache replacement.",
		"appsync-logging-enabled":                            "Enabling AppSync logging requires log destination selection and sensitive-field logging policy decisions.",
		"aurora-global-database-encryption-at-rest":          "Changing Aurora global database encryption requires cluster recreation or controlled migration.",
		"aurora-last-backup-recovery-point-created":          "Creating or validating Aurora recovery points requires backup-window and retention policy decisions.",
		"aurora-meets-restore-time-target":                   "Meeting Aurora restore-time targets requires workload-specific backup and capacity strategy tuning.",
		"aurora-resources-in-logically-air-gapped-vault":     "Air-gapped backup vault placement requires account-boundary and recovery governance decisions.",
		"aurora-resources-protected-by-backup-plan":          "Attaching Aurora resources to backup plans requires retention, schedule, and vault policy selection.",
		"autoscaling-launch-config-hop-limit":                "IMDS hop limit changes for launch configurations require workload network-path validation.",
		"autoscaling-launch-config-public-ip-disabled":       "Disabling public IP assignment in launch configurations can break reachability and bootstrap flows.",
		"autoscaling-launchconfig-requires-imdsv2":           "Requiring IMDSv2 in launch configurations can break legacy bootstrap scripts and agents.",
		"autoscaling-launch-template":                        "Migrating from launch configurations to launch templates requires versioning and rollout coordination.",
		"autoscaling-multiple-az":                            "Expanding Auto Scaling groups across AZs requires subnet capacity and zonal dependency validation.",
		"autoscaling-multiple-instance-types":                "Selecting multiple Auto Scaling instance types requires capacity, pricing, and compatibility choices.",
		"clb-multiple-az":                                    "Adding Classic Load Balancer AZs requires subnet selection and traffic distribution validation.",
		"cloudformation-stack-drift-detection-check":         "Drift detection and reconciliation can surface intentional changes that need human review.",
		"cloudformation-stack-notification-check":            "Stack notifications require environment-specific SNS topic and subscriber policy selection.",
		"cloudformation-stack-service-role-check":            "Assigning CloudFormation service roles requires least-privilege IAM policy design.",
		"cloudfront-config-load":                             "CloudFront configuration load remediation is not safely inferable from rule context alone.",
		"cloudfront-custom-ssl-certificate":                  "Changing CloudFront certificates requires domain ownership validation and cutover planning.",
		"cloudfront-distribution-key-group-enabled":          "Enabling CloudFront key groups requires signer key lifecycle and client token flow setup.",
		"cloudfront-origin-failover-enabled":                 "Origin failover requires health-check, origin-priority, and failback behavior decisions.",
		"cloudfront-s3-origin-non-existent-bucket":           "Repairing missing S3 origins requires choosing the correct bucket and data ownership mapping.",
		"cloudwatch-log-group-encrypted":                     "Encrypting existing log groups requires KMS key policy design and ingestion compatibility checks.",
		"codebuild-project-environment-privileged-check":     "Disabling privileged CodeBuild mode can break Docker-in-Docker builds and needs pipeline redesign.",
		"codebuild-project-envvar-awscred-check":             "Removing AWS credentials from CodeBuild env vars requires secure secret-source migration.",
		"codebuild-project-source-repo-url-check":            "Changing CodeBuild source repository URLs requires repository trust and webhook integration validation.",
		"codedeploy-ec2-minimum-healthy-hosts-configured":    "Minimum healthy host settings require deployment-risk tolerance and capacity decisions.",
		"codedeploy-lambda-allatonce-traffic-shift-disabled": "Lambda traffic-shift strategy changes require release policy and rollback timing decisions.",
		"cognito-userpool-cust-auth-threat-full-check":       "Custom auth threat protection mode changes require sign-in risk policy and UX validation.",
		"custom-eventbus-policy-attached":                    "EventBridge custom bus policies require account and principal trust-boundary decisions.",
		"custom-schema-registry-policy-attached":             "Schema registry policies require account-level producer and consumer authorization decisions.",
		"desired-instance-tenancy":                           "Changing EC2 tenancy can require instance replacement and licensing impact review.",
		"desired-instance-type":                              "Changing EC2 instance type requires workload performance and compatibility validation.",
		"dms-mongo-db-authentication-enabled":                "Enabling DMS MongoDB authentication requires source credential design and connection testing.",
		"dms-neptune-iam-authorization-enabled":              "Enabling DMS Neptune IAM authorization requires role and policy wiring per endpoint.",
		"dms-redis-tls-enabled":                              "Enabling DMS Redis TLS requires endpoint certificate trust and client compatibility planning.",
		"dms-replication-instance-multi-az-enabled":          "Enabling DMS replication Multi-AZ changes cost and failover behavior and needs capacity planning.",
		"dms-replication-not-public":                         "Making DMS replication instances private requires subnet routing and operational access redesign.",
		"docdb-cluster-encrypted":                            "Enabling DocumentDB at-rest encryption requires cluster recreation or controlled data migration.",
	}

	for id, reason := range unsupported {
		if fix.Lookup(id) == nil {
			fix.Register(&unsupportedFix{checkID: id, reason: reason})
		}
	}

	_ = d
}
