package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch25(d *awsdata.Data) {
	unsupported := map[string]string{
		"rds-storage-encrypted":                               "Automatic remediation is unsafe: enabling RDS storage encryption generally requires snapshot-and-restore migration planning.",
		"redshift-cluster-configuration-check":                "Automatic remediation is unsafe: Redshift cluster configuration hardening requires workload-specific parameter and networking decisions.",
		"redshift-cluster-kms-enabled":                        "Automatic remediation is unsafe: enabling Redshift KMS encryption requires key policy design and migration planning.",
		"redshift-cluster-multi-az-enabled":                   "Automatic remediation is unsafe: enabling Redshift Multi-AZ requires capacity, cost, and failover impact validation.",
		"redshift-cluster-subnet-group-multi-az":              "Automatic remediation is unsafe: subnet group changes for multi-AZ Redshift require environment-specific network placement decisions.",
		"redshift-require-tls-ssl":                            "Automatic remediation is unsafe: enforcing Redshift TLS/SSL requires coordinated client configuration rollout.",
		"redshift-serverless-default-db-name-check":           "Automatic remediation is unsafe: changing Redshift Serverless default database naming can break dependent clients.",
		"redshift-serverless-namespace-cmk-encryption":        "Automatic remediation is unsafe: enabling Redshift Serverless CMK encryption requires key selection and access-policy validation.",
		"redshift-serverless-workgroup-encrypted-in-transit":  "Automatic remediation is unsafe: enforcing Redshift Serverless encryption in transit requires coordinated client compatibility checks.",
		"redshift-unrestricted-port-access":                   "Automatic remediation is unsafe: tightening Redshift ingress requires application-specific source allowlists.",
		"required-tags":                                       "Automatic remediation is unsafe: organization-required tag keys and values are policy-specific and cannot be inferred safely.",
		"root-account-hardware-mfa-enabled":                   "Automatic remediation is unsafe: enabling root hardware MFA requires interactive device provisioning by the account owner.",
		"s3-access-point-in-vpc-only":                         "Automatic remediation is unsafe: forcing S3 access points to VPC-only may break existing access patterns.",
		"s3-access-point-public-access-blocks":                "Automatic remediation is unsafe: changing access point public access blocks requires validating intended external access behavior.",
		"s3-bucket-blacklisted-actions-prohibited":            "Automatic remediation is unsafe: bucket policy action restrictions must be tailored to workload-specific permissions.",
		"s3-bucket-default-lock-enabled":                      "Automatic remediation is unsafe: enabling S3 Object Lock default retention is irreversible and requires compliance-owner approval.",
		"s3-bucket-mfa-delete-enabled":                        "Automatic remediation is unsafe: enabling S3 MFA delete requires root-account workflow changes and operational coordination.",
		"s3-bucket-policy-grantee-check":                      "Automatic remediation is unsafe: removing bucket policy grantees can break cross-account and service integrations.",
		"s3-bucket-policy-not-more-permissive":                "Automatic remediation is unsafe: reducing bucket policy permissiveness requires workload-specific access analysis.",
		"s3-bucket-tagged":                                    "Automatic remediation is unsafe: required S3 bucket tag sets are organization-specific and cannot be inferred safely.",
		"s3-event-notifications-enabled":                      "Automatic remediation is unsafe: enabling S3 event notifications requires choosing correct destinations and event filters.",
		"s3express-dir-bucket-lifecycle-rules-check":          "Automatic remediation is unsafe: lifecycle rules for S3 Express directory buckets require data-retention policy decisions.",
		"s3-last-backup-recovery-point-created":               "Automatic remediation is unsafe: backup policy schedules and vault selection require workload-specific RPO design.",
		"s3-meets-restore-time-target":                        "Automatic remediation is unsafe: restore-time objective compliance requires architecture and backup strategy changes.",
		"s3-resources-in-logically-air-gapped-vault":          "Automatic remediation is unsafe: air-gapped vault placement requires account-level backup architecture decisions.",
		"s3-resources-protected-by-backup-plan":               "Automatic remediation is unsafe: attaching resources to backup plans requires environment-specific schedule and retention policy choices.",
		"sagemaker-endpoint-config-prod-instance-count":       "Automatic remediation is unsafe: SageMaker production instance count changes affect performance, cost, and availability.",
		"sagemaker-endpoint-configuration-kms-key-configured": "Automatic remediation is unsafe: enabling SageMaker endpoint KMS encryption requires key policy and access validation.",
		"sagemaker-model-in-vpc":                              "Automatic remediation is unsafe: moving SageMaker model hosting into a VPC requires networking and dependency validation.",
		"sagemaker-model-isolation-enabled":                   "Automatic remediation is unsafe: enabling model container isolation may impact model runtime compatibility.",
		"sagemaker-notebook-instance-inside-vpc":              "Automatic remediation is unsafe: moving SageMaker notebook instances into a VPC can break connectivity and user workflows.",
		"sagemaker-notebook-instance-kms-key-configured":      "Automatic remediation is unsafe: enabling SageMaker notebook KMS encryption requires key selection and access-policy planning.",
		"sagemaker-notebook-instance-platform-version":        "Automatic remediation is unsafe: notebook platform version upgrades require dependency and compatibility testing.",
		"sagemaker-notebook-no-direct-internet-access":        "Automatic remediation is unsafe: disabling direct internet access on notebooks requires private dependency access paths.",
		"security-account-information-provided":               "Automatic remediation is unsafe: security contact/account information updates must be validated against organization ownership.",
		"service-vpc-endpoint-enabled":                        "Automatic remediation is unsafe: creating service VPC endpoints requires route, DNS, and policy decisions per environment.",
		"ses-malware-scanning-enabled":                        "Automatic remediation is unsafe: SES malware scanning enforcement requires mail-flow and policy validation.",
		"shield-advanced-enabled-autorenew":                   "Automatic remediation is unsafe: Shield Advanced auto-renew settings require billing and governance approval.",
		"shield-drt-access":                                   "Automatic remediation is unsafe: enabling Shield DRT access requires legal/security approval and support-plan prerequisites.",
		"sns-topic-message-delivery-notification-enabled":     "Automatic remediation is unsafe: SNS delivery status settings require destination-specific logging and IAM role configuration.",
		"sqs-queue-dlq-check":                                 "Automatic remediation is unsafe: DLQ configuration requires workload-specific retry, ordering, and retention decisions.",
		"transfer-workflow-description":                       "Automatic remediation is unsafe: transfer workflow metadata standards are organization-defined and cannot be inferred safely.",
		"vpc-endpoint-enabled":                                "Automatic remediation is unsafe: VPC endpoint creation requires subnet, route-table, DNS, and policy design.",
		"vpc-flow-logs-enabled":                               "Automatic remediation is unsafe: VPC flow log destination, format, and retention settings require environment-specific decisions.",
		"vpc-network-acl-unused-check":                        "Automatic remediation is unsafe: deleting or replacing network ACLs requires dependency analysis across associated subnets.",
		"vpc-peering-dns-resolution-check":                    "Automatic remediation is unsafe: enabling DNS resolution on peering links requires coordinated network and naming validation.",
		"vpc-sg-open-only-to-authorized-ports":                "Automatic remediation is unsafe: security group port restrictions require application-specific traffic allowlists.",
		"vpc-sg-port-restriction-check":                       "Automatic remediation is unsafe: security group port hardening requires workload-specific ingress and egress validation.",
		"vpc-vpn-2-tunnels-up":                                "Automatic remediation is unsafe: VPN tunnel availability depends on on-premises device coordination and provider-specific settings.",
	}

	for id, reason := range unsupported {
		if fix.Lookup(id) == nil {
			fix.Register(&unsupportedFix{checkID: id, reason: reason})
		}
	}

	_ = d
}
