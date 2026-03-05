package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch23(d *awsdata.Data) {
	unsupported := map[string]string{
		"efs-meets-restore-time-target":                 "Automatic remediation is unsafe: achieving EFS restore-time targets depends on workload-specific backup architecture and recovery testing.",
		"efs-mount-target-public-accessible":            "Automatic remediation is unsafe: tightening EFS mount target network exposure requires workload-specific connectivity validation.",
		"efs-resources-in-logically-air-gapped-vault":   "Automatic remediation is unsafe: moving EFS backups to logically air-gapped vaults requires organization-specific vault and retention design.",
		"efs-resources-protected-by-backup-plan":        "Automatic remediation is unsafe: assigning EFS resources to backup plans requires workload-specific schedule and retention decisions.",
		"eip-attached":                                  "Automatic remediation is unsafe: attaching or releasing Elastic IPs can disrupt production ingress and dependency routing.",
		"eks-cluster-oldest-supported-version":          "Automatic remediation is unsafe: upgrading EKS clusters requires workload-specific version compatibility and rollout planning.",
		"eks-cluster-secrets-encrypted":                 "Automatic remediation is unsafe: enabling EKS secrets encryption requires KMS key strategy and cluster recreation or migration planning.",
		"eks-cluster-supported-version":                 "Automatic remediation is unsafe: upgrading EKS clusters requires workload-specific version compatibility and rollout planning.",
		"eks-secrets-encrypted":                         "Automatic remediation is unsafe: enabling EKS secrets encryption requires KMS key strategy and cluster recreation or migration planning.",
		"elasticache-rbac-auth-enabled":                 "Automatic remediation is unsafe: enabling ElastiCache RBAC authentication requires coordinated user, token, and client changes.",
		"elasticache-repl-grp-encrypted-at-rest":        "Automatic remediation is unsafe: enabling ElastiCache at-rest encryption can require replacement and workload migration planning.",
		"elasticache-repl-grp-encrypted-in-transit":     "Automatic remediation is unsafe: enforcing ElastiCache in-transit encryption requires client TLS compatibility validation.",
		"elasticache-repl-grp-redis-auth-enabled":       "Automatic remediation is unsafe: enabling Redis AUTH on ElastiCache requires credential rollout across dependent clients.",
		"elasticache-subnet-group-check":                "Automatic remediation is unsafe: changing ElastiCache subnet group placement can impact availability and network reachability.",
		"elasticache-supported-engine-version":          "Automatic remediation is unsafe: upgrading ElastiCache engine versions requires workload-specific compatibility and failover planning.",
		"elasticsearch-in-vpc-only":                     "Automatic remediation is unsafe: restricting Elasticsearch domains to VPC-only access can break existing public integrations.",
		"elasticsearch-logs-to-cloudwatch":              "Automatic remediation is unsafe: enabling Elasticsearch log publishing requires workload-specific log destination and cost controls.",
		"elb-acm-certificate-required":                  "Automatic remediation is unsafe: enforcing ACM certificates on ELB listeners requires certificate issuance and listener migration planning.",
		"elb-custom-security-policy-ssl-check":          "Automatic remediation is unsafe: changing ELB SSL policies can break legacy clients and must be validated per consumer.",
		"elb-internal-scheme-check":                     "Automatic remediation is unsafe: converting ELBs to internal scheme can break internet-facing traffic paths.",
		"elb-predefined-security-policy-ssl-check":      "Automatic remediation is unsafe: changing ELB SSL policies can break legacy clients and must be validated per consumer.",
		"elb-tls-https-listeners-only":                  "Automatic remediation is unsafe: forcing ELB listeners to TLS/HTTPS requires application and client protocol migration planning.",
		"elbv2-acm-certificate-required":                "Automatic remediation is unsafe: enforcing ACM certificates on ELBv2 listeners requires certificate issuance and listener migration planning.",
		"elbv2-listener-encryption-in-transit":          "Automatic remediation is unsafe: enforcing ELBv2 listener encryption requires protocol and certificate rollout validation.",
		"elbv2-multiple-az":                             "Automatic remediation is unsafe: reconfiguring ELBv2 across multiple AZs can alter network topology and traffic behavior.",
		"elbv2-predefined-security-policy-ssl-check":    "Automatic remediation is unsafe: changing ELBv2 SSL policies can break legacy clients and must be validated per consumer.",
		"emr-kerberos-enabled":                          "Automatic remediation is unsafe: enabling EMR Kerberos requires identity integration and cluster lifecycle planning.",
		"emr-master-no-public-ip":                       "Automatic remediation is unsafe: removing EMR master public IP access can break operational access paths.",
		"emr-security-configuration-encryption-rest":    "Automatic remediation is unsafe: enabling EMR at-rest encryption requires key management and job compatibility validation.",
		"emr-security-configuration-encryption-transit": "Automatic remediation is unsafe: enabling EMR in-transit encryption requires endpoint and client compatibility planning.",
		"encrypted-volumes":                             "Automatic remediation is unsafe: enabling encryption for existing volumes can require snapshot, replacement, and downtime coordination.",
		"event-data-store-cmk-encryption-enabled":       "Automatic remediation is unsafe: switching Event Data Store encryption to a CMK requires key policy and access path validation.",
		"evidently-segment-description":                 "Automatic remediation is unsafe: updating CloudWatch Evidently segment metadata is organizational and requires owner-defined conventions.",
		"fms-shield-resource-policy-check":              "Automatic remediation is unsafe: modifying FMS Shield resource policies requires organization-specific governance and exception handling.",
		"fms-webacl-resource-policy-check":              "Automatic remediation is unsafe: modifying FMS WAF resource policies requires organization-specific governance and exception handling.",
		"fms-webacl-rulegroup-association-check":        "Automatic remediation is unsafe: changing FMS WAF rule group associations can affect application behavior and false-positive rates.",
		"fsx-last-backup-recovery-point-created":        "Automatic remediation is unsafe: establishing FSx recovery point cadence requires workload-specific backup windows and retention policy.",
		"fsx-lustre-copy-tags-to-backups":               "Automatic remediation is unsafe: changing FSx backup tag propagation requires organization-specific tag governance alignment.",
		"fsx-meets-restore-time-target":                 "Automatic remediation is unsafe: meeting FSx restore-time targets depends on workload-specific backup architecture and recovery testing.",
		"fsx-ontap-deployment-type-check":               "Automatic remediation is unsafe: changing FSx ONTAP deployment type is a topology decision requiring migration planning.",
		"fsx-openzfs-deployment-type-check":             "Automatic remediation is unsafe: changing FSx OpenZFS deployment type is a topology decision requiring migration planning.",
		"fsx-resources-protected-by-backup-plan":        "Automatic remediation is unsafe: assigning FSx resources to backup plans requires workload-specific schedule and retention decisions.",
		"fsx-windows-deployment-type-check":             "Automatic remediation is unsafe: changing FSx Windows deployment type is a topology decision requiring migration planning.",
		"glue-ml-transform-encrypted-at-rest":           "Automatic remediation is unsafe: enabling Glue ML transform at-rest encryption requires key strategy and job compatibility validation.",
		"glue-spark-job-supported-version":              "Automatic remediation is unsafe: upgrading Glue Spark job versions requires workload-specific dependency and runtime validation.",
		"guardduty-non-archived-findings":               "Automatic remediation is unsafe: archiving GuardDuty findings requires triage policy and investigation workflow decisions.",
		"iam-group-has-users-check":                     "Automatic remediation is unsafe: adding users to IAM groups requires identity owner approval and least-privilege review.",
		"iam-no-inline-policy-check":                    "Automatic remediation is unsafe: replacing inline IAM policies requires policy refactoring and blast-radius review.",
		"iam-policy-in-use":                             "Automatic remediation is unsafe: attaching or detaching IAM policies requires principal-level access analysis and approval.",
	}

	for id, reason := range unsupported {
		if fix.Lookup(id) == nil {
			fix.Register(&unsupportedFix{checkID: id, reason: reason})
		}
	}

	_ = d
}
