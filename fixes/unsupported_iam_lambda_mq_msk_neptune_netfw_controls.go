package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch24(d *awsdata.Data) {
	const unsupportedReason = "Automatic remediation is unsafe: this control requires environment-specific validation and change planning."

	unsupportedIDs := []string{
		"iam-server-certificate-expiration-check",
		"internet-gateway-authorized-vpc-only",
		"ivs-channel-playback-authorization-enabled",
		"kms-key-policy-no-public-access",
		"lambda-function-settings-check",
		"lambda-inside-vpc",
		"lambda-vpc-multi-az-check",
		"macie-auto-sensitive-data-discovery-check",
		"mq-active-broker-ldap-authentication",
		"mq-active-deployment-mode",
		"mq-active-single-instance-broker-storage-type-efs",
		"mq-rabbit-deployment-mode",
		"msk-connect-connector-logging-enabled",
		"msk-in-cluster-node-require-tls",
		"msk-unrestricted-access-check",
		"nacl-no-unrestricted-ssh-rdp",
		"neptune-cluster-encrypted",
		"neptune-cluster-multi-az-enabled",
		"neptune-cluster-snapshot-encrypted",
		"netfw-multi-az-enabled",
		"netfw-policy-default-action-fragment-packets",
		"netfw-policy-default-action-full-packets",
		"netfw-policy-rule-group-associated",
		"netfw-stateless-rule-group-not-empty",
		"nlb-internal-scheme-check",
		"no-unrestricted-route-to-igw",
		"opensearch-access-control-enabled",
		"opensearch-data-node-fault-tolerance",
		"opensearch-in-vpc-only",
		"opensearch-logs-to-cloudwatch",
		"opensearch-primary-node-fault-tolerance",
		"opensearch-update-check",
		"rabbit-mq-supported-version",
		"rds-cluster-encrypted-at-rest",
		"rds-cluster-multi-az-enabled",
		"rds-db-security-group-not-allowed",
		"rds-enhanced-monitoring-enabled",
		"rds-in-backup-plan",
		"rds-instance-subnet-igw-check",
		"rds-last-backup-recovery-point-created",
		"rds-mariadb-instance-encrypted-in-transit",
		"rds-meets-restore-time-target",
		"rds-mysql-instance-encrypted-in-transit",
		"rds-postgres-instance-encrypted-in-transit",
		"rds-resources-protected-by-backup-plan",
		"rds-snapshot-encrypted",
		"rds-sqlserver-encrypted-in-transit",
	}

	for _, id := range unsupportedIDs {
		if fix.Lookup(id) == nil {
			fix.Register(&unsupportedFix{checkID: id, reason: unsupportedReason})
		}
	}

	taggedIDs := []string{
		"iotevents-alarm-model-tagged",
		"iotevents-detector-model-tagged",
	}

	for _, id := range taggedIDs {
		if fix.Lookup(id) == nil {
			fix.Register(&genericTaggedFix{checkID: id, clients: d.Clients})
		}
	}
}
