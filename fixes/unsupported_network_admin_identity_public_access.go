package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch19(d *awsdata.Data) {
	if id := "restricted-ssh"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: narrowing SSH ingress requires workload-specific source CIDRs and access validation."})
	}
	if id := "restricted-common-ports"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: restricting common inbound ports requires application-specific port and source allowlists."})
	}
	if id := "mfa-enabled-for-iam-console-access"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: enforcing MFA for IAM console users requires identity lifecycle coordination and user enrollment."})
	}
	if id := "rds-cluster-default-admin-check"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: rotating RDS cluster master usernames from defaults requires engine-specific credential migration planning."})
	}
	if id := "rds-instance-default-admin-check"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: rotating RDS instance master usernames from defaults requires engine-specific credential migration planning."})
	}
	if id := "redshift-default-admin-check"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: changing Redshift admin usernames can break dependent clients and requires coordinated credential rollout."})
	}
	if id := "redshift-serverless-default-admin-check"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: changing Redshift Serverless admin usernames requires coordinated credential rotation across dependent workloads."})
	}
	if id := "redshift-default-db-name-check"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: changing the default Redshift database name requires data migration and application connection updates."})
	}
	if id := "mq-no-public-access"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: disabling public access on Amazon MQ brokers can immediately break external client connectivity."})
	}
	if id := "cognito-identity-pool-unauthenticated-logins"; fix.Lookup(id) == nil {
		fix.Register(&unsupportedFix{checkID: id, reason: "Automatic remediation is unsafe: disabling unauthenticated identities in Cognito identity pools can break guest user flows and role mappings."})
	}
}
