package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch17(d *awsdata.Data) {
	_ = d

	if fix.Lookup("access-keys-rotated") == nil {
		fix.Register(&unsupportedFix{checkID: "access-keys-rotated", reason: "Access key rotation requires credential-owner coordination and staged secret updates; safe in-place automation is not possible."})
	}
	if fix.Lookup("account-part-of-organizations") == nil {
		fix.Register(&unsupportedFix{checkID: "account-part-of-organizations", reason: "Joining an AWS Organization requires management-account invitation flow and governance approval; safe in-place automation is not possible."})
	}
	if fix.Lookup("acm-certificate-expiration-check") == nil {
		fix.Register(&unsupportedFix{checkID: "acm-certificate-expiration-check", reason: "Certificate renewal and replacement depend on domain validation and service cutover planning; safe in-place automation is not possible."})
	}
	if fix.Lookup("acm-certificate-rsa-check") == nil {
		fix.Register(&unsupportedFix{checkID: "acm-certificate-rsa-check", reason: "Replacing certificate key algorithms requires issuing a new certificate and coordinated endpoint rollout; safe in-place automation is not possible."})
	}
	if fix.Lookup("acm-pca-root-ca-disabled") == nil {
		fix.Register(&unsupportedFix{checkID: "acm-pca-root-ca-disabled", reason: "Disabling a private root CA can revoke active trust chains and requires PKI owner review; safe in-place automation is not possible."})
	}
	if fix.Lookup("active-mq-supported-version") == nil {
		fix.Register(&unsupportedFix{checkID: "active-mq-supported-version", reason: "Broker engine upgrades require compatibility testing and maintenance-window planning; safe in-place automation is not possible."})
	}
	if fix.Lookup("approved-amis-by-id") == nil {
		fix.Register(&unsupportedFix{checkID: "approved-amis-by-id", reason: "AMI approval-by-ID is an organization policy decision and cannot be inferred safely in place."})
	}
	if fix.Lookup("approved-amis-by-tag") == nil {
		fix.Register(&unsupportedFix{checkID: "approved-amis-by-tag", reason: "AMI approval-by-tag requires account-specific governance criteria and cannot be inferred safely in place."})
	}
	if fix.Lookup("iam-root-access-key-check") == nil {
		fix.Register(&unsupportedFix{checkID: "iam-root-access-key-check", reason: "Deleting root access keys requires break-glass credential review and ownership confirmation; safe in-place automation is not possible."})
	}
	if fix.Lookup("root-account-mfa-enabled") == nil {
		fix.Register(&unsupportedFix{checkID: "root-account-mfa-enabled", reason: "Enabling root MFA needs interactive device enrollment by the account owner; safe in-place automation is not possible."})
	}
}
