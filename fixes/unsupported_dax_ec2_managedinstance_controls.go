package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch20(d *awsdata.Data) {
	unsupported := map[string]string{
		"dax-encryption-enabled":                                  "DAX encryption changes can require table key strategy and client-compatibility decisions that must be validated per workload.",
		"dax-tls-endpoint-encryption":                             "Enabling DAX TLS endpoints requires workload-specific certificate, client library, and connection rollout planning.",
		"ec2-instance-launched-with-allowed-ami":                  "Selecting an allowed AMI requires workload-specific baseline, hardening, and software compatibility decisions.",
		"ec2-no-amazon-key-pair":                                  "Removing or replacing EC2 key pairs requires workload-specific access and break-glass strategy decisions.",
		"ec2-instance-profile-attached":                           "Attaching an EC2 instance profile requires workload-specific IAM least-privilege policy design.",
		"ec2-instance-managed-by-systems-manager":                 "Enrolling instances in Systems Manager requires workload-specific agent, network, and operational access decisions.",
		"ec2-managedinstance-patch-compliance-status-check":       "Patch compliance remediation requires workload-specific maintenance windows, approval gates, and reboot strategy decisions.",
		"ec2-managedinstance-association-compliance-status-check": "Association compliance remediation requires workload-specific SSM document selection and execution targeting decisions.",
		"ec2-managedinstance-platform-check":                      "Managed instance platform alignment requires workload-specific OS support and lifecycle decisions.",
		"ec2-managedinstance-applications-blacklisted":            "Application blacklist remediation requires workload-specific software allowlist and business dependency decisions.",
	}

	for id, reason := range unsupported {
		if fix.Lookup(id) == nil {
			fix.Register(&unsupportedFix{checkID: id, reason: reason})
		}
	}

	_ = d
}
