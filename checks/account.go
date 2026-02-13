package checks

import (
	"errors"

	"bptools/awsdata"
	"bptools/checker"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// RegisterAccountChecks registers account-level checks.
func RegisterAccountChecks(d *awsdata.Data) {
	checker.Register(SingleCheck(
		"account-part-of-organizations",
		"Checks if an AWS account is part of AWS Organizations. The rule is NON_COMPLIANT if an AWS account is not part of AWS Organizations or AWS Organizations master account ID does not match rule parameter MasterAccountId.",
		"organizations",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			org, err := d.OrgAccount.Get()
			if err != nil {
				var notIn *orgtypes.AWSOrganizationsNotInUseException
				if errors.As(err, &notIn) {
					return false, "Account is not part of an AWS Organization", nil
				}
				return false, "Error checking organization", err
			}
			if org != nil && org.Organization != nil && org.Organization.Id != nil {
				return true, "Account is part of an AWS Organization", nil
			}
			return false, "No organization info returned", nil
		},
	))

	checker.Register(SingleCheck(
		"security-account-information-provided",
		"Checks if you have provided security contact information for your AWS account contacts. The rule is NON_COMPLIANT if security contact information within the account is not provided.",
		"account",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			contact, err := d.AccountSecurityContact.Get()
			if err != nil {
				return false, err.Error(), err
			}
			if contact == nil {
				return false, "Security alternate contact not set", nil
			}
			ok := contact.EmailAddress != nil && *contact.EmailAddress != "" && contact.Name != nil && *contact.Name != ""
			if ok {
				return true, "Security alternate contact provided", nil
			}
			return false, "Security alternate contact incomplete", nil
		},
	))
}
