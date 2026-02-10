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
		"This rule checks account membership in organizations.",
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
		"This rule checks security account information provided.",
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
