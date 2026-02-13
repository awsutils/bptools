package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cognitoidptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// RegisterCognitoChecks registers Cognito checks.
func RegisterCognitoChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"cognito-identity-pool-unauthenticated-logins",
		"Checks if Amazon Cognito identity pools disallow unauthenticated logins. The rule is NON_COMPLIANT if configuration.AllowUnauthenticatedIdentities is true.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			pools, err := d.CognitoIdentityPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, p := range pools {
				id := identityPoolID(p)
				enabled := !p.AllowUnauthenticatedIdentities
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cognito-identity-pool-unauth-access-check",
		"Checks if Amazon Cognito Identity Pool allows unauthenticated identities. The rule is NON_COMPLIANT if the Identity Pool is configured to allow unauthenticated identities.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			pools, err := d.CognitoIdentityPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range pools {
				id := identityPoolID(p)
				ok := !p.AllowUnauthenticatedIdentities
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AllowUnauthenticatedIdentities: %v", p.AllowUnauthenticatedIdentities)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cognito-userpool-cust-auth-threat-full-check",
		"Checks if Amazon Cognito user pools have threat protection enabled with full-function enforcement mode for custom authentication. This rule is NON_COMPLIANT if threat protection for custom authentication is not set to full-function enforcement mode.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			pools, err := d.CognitoUserPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range pools {
				id := userPoolID(p)
				mode := cognitoidptypes.AdvancedSecurityModeTypeOff
				customMode := cognitoidptypes.AdvancedSecurityEnabledModeTypeAudit
				hasCustomMode := false
				if p.UserPoolAddOns != nil {
					mode = p.UserPoolAddOns.AdvancedSecurityMode
					if p.UserPoolAddOns.AdvancedSecurityAdditionalFlows != nil {
						customMode = p.UserPoolAddOns.AdvancedSecurityAdditionalFlows.CustomAuthMode
						hasCustomMode = true
					}
				}
				ok := mode == cognitoidptypes.AdvancedSecurityModeTypeEnforced &&
					hasCustomMode &&
					customMode == cognitoidptypes.AdvancedSecurityEnabledModeTypeEnforced
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail:  fmt.Sprintf("AdvancedSecurityMode: %s, CustomAuthMode: %s", mode, customMode),
				})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cognito-user-pool-advanced-security-enabled",
		"Checks if an Amazon Cognito user pool has advanced security enabled for standard authentication. The rule is NON_COMPLIANT if advanced security is not enabled. Optionally, you can specify an advanced security mode for the rule to check.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			pools, err := d.CognitoUserPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, p := range pools {
				id := userPoolID(p)
				mode := cognitoidptypes.AdvancedSecurityModeTypeOff
				if p.UserPoolAddOns != nil {
					mode = p.UserPoolAddOns.AdvancedSecurityMode
				}
				enabled := mode != cognitoidptypes.AdvancedSecurityModeTypeOff
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cognito-user-pool-deletion-protection-enabled",
		"Checks whether Amazon Cognito user pools has deletion protection enabled. This rule is NON_COMPLIANT if a user pool has deletion protection disabled.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			pools, err := d.CognitoUserPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, p := range pools {
				id := userPoolID(p)
				enabled := p.DeletionProtection == cognitoidptypes.DeletionProtectionTypeActive
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cognito-user-pool-mfa-enabled",
		"Checks if Amazon Cognito user pools configured with a PASSWORD-only sign-in policy have Multi-Factor Authentication (MFA) enabled. This rule is NON_COMPLIANT if the Cognito user pool configured with PASSWORD only sign in policy does not have MFA enabled.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			pools, err := d.CognitoUserPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, p := range pools {
				id := userPoolID(p)
				passwordOnly := cognitoPasswordOnlySignInPool(p)
				enabled := !passwordOnly || p.MfaConfiguration != cognitoidptypes.UserPoolMfaTypeOff
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cognito-user-pool-password-policy-check",
		"Checks if the password policy for Amazon cognito user pool meets the specified requirements indicated in the parameters. The rule is NON_COMPLIANT if the user pool password policy does not meet the specified requirements.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			pools, err := d.CognitoUserPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range pools {
				id := userPoolID(p)
				policy := p.Policies.PasswordPolicy
				ok := policy != nil && policy.MinimumLength != nil && *policy.MinimumLength >= 8 &&
					policy.RequireUppercase &&
					policy.RequireLowercase &&
					policy.RequireNumbers &&
					policy.RequireSymbols
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Password policy requires length/upper/lower/number/symbol"})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"cognito-user-pool-tagged",
		"Checks if Amazon Cognito user pools have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"cognito",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			pools, err := d.CognitoUserPoolDetails.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.CognitoUserPoolTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, p := range pools {
				id := "unknown"
				key := ""
				if p.Arn != nil {
					id = *p.Arn
					key = *p.Arn
				} else if p.Id != nil {
					id = *p.Id
					key = *p.Id
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[key]})
			}
			return res, nil
		},
	))
}

func identityPoolID(p cognitoidentity.DescribeIdentityPoolOutput) string {
	if p.IdentityPoolId != nil {
		return *p.IdentityPoolId
	}
	if p.IdentityPoolName != nil {
		return *p.IdentityPoolName
	}
	return "unknown"
}

func userPoolID(p cognitoidptypes.UserPoolType) string {
	if p.Arn != nil {
		return *p.Arn
	}
	if p.Id != nil {
		return *p.Id
	}
	return "unknown"
}

func cognitoPasswordOnlySignInPool(p cognitoidptypes.UserPoolType) bool {
	if p.Policies == nil || p.Policies.SignInPolicy == nil {
		return true
	}
	factors := p.Policies.SignInPolicy.AllowedFirstAuthFactors
	if len(factors) != 1 {
		return false
	}
	return factors[0] == cognitoidptypes.AuthFactorTypePassword
}
