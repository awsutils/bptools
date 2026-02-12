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
		"This rule checks COGNITO identity pool unauthenticated logins.",
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
		"This rule checks configuration for COGNITO identity pool unauth access.",
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
		"This rule checks configuration for COGNITO userpool cust auth threat full.",
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
		"This rule checks enabled state for COGNITO user pool advanced security.",
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
		"This rule checks enabled state for COGNITO user pool deletion protection.",
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
		"This rule checks enabled state for COGNITO user pool MFA.",
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
		"This rule checks configuration for COGNITO user pool password policy.",
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
		"This rule checks tagging for COGNITO user pool exist.",
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
