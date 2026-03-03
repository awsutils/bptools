package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// cognitoPoolID extracts the pool ID from an ARN or returns the value as-is.
// ARN format: arn:aws:cognito-idp:region:account:userpool/pool-id
func cognitoPoolID(resourceID string) string {
	if strings.HasPrefix(resourceID, "arn:") {
		parts := strings.Split(resourceID, "/")
		return parts[len(parts)-1]
	}
	return resourceID
}

// ── cognito-user-pool-deletion-protection-enabled ────────────────────────────

type cognitoUserPoolDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *cognitoUserPoolDeletionProtectionFix) CheckID() string {
	return "cognito-user-pool-deletion-protection-enabled"
}
func (f *cognitoUserPoolDeletionProtectionFix) Description() string {
	return "Enable deletion protection on Cognito user pool"
}
func (f *cognitoUserPoolDeletionProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cognitoUserPoolDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *cognitoUserPoolDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	poolID := cognitoPoolID(resourceID)

	out, err := f.clients.CognitoIDP.DescribeUserPool(fctx.Ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(poolID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe user pool: " + err.Error()
		return base
	}
	if out.UserPool != nil && out.UserPool.DeletionProtection == cognitotypes.DeletionProtectionTypeActive {
		base.Status = fix.FixSkipped
		base.Message = "deletion protection already active"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable deletion protection on Cognito user pool " + poolID}
		return base
	}

	_, err = f.clients.CognitoIDP.UpdateUserPool(fctx.Ctx, &cognitoidentityprovider.UpdateUserPoolInput{
		UserPoolId:        aws.String(poolID),
		DeletionProtection: cognitotypes.DeletionProtectionTypeActive,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update user pool: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled deletion protection on Cognito user pool " + poolID}
	base.Status = fix.FixApplied
	return base
}

// ── cognito-user-pool-advanced-security-enabled ───────────────────────────────

type cognitoAdvancedSecurityFix struct{ clients *awsdata.Clients }

func (f *cognitoAdvancedSecurityFix) CheckID() string {
	return "cognito-user-pool-advanced-security-enabled"
}
func (f *cognitoAdvancedSecurityFix) Description() string {
	return "Enable advanced security mode on Cognito user pool"
}
func (f *cognitoAdvancedSecurityFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cognitoAdvancedSecurityFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cognitoAdvancedSecurityFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	poolID := cognitoPoolID(resourceID)

	out, err := f.clients.CognitoIDP.DescribeUserPool(fctx.Ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(poolID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe user pool: " + err.Error()
		return base
	}
	if out.UserPool != nil && out.UserPool.UserPoolAddOns != nil &&
		out.UserPool.UserPoolAddOns.AdvancedSecurityMode != cognitotypes.AdvancedSecurityModeTypeOff {
		base.Status = fix.FixSkipped
		base.Message = "advanced security already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable advanced security (AUDIT) on Cognito user pool " + poolID}
		return base
	}

	_, err = f.clients.CognitoIDP.UpdateUserPool(fctx.Ctx, &cognitoidentityprovider.UpdateUserPoolInput{
		UserPoolId: aws.String(poolID),
		UserPoolAddOns: &cognitotypes.UserPoolAddOnsType{
			AdvancedSecurityMode: cognitotypes.AdvancedSecurityModeTypeAudit,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update user pool: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled advanced security (AUDIT) on Cognito user pool " + poolID}
	base.Status = fix.FixApplied
	return base
}

// ── cognito-user-pool-password-policy-check ───────────────────────────────────

type cognitoPasswordPolicyFix struct{ clients *awsdata.Clients }

func (f *cognitoPasswordPolicyFix) CheckID() string {
	return "cognito-user-pool-password-policy-check"
}
func (f *cognitoPasswordPolicyFix) Description() string {
	return "Enforce strong password policy on Cognito user pool"
}
func (f *cognitoPasswordPolicyFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cognitoPasswordPolicyFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cognitoPasswordPolicyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	poolID := cognitoPoolID(resourceID)

	out, err := f.clients.CognitoIDP.DescribeUserPool(fctx.Ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(poolID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe user pool: " + err.Error()
		return base
	}
	if out.UserPool != nil && out.UserPool.Policies != nil {
		p := out.UserPool.Policies.PasswordPolicy
		if p != nil && p.MinimumLength != nil && *p.MinimumLength >= 8 &&
			p.RequireUppercase && p.RequireLowercase && p.RequireNumbers && p.RequireSymbols {
			base.Status = fix.FixSkipped
			base.Message = "password policy already meets requirements"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enforce strong password policy on Cognito user pool " + poolID}
		return base
	}

	_, err = f.clients.CognitoIDP.UpdateUserPool(fctx.Ctx, &cognitoidentityprovider.UpdateUserPoolInput{
		UserPoolId: aws.String(poolID),
		Policies: &cognitotypes.UserPoolPolicyType{
			PasswordPolicy: &cognitotypes.PasswordPolicyType{
				MinimumLength:                 aws.Int32(8),
				RequireUppercase:              true,
				RequireLowercase:              true,
				RequireNumbers:                true,
				RequireSymbols:                true,
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update user pool: " + err.Error()
		return base
	}
	base.Steps = []string{"enforced strong password policy on Cognito user pool " + poolID}
	base.Status = fix.FixApplied
	return base
}

// ── cognito-user-pool-mfa-enabled ─────────────────────────────────────────────

type cognitoMFAFix struct{ clients *awsdata.Clients }

func (f *cognitoMFAFix) CheckID() string {
	return "cognito-user-pool-mfa-enabled"
}
func (f *cognitoMFAFix) Description() string {
	return "Enable MFA (OPTIONAL) on Cognito user pool"
}
func (f *cognitoMFAFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cognitoMFAFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cognitoMFAFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	poolID := cognitoPoolID(resourceID)

	out, err := f.clients.CognitoIDP.DescribeUserPool(fctx.Ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(poolID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe user pool: " + err.Error()
		return base
	}
	if out.UserPool != nil && out.UserPool.MfaConfiguration != cognitotypes.UserPoolMfaTypeOff {
		base.Status = fix.FixSkipped
		base.Message = "MFA already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable MFA (OPTIONAL) on Cognito user pool " + poolID}
		return base
	}

	_, err = f.clients.CognitoIDP.UpdateUserPool(fctx.Ctx, &cognitoidentityprovider.UpdateUserPoolInput{
		UserPoolId:       aws.String(poolID),
		MfaConfiguration: cognitotypes.UserPoolMfaTypeOptional,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update user pool: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled MFA (OPTIONAL) on Cognito user pool " + poolID}
	base.Status = fix.FixApplied
	return base
}
