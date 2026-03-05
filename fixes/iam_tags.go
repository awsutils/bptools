package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type iamOIDCProviderTaggedFix struct{ clients *awsdata.Clients }

func (f *iamOIDCProviderTaggedFix) CheckID() string             { return "iam-oidc-provider-tagged" }
func (f *iamOIDCProviderTaggedFix) Description() string         { return "Tag IAM OIDC provider" }
func (f *iamOIDCProviderTaggedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *iamOIDCProviderTaggedFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *iamOIDCProviderTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	arn := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing OIDC provider ARN"
		return base
	}

	out, err := f.clients.IAM.GetOpenIDConnectProvider(fctx.Ctx, &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(arn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get OIDC provider: " + err.Error()
		return base
	}
	if len(out.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "OIDC provider already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag IAM OIDC provider " + arn}
		return base
	}

	_, err = f.clients.IAM.TagOpenIDConnectProvider(fctx.Ctx, &iam.TagOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(arn),
		Tags: []iamtypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag OIDC provider: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged IAM OIDC provider " + arn}
	return base
}

type iamSAMLProviderTaggedFix struct{ clients *awsdata.Clients }

func (f *iamSAMLProviderTaggedFix) CheckID() string             { return "iam-saml-provider-tagged" }
func (f *iamSAMLProviderTaggedFix) Description() string         { return "Tag IAM SAML provider" }
func (f *iamSAMLProviderTaggedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *iamSAMLProviderTaggedFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *iamSAMLProviderTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	arn := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing SAML provider ARN"
		return base
	}

	out, err := f.clients.IAM.GetSAMLProvider(fctx.Ctx, &iam.GetSAMLProviderInput{
		SAMLProviderArn: aws.String(arn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get SAML provider: " + err.Error()
		return base
	}
	if len(out.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "SAML provider already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag IAM SAML provider " + arn}
		return base
	}

	_, err = f.clients.IAM.TagSAMLProvider(fctx.Ctx, &iam.TagSAMLProviderInput{
		SAMLProviderArn: aws.String(arn),
		Tags: []iamtypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag SAML provider: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged IAM SAML provider " + arn}
	return base
}

type iamServerCertificateTaggedFix struct{ clients *awsdata.Clients }

func (f *iamServerCertificateTaggedFix) CheckID() string             { return "iam-server-certificate-tagged" }
func (f *iamServerCertificateTaggedFix) Description() string         { return "Tag IAM server certificate" }
func (f *iamServerCertificateTaggedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *iamServerCertificateTaggedFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *iamServerCertificateTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	name := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing server certificate name"
		return base
	}

	out, err := f.clients.IAM.GetServerCertificate(fctx.Ctx, &iam.GetServerCertificateInput{
		ServerCertificateName: aws.String(name),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get server certificate: " + err.Error()
		return base
	}
	if out.ServerCertificate != nil && len(out.ServerCertificate.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "server certificate already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag IAM server certificate " + name}
		return base
	}

	_, err = f.clients.IAM.TagServerCertificate(fctx.Ctx, &iam.TagServerCertificateInput{
		ServerCertificateName: aws.String(name),
		Tags: []iamtypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag server certificate: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged IAM server certificate " + name}
	return base
}
