package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// ── cloudfront-viewer-policy-https ───────────────────────────────────────────

type cloudFrontHTTPSFix struct{ clients *awsdata.Clients }

func (f *cloudFrontHTTPSFix) CheckID() string {
	return "cloudfront-viewer-policy-https"
}
func (f *cloudFrontHTTPSFix) Description() string {
	return "Enforce HTTPS viewer protocol policy on CloudFront distribution"
}
func (f *cloudFrontHTTPSFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudFrontHTTPSFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudFrontHTTPSFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{
		Id: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil || cfg.DefaultCacheBehavior == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config or default cache behavior is nil"
		return base
	}

	// Check if already compliant
	compliant := (cfg.DefaultCacheBehavior.ViewerProtocolPolicy == cftypes.ViewerProtocolPolicyRedirectToHttps ||
		cfg.DefaultCacheBehavior.ViewerProtocolPolicy == cftypes.ViewerProtocolPolicyHttpsOnly)
	if compliant && cfg.CacheBehaviors != nil {
		for _, cb := range cfg.CacheBehaviors.Items {
			if cb.ViewerProtocolPolicy != cftypes.ViewerProtocolPolicyRedirectToHttps &&
				cb.ViewerProtocolPolicy != cftypes.ViewerProtocolPolicyHttpsOnly {
				compliant = false
				break
			}
		}
	}
	if compliant {
		base.Status = fix.FixSkipped
		base.Message = "HTTPS viewer protocol already enforced"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set ViewerProtocolPolicy=redirect-to-https on CloudFront distribution " + resourceID}
		return base
	}

	// Set redirect-to-https on default and all cache behaviors
	cfg.DefaultCacheBehavior.ViewerProtocolPolicy = cftypes.ViewerProtocolPolicyRedirectToHttps
	if cfg.CacheBehaviors != nil {
		for i := range cfg.CacheBehaviors.Items {
			if cfg.CacheBehaviors.Items[i].ViewerProtocolPolicy == cftypes.ViewerProtocolPolicyAllowAll {
				cfg.CacheBehaviors.Items[i].ViewerProtocolPolicy = cftypes.ViewerProtocolPolicyRedirectToHttps
			}
		}
	}

	_, err = f.clients.CloudFront.UpdateDistribution(fctx.Ctx, &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(resourceID),
		IfMatch:            out.ETag,
		DistributionConfig: cfg,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update distribution: " + err.Error()
		return base
	}
	base.Steps = []string{"set ViewerProtocolPolicy=redirect-to-https on CloudFront distribution " + resourceID}
	base.Status = fix.FixApplied
	return base
}
