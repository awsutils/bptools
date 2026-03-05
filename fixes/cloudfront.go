package fixes

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/fix"
	"bptools/fix/pool"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

type cloudFrontAccessLogsFix struct {
	clients *awsdata.Clients
	pool    *pool.S3BucketPool
}

func newCloudFrontAccessLogsFix(clients *awsdata.Clients, p *pool.S3BucketPool) *cloudFrontAccessLogsFix {
	return &cloudFrontAccessLogsFix{clients: clients, pool: p}
}

func (f *cloudFrontAccessLogsFix) CheckID() string { return "cloudfront-accesslogs-enabled" }
func (f *cloudFrontAccessLogsFix) Description() string {
	return "Enable CloudFront standard access logging"
}
func (f *cloudFrontAccessLogsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudFrontAccessLogsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudFrontAccessLogsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
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
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}
	if cfg.Logging != nil && cfg.Logging.Enabled != nil && *cfg.Logging.Enabled &&
		cfg.Logging.Bucket != nil && strings.TrimSpace(*cfg.Logging.Bucket) != "" {
		base.Status = fix.FixSkipped
		base.Message = "access logging already enabled"
		return base
	}

	targetBucket, steps, err := f.pool.Ensure(fctx.Ctx, pool.S3BucketSpec{
		Purpose:        "cloudfront-logs",
		Region:         "us-east-1",
		BucketPrefix:   "logs-",
		BucketPolicyFn: serviceLogsBucketPolicy,
	}, fctx.DryRun)
	base.Steps = append(base.Steps, steps...)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure logging bucket: " + err.Error()
		return base
	}

	prefix := "cloudfront-access-logs/" + resourceID + "/"
	cfBucket := targetBucket + ".s3.amazonaws.com"

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = append(base.Steps, fmt.Sprintf("would enable CloudFront access logs to bucket %s with prefix %s", cfBucket, prefix))
		return base
	}

	cfg.Logging = &cftypes.LoggingConfig{
		Enabled: aws.Bool(true),
		Bucket:  aws.String(cfBucket),
		Prefix:  aws.String(prefix),
	}

	_, err = f.clients.CloudFront.UpdateDistribution(fctx.Ctx, &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(resourceID),
		IfMatch:            out.ETag,
		DistributionConfig: cfg,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update distribution logging: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = append(base.Steps, fmt.Sprintf("enabled CloudFront access logs to bucket %s with prefix %s", cfBucket, prefix))
	return base
}

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

type cloudFrontDefaultRootObjectFix struct{ clients *awsdata.Clients }

func (f *cloudFrontDefaultRootObjectFix) CheckID() string {
	return "cloudfront-default-root-object-configured"
}
func (f *cloudFrontDefaultRootObjectFix) Description() string {
	return "Set CloudFront default root object"
}
func (f *cloudFrontDefaultRootObjectFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudFrontDefaultRootObjectFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *cloudFrontDefaultRootObjectFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}
	if cfg.DefaultRootObject != nil && strings.TrimSpace(*cfg.DefaultRootObject) != "" {
		base.Status = fix.FixSkipped
		base.Message = "default root object already configured"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set DefaultRootObject=index.html for CloudFront distribution " + resourceID}
		return base
	}
	cfg.DefaultRootObject = aws.String("index.html")
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
	base.Status = fix.FixApplied
	base.Steps = []string{"set DefaultRootObject=index.html for CloudFront distribution " + resourceID}
	return base
}

type cloudFrontNoDeprecatedSSLProtocolsFix struct{ clients *awsdata.Clients }

func (f *cloudFrontNoDeprecatedSSLProtocolsFix) CheckID() string {
	return "cloudfront-no-deprecated-ssl-protocols"
}
func (f *cloudFrontNoDeprecatedSSLProtocolsFix) Description() string {
	return "Remove deprecated SSLv3 origin protocol from CloudFront custom origins"
}
func (f *cloudFrontNoDeprecatedSSLProtocolsFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *cloudFrontNoDeprecatedSSLProtocolsFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *cloudFrontNoDeprecatedSSLProtocolsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}

	changed := false
	for i := range cfg.Origins.Items {
		origin := &cfg.Origins.Items[i]
		if origin.CustomOriginConfig == nil || origin.CustomOriginConfig.OriginSslProtocols == nil {
			continue
		}
		protos := origin.CustomOriginConfig.OriginSslProtocols
		var kept []cftypes.SslProtocol
		for _, p := range protos.Items {
			if strings.EqualFold(string(p), string(cftypes.SslProtocolSSLv3)) {
				changed = true
				continue
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			kept = []cftypes.SslProtocol{cftypes.SslProtocolTLSv12}
			changed = true
		}
		if changed {
			origin.CustomOriginConfig.OriginSslProtocols = &cftypes.OriginSslProtocols{
				Items:    kept,
				Quantity: aws.Int32(int32(len(kept))),
			}
		}
	}
	if !changed {
		base.Status = fix.FixSkipped
		base.Message = "no deprecated SSL protocols found"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would remove SSLv3 from CloudFront custom origins for distribution " + resourceID}
		return base
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
	base.Status = fix.FixApplied
	base.Steps = []string{"removed SSLv3 from CloudFront custom origins for distribution " + resourceID}
	return base
}

type cloudFrontViewerTLSPolicyFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *cloudFrontViewerTLSPolicyFix) CheckID() string { return f.checkID }
func (f *cloudFrontViewerTLSPolicyFix) Description() string {
	return "Set CloudFront viewer minimum TLS policy to TLSv1.2_2019"
}
func (f *cloudFrontViewerTLSPolicyFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *cloudFrontViewerTLSPolicyFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudFrontViewerTLSPolicyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}
	if cfg.ViewerCertificate == nil {
		base.Status = fix.FixSkipped
		base.Message = "viewer certificate not configured (CloudFront default certificate)"
		return base
	}
	if cfg.ViewerCertificate.MinimumProtocolVersion == cftypes.MinimumProtocolVersionTLSv122019 ||
		cfg.ViewerCertificate.MinimumProtocolVersion == cftypes.MinimumProtocolVersionTLSv122021 {
		base.Status = fix.FixSkipped
		base.Message = "viewer minimum TLS policy already compliant"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set ViewerCertificate.MinimumProtocolVersion=TLSv1.2_2019 for CloudFront distribution " + resourceID}
		return base
	}
	cfg.ViewerCertificate.MinimumProtocolVersion = cftypes.MinimumProtocolVersionTLSv122019
	_, err = f.clients.CloudFront.UpdateDistribution(fctx.Ctx, &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(resourceID),
		IfMatch:            out.ETag,
		DistributionConfig: cfg,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update distribution TLS policy: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set ViewerCertificate.MinimumProtocolVersion=TLSv1.2_2019 for CloudFront distribution " + resourceID}
	return base
}

type cloudFrontSniEnabledFix struct{ clients *awsdata.Clients }

func (f *cloudFrontSniEnabledFix) CheckID() string { return "cloudfront-sni-enabled" }
func (f *cloudFrontSniEnabledFix) Description() string {
	return "Set CloudFront SSL support method to sni-only when using custom certificate"
}
func (f *cloudFrontSniEnabledFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudFrontSniEnabledFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *cloudFrontSniEnabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil || cfg.ViewerCertificate == nil {
		base.Status = fix.FixSkipped
		base.Message = "viewer certificate not configured"
		return base
	}
	customCert := (cfg.ViewerCertificate.ACMCertificateArn != nil && strings.TrimSpace(*cfg.ViewerCertificate.ACMCertificateArn) != "") ||
		(cfg.ViewerCertificate.IAMCertificateId != nil && strings.TrimSpace(*cfg.ViewerCertificate.IAMCertificateId) != "")
	if !customCert {
		base.Status = fix.FixSkipped
		base.Message = "distribution is not using a custom certificate"
		return base
	}
	if cfg.ViewerCertificate.SSLSupportMethod == cftypes.SSLSupportMethodSniOnly {
		base.Status = fix.FixSkipped
		base.Message = "SSL support method already sni-only"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set ViewerCertificate.SSLSupportMethod=sni-only for CloudFront distribution " + resourceID}
		return base
	}
	cfg.ViewerCertificate.SSLSupportMethod = cftypes.SSLSupportMethodSniOnly
	_, err = f.clients.CloudFront.UpdateDistribution(fctx.Ctx, &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(resourceID),
		IfMatch:            out.ETag,
		DistributionConfig: cfg,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update distribution SNI setting: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set ViewerCertificate.SSLSupportMethod=sni-only for CloudFront distribution " + resourceID}
	return base
}

type cloudFrontTrafficToOriginEncryptedFix struct{ clients *awsdata.Clients }

func (f *cloudFrontTrafficToOriginEncryptedFix) CheckID() string {
	return "cloudfront-traffic-to-origin-encrypted"
}
func (f *cloudFrontTrafficToOriginEncryptedFix) Description() string {
	return "Set CloudFront custom origin protocol policy to https-only"
}
func (f *cloudFrontTrafficToOriginEncryptedFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *cloudFrontTrafficToOriginEncryptedFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *cloudFrontTrafficToOriginEncryptedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}
	changed := false
	for i := range cfg.Origins.Items {
		origin := &cfg.Origins.Items[i]
		if origin.CustomOriginConfig == nil {
			continue
		}
		if origin.CustomOriginConfig.OriginProtocolPolicy != cftypes.OriginProtocolPolicyHttpsOnly {
			origin.CustomOriginConfig.OriginProtocolPolicy = cftypes.OriginProtocolPolicyHttpsOnly
			changed = true
		}
	}
	if !changed {
		base.Status = fix.FixSkipped
		base.Message = "origin traffic already encrypted"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set custom origins to https-only for CloudFront distribution " + resourceID}
		return base
	}
	_, err = f.clients.CloudFront.UpdateDistribution(fctx.Ctx, &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(resourceID),
		IfMatch:            out.ETag,
		DistributionConfig: cfg,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update distribution origin protocol policy: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set custom origins to https-only for CloudFront distribution " + resourceID}
	return base
}

type cloudFrontAssociatedWithWAFFix struct{ clients *awsdata.Clients }

func (f *cloudFrontAssociatedWithWAFFix) CheckID() string { return "cloudfront-associated-with-waf" }
func (f *cloudFrontAssociatedWithWAFFix) Description() string {
	return "Associate CloudFront distribution with a WAFv2 Web ACL"
}
func (f *cloudFrontAssociatedWithWAFFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *cloudFrontAssociatedWithWAFFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *cloudFrontAssociatedWithWAFFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	distOut, err := f.clients.CloudFront.GetDistribution(fctx.Ctx, &cloudfront.GetDistributionInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution: " + err.Error()
		return base
	}
	if distOut.Distribution == nil || distOut.Distribution.ARN == nil || strings.TrimSpace(*distOut.Distribution.ARN) == "" {
		base.Status = fix.FixFailed
		base.Message = "distribution ARN is missing"
		return base
	}
	distARN := *distOut.Distribution.ARN

	wafOpts := f.clients.WAFv2.Options()
	wafOpts.Region = "us-east-1"
	wafClient := wafv2.New(wafOpts)

	_, err = wafClient.GetWebACLForResource(fctx.Ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: aws.String(distARN)})
	if err == nil {
		base.Status = fix.FixSkipped
		base.Message = "distribution already associated with a Web ACL"
		return base
	}
	var notFound *wafv2types.WAFNonexistentItemException
	if !errors.As(err, &notFound) {
		base.Status = fix.FixFailed
		base.Message = "get web ACL for resource: " + err.Error()
		return base
	}

	var webACLARNs []string
	var marker *string
	for {
		out, err := wafClient.ListWebACLs(fctx.Ctx, &wafv2.ListWebACLsInput{
			Scope:      wafv2types.ScopeCloudfront,
			NextMarker: marker,
			Limit:      aws.Int32(100),
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "list CloudFront Web ACLs: " + err.Error()
			return base
		}
		for _, acl := range out.WebACLs {
			if acl.ARN != nil && strings.TrimSpace(*acl.ARN) != "" {
				webACLARNs = append(webACLARNs, *acl.ARN)
			}
		}
		if out.NextMarker == nil || strings.TrimSpace(*out.NextMarker) == "" {
			break
		}
		marker = out.NextMarker
	}
	if len(webACLARNs) == 0 {
		base.Status = fix.FixFailed
		base.Message = "no CLOUDFRONT scope Web ACL found to associate"
		return base
	}
	if len(webACLARNs) > 1 {
		base.Status = fix.FixFailed
		base.Message = "multiple CLOUDFRONT scope Web ACLs found; refusing to auto-select"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would associate Web ACL %s to CloudFront distribution %s", webACLARNs[0], resourceID)}
		return base
	}
	_, err = wafClient.AssociateWebACL(fctx.Ctx, &wafv2.AssociateWebACLInput{
		ResourceArn: aws.String(distARN),
		WebACLArn:   aws.String(webACLARNs[0]),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "associate web ACL: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("associated Web ACL %s to CloudFront distribution %s", webACLARNs[0], resourceID)}
	return base
}

func cloudFrontEnsureS3OAC(fctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	out, err := clients.CloudFront.CreateOriginAccessControl(fctx.Ctx, &cloudfront.CreateOriginAccessControlInput{
		OriginAccessControlConfig: &cftypes.OriginAccessControlConfig{
			Name:                          aws.String("bptools-s3-oac-" + fmt.Sprintf("%d", time.Now().UnixNano())),
			Description:                   aws.String("Managed by bptools"),
			OriginAccessControlOriginType: cftypes.OriginAccessControlOriginTypesS3,
			SigningBehavior:               cftypes.OriginAccessControlSigningBehaviorsAlways,
			SigningProtocol:               cftypes.OriginAccessControlSigningProtocolsSigv4,
		},
	})
	if err != nil {
		return "", err
	}
	if out.OriginAccessControl == nil || out.OriginAccessControl.Id == nil || strings.TrimSpace(*out.OriginAccessControl.Id) == "" {
		return "", fmt.Errorf("created OAC missing ID")
	}
	return *out.OriginAccessControl.Id, nil
}

func cloudFrontEnsureLambdaOAC(fctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	out, err := clients.CloudFront.CreateOriginAccessControl(fctx.Ctx, &cloudfront.CreateOriginAccessControlInput{
		OriginAccessControlConfig: &cftypes.OriginAccessControlConfig{
			Name:                          aws.String("bptools-lambda-oac-" + fmt.Sprintf("%d", time.Now().UnixNano())),
			Description:                   aws.String("Managed by bptools"),
			OriginAccessControlOriginType: cftypes.OriginAccessControlOriginTypesLambda,
			SigningBehavior:               cftypes.OriginAccessControlSigningBehaviorsAlways,
			SigningProtocol:               cftypes.OriginAccessControlSigningProtocolsSigv4,
		},
	})
	if err != nil {
		return "", err
	}
	if out.OriginAccessControl == nil || out.OriginAccessControl.Id == nil || strings.TrimSpace(*out.OriginAccessControl.Id) == "" {
		return "", fmt.Errorf("created OAC missing ID")
	}
	return *out.OriginAccessControl.Id, nil
}

func cloudFrontEnsureOAI(fctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	out, err := clients.CloudFront.CreateCloudFrontOriginAccessIdentity(fctx.Ctx, &cloudfront.CreateCloudFrontOriginAccessIdentityInput{
		CloudFrontOriginAccessIdentityConfig: &cftypes.CloudFrontOriginAccessIdentityConfig{
			CallerReference: aws.String(fmt.Sprintf("bptools-%d", time.Now().UnixNano())),
			Comment:         aws.String("Managed by bptools"),
		},
	})
	if err != nil {
		return "", err
	}
	if out.CloudFrontOriginAccessIdentity == nil || out.CloudFrontOriginAccessIdentity.Id == nil || strings.TrimSpace(*out.CloudFrontOriginAccessIdentity.Id) == "" {
		return "", fmt.Errorf("created OAI missing ID")
	}
	return "origin-access-identity/cloudfront/" + *out.CloudFrontOriginAccessIdentity.Id, nil
}

type cloudFrontS3OriginOACFix struct{ clients *awsdata.Clients }

func (f *cloudFrontS3OriginOACFix) CheckID() string {
	return "cloudfront-s3-origin-access-control-enabled"
}
func (f *cloudFrontS3OriginOACFix) Description() string {
	return "Enable CloudFront origin access control for S3 origins"
}

type cloudFrontOriginAccessIdentityFix struct{ clients *awsdata.Clients }

func (f *cloudFrontOriginAccessIdentityFix) CheckID() string {
	return "cloudfront-origin-access-identity-enabled"
}
func (f *cloudFrontOriginAccessIdentityFix) Description() string {
	return "Enable CloudFront origin access identity for S3 origins"
}
func (f *cloudFrontOriginAccessIdentityFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *cloudFrontOriginAccessIdentityFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudFrontOriginAccessIdentityFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}
	needs := false
	for _, o := range cfg.Origins.Items {
		if o.S3OriginConfig == nil {
			continue
		}
		if o.OriginAccessControlId != nil && strings.TrimSpace(*o.OriginAccessControlId) != "" {
			base.Status = fix.FixFailed
			base.Message = "S3 origin uses OAC; cannot auto-switch to OAI safely"
			return base
		}
		if o.S3OriginConfig.OriginAccessIdentity == nil || strings.TrimSpace(*o.S3OriginConfig.OriginAccessIdentity) == "" {
			needs = true
		}
	}
	if !needs {
		base.Status = fix.FixSkipped
		base.Message = "all S3 origins already have origin access identity"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would create OAI and assign to S3 origins for CloudFront distribution " + resourceID}
		return base
	}
	oai, err := cloudFrontEnsureOAI(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create OAI: " + err.Error()
		return base
	}
	for i := range cfg.Origins.Items {
		origin := &cfg.Origins.Items[i]
		if origin.S3OriginConfig != nil && (origin.S3OriginConfig.OriginAccessIdentity == nil || strings.TrimSpace(*origin.S3OriginConfig.OriginAccessIdentity) == "") {
			origin.S3OriginConfig.OriginAccessIdentity = aws.String(oai)
		}
	}
	_, err = f.clients.CloudFront.UpdateDistribution(fctx.Ctx, &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(resourceID),
		IfMatch:            out.ETag,
		DistributionConfig: cfg,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update distribution OAI: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"created OAI and assigned it to S3 origins for CloudFront distribution " + resourceID}
	return base
}
func (f *cloudFrontS3OriginOACFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *cloudFrontS3OriginOACFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudFrontS3OriginOACFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}
	needs := false
	for _, o := range cfg.Origins.Items {
		if o.S3OriginConfig != nil && (o.OriginAccessControlId == nil || strings.TrimSpace(*o.OriginAccessControlId) == "") {
			needs = true
			break
		}
	}
	if !needs {
		base.Status = fix.FixSkipped
		base.Message = "all S3 origins already have origin access control"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would create S3 OAC and assign to S3 origins for CloudFront distribution " + resourceID}
		return base
	}
	oacID, err := cloudFrontEnsureS3OAC(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create S3 OAC: " + err.Error()
		return base
	}
	for i := range cfg.Origins.Items {
		origin := &cfg.Origins.Items[i]
		if origin.S3OriginConfig != nil && (origin.OriginAccessControlId == nil || strings.TrimSpace(*origin.OriginAccessControlId) == "") {
			origin.OriginAccessControlId = aws.String(oacID)
			if origin.S3OriginConfig != nil {
				origin.S3OriginConfig.OriginAccessIdentity = aws.String("")
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
		base.Message = "update distribution S3 OAC: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"created S3 OAC and assigned it to S3 origins for CloudFront distribution " + resourceID}
	return base
}

type cloudFrontLambdaURLOACFix struct{ clients *awsdata.Clients }

func (f *cloudFrontLambdaURLOACFix) CheckID() string {
	return "cloudfront-origin-lambda-url-oac-enabled"
}
func (f *cloudFrontLambdaURLOACFix) Description() string {
	return "Enable CloudFront origin access control for Lambda URL origins"
}
func (f *cloudFrontLambdaURLOACFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *cloudFrontLambdaURLOACFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudFrontLambdaURLOACFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	out, err := f.clients.CloudFront.GetDistributionConfig(fctx.Ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get distribution config: " + err.Error()
		return base
	}
	cfg := out.DistributionConfig
	if cfg == nil {
		base.Status = fix.FixFailed
		base.Message = "distribution config is nil"
		return base
	}
	needs := false
	for _, o := range cfg.Origins.Items {
		if o.DomainName != nil && strings.Contains(strings.ToLower(strings.TrimSpace(*o.DomainName)), "lambda-url") &&
			(o.OriginAccessControlId == nil || strings.TrimSpace(*o.OriginAccessControlId) == "") {
			needs = true
			break
		}
	}
	if !needs {
		base.Status = fix.FixSkipped
		base.Message = "all Lambda URL origins already have origin access control"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would create Lambda OAC and assign to Lambda URL origins for CloudFront distribution " + resourceID}
		return base
	}
	oacID, err := cloudFrontEnsureLambdaOAC(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create Lambda OAC: " + err.Error()
		return base
	}
	for i := range cfg.Origins.Items {
		origin := &cfg.Origins.Items[i]
		if origin.DomainName != nil && strings.Contains(strings.ToLower(strings.TrimSpace(*origin.DomainName)), "lambda-url") &&
			(origin.OriginAccessControlId == nil || strings.TrimSpace(*origin.OriginAccessControlId) == "") {
			origin.OriginAccessControlId = aws.String(oacID)
		}
	}
	_, err = f.clients.CloudFront.UpdateDistribution(fctx.Ctx, &cloudfront.UpdateDistributionInput{
		Id:                 aws.String(resourceID),
		IfMatch:            out.ETag,
		DistributionConfig: cfg,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update distribution Lambda OAC: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"created Lambda OAC and assigned it to Lambda URL origins for CloudFront distribution " + resourceID}
	return base
}
