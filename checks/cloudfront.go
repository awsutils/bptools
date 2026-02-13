package checks

import (
	"fmt"
	"os"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

func cfID(id string, cfg cftypes.DistributionConfig) string {
	if id != "" {
		return id
	}
	if cfg.Comment != nil {
		return *cfg.Comment
	}
	return "unknown"
}

func RegisterCloudFrontChecks(d *awsdata.Data) {
	configs, err := d.CloudFrontDistributionConfigs.Get()
	if err != nil {
		checker.Register(&BaseCheck{CheckID: "cloudfront-config-load", Desc: "Load CloudFront configs", Svc: "cloudfront", RunFunc: func() []checker.Result {
			return []checker.Result{{CheckID: "cloudfront-config-load", Status: checker.StatusError, Message: err.Error()}}
		}})
		return
	}

	// cloudfront-accesslogs-enabled
	checker.Register(LoggingCheck(
		"cloudfront-accesslogs-enabled",
		"Checks if Amazon CloudFront distributions are configured to deliver access logs to an Amazon S3 bucket using standard logging (legacy). The rule is NON_COMPLIANT if a CloudFront distribution does not have legacy logging configured.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			var res []LoggingResource
			for id, cfg := range configs {
				logging := cfg.Logging != nil && cfg.Logging.Enabled != nil && *cfg.Logging.Enabled && cfg.Logging.Bucket != nil && *cfg.Logging.Bucket != ""
				res = append(res, LoggingResource{ID: cfID(id, cfg), Logging: logging})
			}
			return res, nil
		},
	))

	// cloudfront-associated-with-waf
	checker.Register(EnabledCheck(
		"cloudfront-associated-with-waf",
		"Checks if Amazon CloudFront distributions are associated with either web application firewall (WAF) or WAFv2 web access control lists (ACLs). The rule is NON_COMPLIANT if a CloudFront distribution is not associated with a WAF web ACL.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			waf, err := d.CloudFrontDistributionWAF.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id := range configs {
				res = append(res, EnabledResource{ID: id, Enabled: waf[id]})
			}
			return res, nil
		},
	))

	// cloudfront-custom-ssl-certificate
	checker.Register(ConfigCheck(
		"cloudfront-custom-ssl-certificate",
		"Checks if the certificate associated with an Amazon CloudFront distribution is the default SSL certificate. The rule is NON_COMPLIANT if a CloudFront distribution uses the default SSL certificate.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				vc := cfg.ViewerCertificate
				ok := vc != nil && ((vc.ACMCertificateArn != nil && *vc.ACMCertificateArn != "") || (vc.IAMCertificateId != nil && *vc.IAMCertificateId != ""))
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "Custom cert configured"})
			}
			return res, nil
		},
	))

	// cloudfront-default-root-object-configured
	checker.Register(ConfigCheck(
		"cloudfront-default-root-object-configured",
		"Checks if an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The rule is NON_COMPLIANT if Amazon CloudFront distribution does not have a default root object configured.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ok := cfg.DefaultRootObject != nil && *cfg.DefaultRootObject != ""
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "Default root object"})
			}
			return res, nil
		},
	))

	// cloudfront-distribution-key-group-enabled
	checker.Register(EnabledCheck(
		"cloudfront-distribution-key-group-enabled",
		"Checks if Amazon CloudFront distributions are configured to use only trusted key groups for signed URL or signed cookie authentication for all cache behaviors. The rule is NON_COMPLIANT if any cache behavior in the distribution is using trusted signers.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			var res []EnabledResource
			for id, cfg := range configs {
				enabled := false
				usesTrustedSigners := cacheBehaviorUsesTrustedSigners(cfg.DefaultCacheBehavior)
				if cfg.DefaultCacheBehavior.TrustedKeyGroups != nil && cfg.DefaultCacheBehavior.TrustedKeyGroups.Quantity != nil && *cfg.DefaultCacheBehavior.TrustedKeyGroups.Quantity > 0 {
					enabled = true
				}
				for _, cb := range cfg.CacheBehaviors.Items {
					if cb.TrustedKeyGroups != nil && cb.TrustedKeyGroups.Quantity != nil && *cb.TrustedKeyGroups.Quantity > 0 {
						enabled = true
					}
					if cb.TrustedSigners != nil && cb.TrustedSigners.Enabled != nil && *cb.TrustedSigners.Enabled {
						usesTrustedSigners = true
					}
				}
				enabled = enabled && !usesTrustedSigners
				res = append(res, EnabledResource{ID: cfID(id, cfg), Enabled: enabled})
			}
			return res, nil
		},
	))

	// cloudfront-no-deprecated-ssl-protocols
	checker.Register(ConfigCheck(
		"cloudfront-no-deprecated-ssl-protocols",
		"Checks if CloudFront distributions are using deprecated SSL protocols for HTTPS communication between CloudFront edge locations and custom origins. This rule is NON_COMPLIANT for a CloudFront distribution if any ‘OriginSslProtocols’ includes ‘SSLv3’.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ok := true
				for _, origin := range cfg.Origins.Items {
					if origin.CustomOriginConfig == nil || origin.CustomOriginConfig.OriginSslProtocols == nil {
						continue
					}
					for _, protocol := range origin.CustomOriginConfig.OriginSslProtocols.Items {
						p := strings.ToUpper(strings.TrimSpace(string(protocol)))
						if p == "SSLV3" {
							ok = false
							break
						}
					}
					if !ok {
						break
					}
				}
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "No deprecated origin SSL protocols"})
			}
			return res, nil
		},
	))

	// cloudfront-origin-access-identity-enabled
	checker.Register(ConfigCheck(
		"cloudfront-origin-access-identity-enabled",
		"Checks if CloudFront distribution with Amazon S3 Origin type has origin access identity configured. The rule is NON_COMPLIANT if the CloudFront distribution is backed by S3 and any origin type is not OAI configured, or the origin is not an S3 bucket.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ok := true
				for _, o := range cfg.Origins.Items {
					if o.S3OriginConfig != nil {
						if o.S3OriginConfig.OriginAccessIdentity == nil || *o.S3OriginConfig.OriginAccessIdentity == "" {
							ok = false
						}
					}
				}
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "S3 origin access identity"})
			}
			return res, nil
		},
	))

	// cloudfront-origin-failover-enabled
	checker.Register(ConfigCheck(
		"cloudfront-origin-failover-enabled",
		"Checks if an origin group is configured for the distribution of at least two origins in the origin group for Amazon CloudFront. The rule is NON_COMPLIANT if there are no origin groups for the distribution.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ok := cfg.OriginGroups != nil && cfg.OriginGroups.Quantity != nil && *cfg.OriginGroups.Quantity > 0
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "Origin groups configured"})
			}
			return res, nil
		},
	))

	// cloudfront-origin-lambda-url-oac-enabled
	checker.Register(ConfigCheck(
		"cloudfront-origin-lambda-url-oac-enabled",
		"Checks if Amazon CloudFront distributions with Amazon Lambda Function URL origins have origin access control (OAC) enabled. The rule is NON_COMPLIANT if any Lambda Function URL origin in a CloudFront distribution does not have OAC enabled.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ok := true
				for _, o := range cfg.Origins.Items {
					if o.DomainName != nil && strings.Contains(*o.DomainName, "lambda-url") {
						if o.OriginAccessControlId == nil || *o.OriginAccessControlId == "" {
							ok = false
						}
					}
				}
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "Lambda URL OAC"})
			}
			return res, nil
		},
	))

	// cloudfront-s3-origin-access-control-enabled
	checker.Register(ConfigCheck(
		"cloudfront-s3-origin-access-control-enabled",
		"Checks if an Amazon CloudFront distribution with an Amazon Simple Storage Service (Amazon S3) Origin type has origin access control (OAC) enabled. The rule is NON_COMPLIANT for CloudFront distributions with Amazon S3 origins that don't have OAC enabled.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ok := true
				for _, o := range cfg.Origins.Items {
					if o.S3OriginConfig != nil {
						if o.OriginAccessControlId == nil || *o.OriginAccessControlId == "" {
							ok = false
						}
					}
				}
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "S3 origin OAC"})
			}
			return res, nil
		},
	))

	// cloudfront-s3-origin-non-existent-bucket
	checker.Register(ConfigCheck(
		"cloudfront-s3-origin-non-existent-bucket",
		"Checks if Amazon CloudFront distributions point to a non-existent S3 bucket. The rule is NON_COMPLIANT if `S3OriginConfig` for a CloudFront distribution points to a non-existent S3 bucket. The rule does not evaluate S3 buckets with static website hosting.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.CloudFrontS3OriginBucketExists.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for b, exists := range buckets {
				res = append(res, ConfigResource{ID: b, Passing: exists, Detail: fmt.Sprintf("Bucket exists: %v", exists)})
			}
			return res, nil
		},
	))

	// cloudfront-security-policy-check + cloudfront-ssl-policy-check + cloudfront-sni-enabled
	allowedPolicies := cloudfrontAllowedViewerPolicies()
	checker.Register(ConfigCheck(
		"cloudfront-security-policy-check",
		"Checks if Amazon CloudFront distributions are using a minimum security policy and cipher suite of TLSv1.2 or greater for viewer connections. This rule is NON_COMPLIANT for a CloudFront distribution if the minimumProtocolVersion is below TLSv1.2_2018.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ver := cftypes.MinimumProtocolVersionTLSv122019
				if cfg.ViewerCertificate != nil {
					ver = cfg.ViewerCertificate.MinimumProtocolVersion
				}
				ok := allowedPolicies[strings.ToUpper(strings.TrimSpace(string(ver)))]
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: fmt.Sprintf("MinProtocol: %s", ver)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudfront-ssl-policy-check",
		"Checks if Amazon CloudFront distributions are configured with the specified security policies.The rule is NON_COMPLIANT if a CloudFront Distribution is not configured with security policies that you specify.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ver := cftypes.MinimumProtocolVersionTLSv122019
				if cfg.ViewerCertificate != nil {
					ver = cfg.ViewerCertificate.MinimumProtocolVersion
				}
				ok := allowedPolicies[strings.ToUpper(strings.TrimSpace(string(ver)))]
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: fmt.Sprintf("MinProtocol: %s", ver)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudfront-sni-enabled",
		"Checks if Amazon CloudFront distributions are using a custom SSL certificate and are configured to use SNI to serve HTTPS requests. The rule is NON_COMPLIANT if a custom SSL certificate is associated but the SSL support method is a dedicated IP address.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				method := "none"
				customCert := cfg.ViewerCertificate != nil && ((cfg.ViewerCertificate.ACMCertificateArn != nil && *cfg.ViewerCertificate.ACMCertificateArn != "") ||
					(cfg.ViewerCertificate.IAMCertificateId != nil && *cfg.ViewerCertificate.IAMCertificateId != ""))
				if customCert {
					method = string(cfg.ViewerCertificate.SSLSupportMethod)
				}
				ok := !customCert || method == "sni-only"
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: fmt.Sprintf("SSLSupportMethod: %s", method)})
			}
			return res, nil
		},
	))

	// cloudfront-traffic-to-origin-encrypted
	checker.Register(ConfigCheck(
		"cloudfront-traffic-to-origin-encrypted",
		"Checks if Amazon CloudFront distributions are encrypting traffic to custom origins. The rule is NON_COMPLIANT if ‘OriginProtocolPolicy’ is ‘http-only’ or if ‘OriginProtocolPolicy’ is ‘match-viewer’ and ‘ViewerProtocolPolicy’ is ‘allow-all’.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				ok := true
				for _, o := range cfg.Origins.Items {
					if o.CustomOriginConfig != nil {
						policy := o.CustomOriginConfig.OriginProtocolPolicy
						if policy == cftypes.OriginProtocolPolicyHttpsOnly {
							continue
						}
						if policy == cftypes.OriginProtocolPolicyMatchViewer && !originHasAllowAllViewerPolicy(cfg, o.Id) {
							continue
						}
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: "Origin protocol policy"})
			}
			return res, nil
		},
	))

	// cloudfront-viewer-policy-https
	checker.Register(ConfigCheck(
		"cloudfront-viewer-policy-https",
		"Checks whether your Amazon CloudFront distributions use HTTPS (directly or via a redirection). The rule is NON_COMPLIANT if the value of ViewerProtocolPolicy is set to 'allow-all' for the defaultCacheBehavior or for the CacheBehaviors.",
		"cloudfront",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			var res []ConfigResource
			for id, cfg := range configs {
				vp := cfg.DefaultCacheBehavior.ViewerProtocolPolicy
				ok := vp == cftypes.ViewerProtocolPolicyRedirectToHttps || vp == cftypes.ViewerProtocolPolicyHttpsOnly
				if ok {
					for _, cb := range cfg.CacheBehaviors.Items {
						if cb.ViewerProtocolPolicy != cftypes.ViewerProtocolPolicyRedirectToHttps && cb.ViewerProtocolPolicy != cftypes.ViewerProtocolPolicyHttpsOnly {
							ok = false
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: cfID(id, cfg), Passing: ok, Detail: fmt.Sprintf("ViewerProtocolPolicy: %s", vp)})
			}
			return res, nil
		},
	))
}

func cacheBehaviorUsesTrustedSigners(cb *cftypes.DefaultCacheBehavior) bool {
	if cb == nil {
		return false
	}
	return cb.TrustedSigners != nil && cb.TrustedSigners.Enabled != nil && *cb.TrustedSigners.Enabled
}

func originHasAllowAllViewerPolicy(cfg cftypes.DistributionConfig, originID *string) bool {
	if originID == nil || *originID == "" {
		return false
	}
	if cfg.DefaultCacheBehavior.TargetOriginId != nil &&
		*cfg.DefaultCacheBehavior.TargetOriginId == *originID &&
		cfg.DefaultCacheBehavior.ViewerProtocolPolicy == cftypes.ViewerProtocolPolicyAllowAll {
		return true
	}
	for _, cb := range cfg.CacheBehaviors.Items {
		if cb.TargetOriginId != nil &&
			*cb.TargetOriginId == *originID &&
			cb.ViewerProtocolPolicy == cftypes.ViewerProtocolPolicyAllowAll {
			return true
		}
	}
	return false
}

func cloudfrontAllowedViewerPolicies() map[string]bool {
	override := strings.TrimSpace(os.Getenv("BPTOOLS_CLOUDFRONT_ALLOWED_SSL_POLICIES"))
	values := []string{"TLSV1.2_2018", "TLSV1.2_2019", "TLSV1.2_2021"}
	if override != "" {
		parts := strings.Split(override, ",")
		values = make([]string, 0, len(parts))
		for _, part := range parts {
			item := strings.ToUpper(strings.TrimSpace(part))
			if item != "" {
				values = append(values, item)
			}
		}
	}
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[strings.ToUpper(strings.TrimSpace(value))] = true
	}
	return out
}
