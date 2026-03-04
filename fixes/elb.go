package fixes

import (
	"context"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"
	"bptools/fix/pool"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type elbLoggingFix struct {
	clients *awsdata.Clients
	pool    *pool.S3BucketPool
}

func newELBLoggingFix(clients *awsdata.Clients, p *pool.S3BucketPool) *elbLoggingFix {
	return &elbLoggingFix{clients: clients, pool: p}
}

func (f *elbLoggingFix) CheckID() string             { return "elb-logging-enabled" }
func (f *elbLoggingFix) Description() string         { return "Enable ALB access logs to S3" }
func (f *elbLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *elbLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *elbLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.CheckID(),
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}

	// Classic ELB resources are identified by name (no ARN). They are deprecated
	// and out of scope for auto-fix.
	if !strings.HasPrefix(resourceID, "arn:") {
		base.Status = fix.FixSkipped
		base.Message = "Classic ELB is deprecated and out of scope for auto-fix"
		return base
	}

	// Idempotency: re-describe the ALB attributes before making any changes.
	attrs, err := f.clients.ELBv2.DescribeLoadBalancerAttributes(fctx.Ctx,
		&elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
			LoadBalancerArn: aws.String(resourceID),
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe load balancer attributes: " + err.Error()
		return base
	}
	for _, attr := range attrs.Attributes {
		if attr.Key != nil && *attr.Key == "access_logs.s3.enabled" &&
			attr.Value != nil && *attr.Value == "true" {
			base.Status = fix.FixSkipped
			base.Message = "access logs already enabled"
			return base
		}
	}

	// Parse the region from the ARN.
	// ARN format: arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/...
	region := arnRegion(resourceID)
	if region == "" {
		base.Status = fix.FixFailed
		base.Message = "could not parse region from ARN: " + resourceID
		return base
	}

	// Ensure a shared logging bucket for this region. The purpose key "service-logs"
	// is intentionally generic so other fixes (NLB, VPC flow logs, S3 access logs,
	// WAF, etc.) can reuse the same bucket by passing the same purpose.
	bucketName, steps, err := f.pool.Ensure(fctx.Ctx, pool.S3BucketSpec{
		Purpose:        "service-logs",
		Region:         region,
		BucketPrefix:   "logs-",
		BucketPolicyFn: serviceLogsBucketPolicy,
	}, fctx.DryRun)
	base.Steps = append(base.Steps, steps...)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure S3 bucket: " + err.Error()
		return base
	}

	// Use the ALB name as an S3 prefix so logs from different ALBs are segregated.
	prefix := albName(resourceID)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = append(base.Steps,
			fmt.Sprintf("would enable access_logs.s3 on %s", resourceID),
			fmt.Sprintf("  bucket=%s prefix=%s", bucketName, prefix),
		)
		return base
	}

	_, err = f.clients.ELBv2.ModifyLoadBalancerAttributes(fctx.Ctx,
		&elasticloadbalancingv2.ModifyLoadBalancerAttributesInput{
			LoadBalancerArn: aws.String(resourceID),
			Attributes: []elbv2types.LoadBalancerAttribute{
				{Key: aws.String("access_logs.s3.enabled"), Value: aws.String("true")},
				{Key: aws.String("access_logs.s3.bucket"), Value: aws.String(bucketName)},
				{Key: aws.String("access_logs.s3.prefix"), Value: aws.String(prefix)},
			},
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify load balancer attributes: " + err.Error()
		return base
	}

	base.Steps = append(base.Steps,
		fmt.Sprintf("enabled access logs on %s → s3://%s/%s", resourceID, bucketName, prefix),
	)
	base.Status = fix.FixApplied
	return base
}

// arnRegion extracts the region from an AWS ARN (index 3 in colon-split).
func arnRegion(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

// albName extracts the ALB name from its ARN for use as an S3 prefix.
// ARN: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/<name>/<id>
func albName(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) >= 3 {
		return parts[len(parts)-2]
	}
	return "alb"
}

// serviceLogsBucketPolicy applies a bucket policy that grants PutObject to all
// common AWS logging service principals. Using a single broad policy means any
// future fix that shares the "service-logs" purpose key can write to this bucket
// without needing to update the policy.
//
// Principals covered:
//   - logdelivery.elasticloadbalancing.amazonaws.com — ALB access logs
//   - delivery.logs.amazonaws.com                    — NLB, GWLB, VPC Flow Logs, WAF
//   - logging.s3.amazonaws.com                       — S3 server access logs
func serviceLogsBucketPolicy(ctx context.Context, s3Client *s3.Client, bucketName string) error {
	policy := fmt.Sprintf(
		`{"Version":"2012-10-17","Statement":[`+
			`{"Sid":"ServiceLogDeliveryWrite","Effect":"Allow",`+
			`"Principal":{"Service":[`+
			`"logdelivery.elasticloadbalancing.amazonaws.com",`+
			`"delivery.logs.amazonaws.com",`+
			`"logging.s3.amazonaws.com"`+
			`]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/*"},`+
			`{"Sid":"ServiceLogDeliveryAclCheck","Effect":"Allow",`+
			`"Principal":{"Service":[`+
			`"logdelivery.elasticloadbalancing.amazonaws.com",`+
			`"delivery.logs.amazonaws.com",`+
			`"logging.s3.amazonaws.com"`+
			`]},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s"}]}`,
		bucketName, bucketName,
	)
	_, err := s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(policy),
	})
	return err
}

// ── elb-cross-zone-load-balancing-enabled ─────────────────────────────────────

type elbCrossZoneFix struct{ clients *awsdata.Clients }

func (f *elbCrossZoneFix) CheckID() string { return "elb-cross-zone-load-balancing-enabled" }
func (f *elbCrossZoneFix) Description() string {
	return "Enable cross-zone load balancing on Classic Load Balancer"
}
func (f *elbCrossZoneFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *elbCrossZoneFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *elbCrossZoneFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ELB.DescribeLoadBalancerAttributes(fctx.Ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{
		LoadBalancerName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe load balancer attributes: " + err.Error()
		return base
	}
	if out.LoadBalancerAttributes != nil && out.LoadBalancerAttributes.CrossZoneLoadBalancing != nil &&
		out.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled {
		base.Status = fix.FixSkipped
		base.Message = "cross-zone load balancing already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable cross-zone load balancing on Classic ELB %s", resourceID)}
		return base
	}

	_, err = f.clients.ELB.ModifyLoadBalancerAttributes(fctx.Ctx, &elasticloadbalancing.ModifyLoadBalancerAttributesInput{
		LoadBalancerName: aws.String(resourceID),
		LoadBalancerAttributes: &elbtypes.LoadBalancerAttributes{
			CrossZoneLoadBalancing: &elbtypes.CrossZoneLoadBalancing{
				Enabled: true,
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify load balancer attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled cross-zone load balancing on Classic ELB %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── clb-desync-mode-check ─────────────────────────────────────────────────────

type clbDesyncModeFix struct{ clients *awsdata.Clients }

func (f *clbDesyncModeFix) CheckID() string          { return "clb-desync-mode-check" }
func (f *clbDesyncModeFix) Description() string      { return "Set Classic ELB desync mitigation mode to defensive" }
func (f *clbDesyncModeFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *clbDesyncModeFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *clbDesyncModeFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attrOut, err := f.clients.ELB.DescribeLoadBalancerAttributes(fctx.Ctx,
		&elasticloadbalancing.DescribeLoadBalancerAttributesInput{
			LoadBalancerName: aws.String(resourceID),
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe lb attributes: " + err.Error()
		return base
	}

	if attrOut.LoadBalancerAttributes != nil {
		for _, a := range attrOut.LoadBalancerAttributes.AdditionalAttributes {
			if aws.ToString(a.Key) == "elb.http.desync_mitigation_mode" {
				v := aws.ToString(a.Value)
				if v == "monitor" || v == "defensive" || v == "strictest" {
					base.Status = fix.FixSkipped
					base.Message = fmt.Sprintf("desync mitigation mode already set to %s", v)
					return base
				}
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set desync mitigation mode to defensive on Classic ELB %s", resourceID)}
		return base
	}

	existing := attrOut.LoadBalancerAttributes
	if existing == nil {
		existing = &elbtypes.LoadBalancerAttributes{}
	}
	existing.AdditionalAttributes = append(existing.AdditionalAttributes,
		elbtypes.AdditionalAttribute{
			Key:   aws.String("elb.http.desync_mitigation_mode"),
			Value: aws.String("defensive"),
		})
	_, err = f.clients.ELB.ModifyLoadBalancerAttributes(fctx.Ctx,
		&elasticloadbalancing.ModifyLoadBalancerAttributesInput{
			LoadBalancerName:       aws.String(resourceID),
			LoadBalancerAttributes: existing,
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify lb attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set desync mitigation mode to defensive on Classic ELB %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
