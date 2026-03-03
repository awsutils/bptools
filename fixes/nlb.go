package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"
	"bptools/fix/pool"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// ── nlb-cross-zone-load-balancing-enabled ────────────────────────────────────

type nlbCrossZoneFix struct{ clients *awsdata.Clients }

func (f *nlbCrossZoneFix) CheckID() string          { return "nlb-cross-zone-load-balancing-enabled" }
func (f *nlbCrossZoneFix) Description() string      { return "Enable cross-zone load balancing on NLB" }
func (f *nlbCrossZoneFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *nlbCrossZoneFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *nlbCrossZoneFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

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
		if attr.Key != nil && *attr.Key == "load_balancing.cross_zone.enabled" &&
			attr.Value != nil && *attr.Value == "true" {
			base.Status = fix.FixSkipped
			base.Message = "cross-zone load balancing already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable cross-zone load balancing on NLB %s", resourceID)}
		return base
	}

	_, err = f.clients.ELBv2.ModifyLoadBalancerAttributes(fctx.Ctx,
		&elasticloadbalancingv2.ModifyLoadBalancerAttributesInput{
			LoadBalancerArn: aws.String(resourceID),
			Attributes: []elbv2types.LoadBalancerAttribute{
				{Key: aws.String("load_balancing.cross_zone.enabled"), Value: aws.String("true")},
			},
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify load balancer attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled cross-zone load balancing on NLB %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── nlb-logging-enabled ───────────────────────────────────────────────────────

type nlbLoggingFix struct {
	clients *awsdata.Clients
	pool    *pool.S3BucketPool
}

func newNLBLoggingFix(clients *awsdata.Clients, p *pool.S3BucketPool) *nlbLoggingFix {
	return &nlbLoggingFix{clients: clients, pool: p}
}

func (f *nlbLoggingFix) CheckID() string          { return "nlb-logging-enabled" }
func (f *nlbLoggingFix) Description() string      { return "Enable NLB access logs to S3" }
func (f *nlbLoggingFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *nlbLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *nlbLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

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

	region := arnRegion(resourceID)
	if region == "" {
		base.Status = fix.FixFailed
		base.Message = "could not parse region from ARN: " + resourceID
		return base
	}

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

	// Use the NLB name as prefix (last segment of ARN)
	parts := strings.Split(resourceID, "/")
	prefix := "nlb"
	if len(parts) > 1 {
		prefix = parts[len(parts)-1]
	}

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
