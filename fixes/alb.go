package fixes

import (
	"fmt"
	"strings"
	"sync"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// ── alb-http-to-https-redirection-check ──────────────────────────────────────

type albHTTPSRedirectFix struct{ clients *awsdata.Clients }

func (f *albHTTPSRedirectFix) CheckID() string          { return "alb-http-to-https-redirection-check" }
func (f *albHTTPSRedirectFix) Description() string      { return "Add HTTP→HTTPS redirect to ALB listeners" }
func (f *albHTTPSRedirectFix) Impact() fix.ImpactType   { return fix.ImpactDegradation }
func (f *albHTTPSRedirectFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *albHTTPSRedirectFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.CheckID(),
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}

	// List current listeners for this ALB.
	out, err := f.clients.ELBv2.DescribeListeners(fctx.Ctx,
		&elasticloadbalancingv2.DescribeListenersInput{
			LoadBalancerArn: aws.String(resourceID),
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe listeners: " + err.Error()
		return base
	}

	// Collect HTTP listeners that don't already redirect to HTTPS.
	type pendingListener struct {
		arn  string
		port int32
	}
	var pending []pendingListener
	for _, l := range out.Listeners {
		if l.Protocol != elbv2types.ProtocolEnumHttp || l.ListenerArn == nil {
			continue
		}
		alreadyRedirects := false
		for _, a := range l.DefaultActions {
			if a.Type == elbv2types.ActionTypeEnumRedirect &&
				a.RedirectConfig != nil &&
				a.RedirectConfig.Protocol != nil &&
				*a.RedirectConfig.Protocol == "HTTPS" {
				alreadyRedirects = true
				break
			}
		}
		if !alreadyRedirects {
			port := int32(0)
			if l.Port != nil {
				port = *l.Port
			}
			pending = append(pending, pendingListener{arn: *l.ListenerArn, port: port})
		}
	}

	if len(pending) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "all HTTP listeners already redirect to HTTPS"
		return base
	}

	redirectAction := elbv2types.Action{
		Type: elbv2types.ActionTypeEnumRedirect,
		RedirectConfig: &elbv2types.RedirectActionConfig{
			Protocol:   aws.String("HTTPS"),
			Port:       aws.String("443"),
			StatusCode: elbv2types.RedirectActionStatusCodeEnumHttp301,
		},
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		for _, l := range pending {
			base.Steps = append(base.Steps,
				fmt.Sprintf("would add HTTP→HTTPS redirect to listener %s (port %d)", l.arn, l.port),
			)
		}
		return base
	}

	for _, l := range pending {
		_, err := f.clients.ELBv2.ModifyListener(fctx.Ctx,
			&elasticloadbalancingv2.ModifyListenerInput{
				ListenerArn:    aws.String(l.arn),
				DefaultActions: []elbv2types.Action{redirectAction},
			})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = fmt.Sprintf("modify listener %s: %s", l.arn, err.Error())
			return base
		}
		base.Steps = append(base.Steps,
			fmt.Sprintf("added HTTP→HTTPS redirect to listener %s (port %d)", l.arn, l.port),
		)
	}

	base.Status = fix.FixApplied
	return base
}

// ── alb-waf-enabled ───────────────────────────────────────────────────────────

const bptoolsWAFName = "bptools-alb-waf"

// albWAFFix finds or creates a bptools-managed WAFv2 WebACL per region and
// associates it with the ALB. The WebACL uses a default-allow policy with no
// rules — its purpose is compliance, not blocking traffic.
type albWAFFix struct {
	clients *awsdata.Clients
	mu      sync.Mutex
	cache   map[string]string // region → WebACL ARN
}

func newALBWAFFix(clients *awsdata.Clients) *albWAFFix {
	return &albWAFFix{clients: clients, cache: make(map[string]string)}
}

func (f *albWAFFix) CheckID() string          { return "alb-waf-enabled" }
func (f *albWAFFix) Description() string      { return "Associate WAFv2 WebACL with ALB" }
func (f *albWAFFix) Impact() fix.ImpactType   { return fix.ImpactDegradation }
func (f *albWAFFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *albWAFFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.CheckID(),
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}

	// Idempotency: check if a WebACL is already associated.
	existing, err := f.clients.WAFv2.GetWebACLForResource(fctx.Ctx,
		&wafv2.GetWebACLForResourceInput{ResourceArn: aws.String(resourceID)})
	if err == nil && existing.WebACL != nil {
		base.Status = fix.FixSkipped
		base.Message = "WAF WebACL already associated"
		return base
	}

	region := arnRegion(resourceID)
	if region == "" {
		base.Status = fix.FixFailed
		base.Message = "could not parse region from ARN: " + resourceID
		return base
	}

	webACLARN, steps, err := f.ensureWebACL(fctx, region)
	base.Steps = append(base.Steps, steps...)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure WAF WebACL: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = append(base.Steps,
			fmt.Sprintf("would associate WebACL %s with ALB %s", webACLARN, resourceID),
		)
		return base
	}

	_, err = f.clients.WAFv2.AssociateWebACL(fctx.Ctx, &wafv2.AssociateWebACLInput{
		ResourceArn: aws.String(resourceID),
		WebACLArn:   aws.String(webACLARN),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "associate WebACL: " + err.Error()
		return base
	}
	base.Steps = append(base.Steps,
		fmt.Sprintf("associated WebACL %s with ALB %s", webACLARN, resourceID),
	)
	base.Status = fix.FixApplied
	return base
}

// ensureWebACL finds the bptools-managed WebACL for the region or creates it.
func (f *albWAFFix) ensureWebACL(fctx fix.FixContext, region string) (string, []string, error) {
	f.mu.Lock()
	if arn, ok := f.cache[region]; ok {
		f.mu.Unlock()
		return arn, nil, nil
	}
	f.mu.Unlock()

	// Search existing WebACLs for one named bptoolsWAFName.
	var nextToken *string
	for {
		out, err := f.clients.WAFv2.ListWebACLs(fctx.Ctx, &wafv2.ListWebACLsInput{
			Scope:      wafv2types.ScopeRegional,
			NextMarker: nextToken,
			Limit:      aws.Int32(100),
		})
		if err != nil {
			return "", nil, fmt.Errorf("list WebACLs: %w", err)
		}
		for _, w := range out.WebACLs {
			if w.Name != nil && *w.Name == bptoolsWAFName && w.ARN != nil {
				arn := *w.ARN
				f.mu.Lock()
				f.cache[region] = arn
				f.mu.Unlock()
				return arn, []string{"found existing WebACL " + arn}, nil
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		nextToken = out.NextMarker
	}

	if fctx.DryRun {
		placeholder := "<would-create:" + bptoolsWAFName + ">"
		return placeholder, []string{"[dry-run] would create WAFv2 WebACL " + bptoolsWAFName + " in " + region}, nil
	}

	metricName := strings.ReplaceAll(bptoolsWAFName, "-", "") // metric names can't contain hyphens
	created, err := f.clients.WAFv2.CreateWebACL(fctx.Ctx, &wafv2.CreateWebACLInput{
		Name:  aws.String(bptoolsWAFName),
		Scope: wafv2types.ScopeRegional,
		DefaultAction: &wafv2types.DefaultAction{
			Allow: &wafv2types.AllowAction{},
		},
		Rules: []wafv2types.Rule{},
		VisibilityConfig: &wafv2types.VisibilityConfig{
			SampledRequestsEnabled:   true,
			CloudWatchMetricsEnabled: true,
			MetricName:               aws.String(metricName),
		},
		Tags: []wafv2types.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf("create WebACL: %w", err)
	}

	arn := *created.Summary.ARN
	f.mu.Lock()
	f.cache[region] = arn
	f.mu.Unlock()
	return arn, []string{"created WAFv2 WebACL " + arn}, nil
}

// ── alb-http-drop-invalid-header-enabled ─────────────────────────────────────

type albDropInvalidHeaderFix struct{ clients *awsdata.Clients }

func (f *albDropInvalidHeaderFix) CheckID() string {
	return "alb-http-drop-invalid-header-enabled"
}
func (f *albDropInvalidHeaderFix) Description() string {
	return "Enable HTTP invalid header dropping on Application Load Balancer"
}
func (f *albDropInvalidHeaderFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *albDropInvalidHeaderFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *albDropInvalidHeaderFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ELBv2.DescribeLoadBalancerAttributes(fctx.Ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
		LoadBalancerArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe load balancer attributes: " + err.Error()
		return base
	}
	for _, a := range out.Attributes {
		if a.Key != nil && *a.Key == "routing.http.drop_invalid_header_fields.enabled" &&
			a.Value != nil && strings.EqualFold(*a.Value, "true") {
			base.Status = fix.FixSkipped
			base.Message = "invalid header dropping already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable drop_invalid_header_fields on ALB " + resourceID}
		return base
	}

	_, err = f.clients.ELBv2.ModifyLoadBalancerAttributes(fctx.Ctx, &elasticloadbalancingv2.ModifyLoadBalancerAttributesInput{
		LoadBalancerArn: aws.String(resourceID),
		Attributes: []elbv2types.LoadBalancerAttribute{
			{Key: aws.String("routing.http.drop_invalid_header_fields.enabled"), Value: aws.String("true")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify load balancer attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled drop_invalid_header_fields on ALB %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── elb-deletion-protection-enabled ──────────────────────────────────────────

type elbDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *elbDeletionProtectionFix) CheckID() string {
	return "elb-deletion-protection-enabled"
}
func (f *elbDeletionProtectionFix) Description() string {
	return "Enable deletion protection on load balancer"
}
func (f *elbDeletionProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *elbDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *elbDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attrOut, err := f.clients.ELBv2.DescribeLoadBalancerAttributes(fctx.Ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
		LoadBalancerArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe load balancer attributes: " + err.Error()
		return base
	}
	for _, a := range attrOut.Attributes {
		if a.Key != nil && *a.Key == "deletion_protection.enabled" && a.Value != nil && *a.Value == "true" {
			base.Status = fix.FixSkipped
			base.Message = "deletion protection already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable deletion protection on load balancer %s", resourceID)}
		return base
	}

	_, err = f.clients.ELBv2.ModifyLoadBalancerAttributes(fctx.Ctx, &elasticloadbalancingv2.ModifyLoadBalancerAttributesInput{
		LoadBalancerArn: aws.String(resourceID),
		Attributes: []elbv2types.LoadBalancerAttribute{
			{Key: aws.String("deletion_protection.enabled"), Value: aws.String("true")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify load balancer attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled deletion protection on load balancer %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
