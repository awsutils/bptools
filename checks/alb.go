package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func lbID(lb elbv2types.LoadBalancer) string {
	if lb.LoadBalancerArn != nil {
		return *lb.LoadBalancerArn
	}
	if lb.LoadBalancerName != nil {
		return *lb.LoadBalancerName
	}
	return "unknown"
}

func isALB(lb elbv2types.LoadBalancer) bool {
	return lb.Type == elbv2types.LoadBalancerTypeEnumApplication
}

func isNLB(lb elbv2types.LoadBalancer) bool {
	return lb.Type == elbv2types.LoadBalancerTypeEnumNetwork
}

// RegisterALBChecks registers ALB-related checks.
func RegisterALBChecks(d *awsdata.Data) {
	// elbv2-acm-certificate-required
	checker.Register(ConfigCheck(
		"elbv2-acm-certificate-required",
		"This rule checks ELBv2 ACM certificate required.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			listeners, err := d.ELBv2Listeners.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, l := range listeners {
				if l.Protocol != elbv2types.ProtocolEnumHttps && l.Protocol != elbv2types.ProtocolEnumTls {
					continue
				}
				id := "unknown"
				if l.ListenerArn != nil {
					id = *l.ListenerArn
				}
				ok := true
				if len(l.Certificates) == 0 {
					ok = false
				} else {
					for _, c := range l.Certificates {
						if c.CertificateArn == nil || !strings.Contains(*c.CertificateArn, ":acm:") {
							ok = false
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "ACM certificate required for TLS/HTTPS"})
			}
			return res, nil
		},
	))

	// elbv2-listener-encryption-in-transit
	checker.Register(ConfigCheck(
		"elbv2-listener-encryption-in-transit",
		"This rule checks encryption in transit for ELBv2 listener.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			listeners, err := d.ELBv2Listeners.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, l := range listeners {
				id := "unknown"
				if l.ListenerArn != nil {
					id = *l.ListenerArn
				}
				ok := l.Protocol == elbv2types.ProtocolEnumHttps || l.Protocol == elbv2types.ProtocolEnumTls
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Protocol: %s", l.Protocol)})
			}
			return res, nil
		},
	))

	// elbv2-multiple-az
	checker.Register(ConfigCheck(
		"elbv2-multiple-az",
		"This rule checks ELBv2 multiple az.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				id := lbID(lb)
				zones := make(map[string]bool)
				for _, az := range lb.AvailabilityZones {
					if az.ZoneName != nil {
						zones[*az.ZoneName] = true
					}
				}
				ok := len(zones) >= 2
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AZs: %d", len(zones))})
			}
			return res, nil
		},
	))

	// elbv2-predefined-security-policy-ssl-check
	checker.Register(ConfigCheck(
		"elbv2-predefined-security-policy-ssl-check",
		"This rule checks configuration for ELBv2 predefined security policy SSL.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			listeners, err := d.ELBv2Listeners.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, l := range listeners {
				if l.Protocol != elbv2types.ProtocolEnumHttps && l.Protocol != elbv2types.ProtocolEnumTls {
					continue
				}
				id := "unknown"
				if l.ListenerArn != nil {
					id = *l.ListenerArn
				}
				policy := ""
				if l.SslPolicy != nil {
					policy = *l.SslPolicy
				}
				ok := strings.HasPrefix(policy, "ELBSecurityPolicy-")
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("SSL policy: %s", policy)})
			}
			return res, nil
		},
	))
	// alb-tagged
	checker.Register(TaggedCheck(
		"alb-tagged",
		"This rule checks tagging for ALB exist.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.ELBv2Tags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, lb := range lbs {
				if !isALB(lb) || lb.LoadBalancerArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: lbID(lb), Tags: tags[*lb.LoadBalancerArn]})
			}
			return res, nil
		},
	))

	// alb-listener-tagged
	checker.Register(TaggedCheck(
		"alb-listener-tagged",
		"This rule checks tagging for ALB listener exist.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			listeners, err := d.ELBv2Listeners.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.ELBv2Tags.Get()
			if err != nil {
				return nil, err
			}
			albArns := make(map[string]bool)
			for _, lb := range lbs {
				if isALB(lb) && lb.LoadBalancerArn != nil {
					albArns[*lb.LoadBalancerArn] = true
				}
			}
			var res []TaggedResource
			for _, l := range listeners {
				if l.ListenerArn == nil || l.LoadBalancerArn == nil {
					continue
				}
				if !albArns[*l.LoadBalancerArn] {
					continue
				}
				res = append(res, TaggedResource{ID: *l.ListenerArn, Tags: tags[*l.ListenerArn]})
			}
			return res, nil
		},
	))

	// alb-internal-scheme-check
	checker.Register(ConfigCheck(
		"alb-internal-scheme-check",
		"This rule checks configuration for ALB internal scheme.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				if !isALB(lb) {
					continue
				}
				internal := lb.Scheme == elbv2types.LoadBalancerSchemeEnumInternal
				res = append(res, ConfigResource{ID: lbID(lb), Passing: internal, Detail: fmt.Sprintf("Scheme: %s", lb.Scheme)})
			}
			return res, nil
		},
	))

	// alb-http-to-https-redirection-check
	checker.Register(ConfigCheck(
		"alb-http-to-https-redirection-check",
		"This rule checks configuration for ALB HTTP to HTTPS redirection.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			listeners, err := d.ELBv2Listeners.Get()
			if err != nil {
				return nil, err
			}
			byLB := make(map[string][]elbv2types.Listener)
			for _, l := range listeners {
				if l.LoadBalancerArn != nil {
					byLB[*l.LoadBalancerArn] = append(byLB[*l.LoadBalancerArn], l)
				}
			}
			var res []ConfigResource
			for _, lb := range lbs {
				if !isALB(lb) || lb.LoadBalancerArn == nil {
					continue
				}
				lst := byLB[*lb.LoadBalancerArn]
				if len(lst) == 0 {
					res = append(res, ConfigResource{ID: lbID(lb), Passing: true, Detail: "No listeners"})
					continue
				}
				ok := true
				for _, l := range lst {
					if l.Protocol != elbv2types.ProtocolEnumHttp {
						continue
					}
					redirect := false
					for _, a := range l.DefaultActions {
						if a.Type == elbv2types.ActionTypeEnumRedirect && a.RedirectConfig != nil && a.RedirectConfig.Protocol != nil && *a.RedirectConfig.Protocol == "HTTPS" {
							redirect = true
							break
						}
					}
					if !redirect {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: lbID(lb), Passing: ok, Detail: fmt.Sprintf("HTTP listeners redirect: %v", ok)})
			}
			return res, nil
		},
	))

	// alb-http-drop-invalid-header-enabled + alb-desync-mode-check
	checker.Register(ConfigCheck(
		"alb-http-drop-invalid-header-enabled",
		"This rule checks enabled state for ALB HTTP drop invalid header.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			attrs, err := d.ELBv2LBAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				if !isALB(lb) || lb.LoadBalancerArn == nil {
					continue
				}
				m := attrs[*lb.LoadBalancerArn]
				enabled := m["routing.http.drop_invalid_header_fields.enabled"] == "true"
				res = append(res, ConfigResource{ID: lbID(lb), Passing: enabled, Detail: fmt.Sprintf("drop_invalid_header_fields: %v", enabled)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"alb-desync-mode-check",
		"This rule checks configuration for ALB desync mode.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			attrs, err := d.ELBv2LBAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				if !isALB(lb) || lb.LoadBalancerArn == nil {
					continue
				}
				mode := attrs[*lb.LoadBalancerArn]["routing.http.desync_mitigation_mode"]
				ok := mode == "defensive" || mode == "strictest"
				res = append(res, ConfigResource{ID: lbID(lb), Passing: ok, Detail: fmt.Sprintf("desync mode: %s", mode)})
			}
			return res, nil
		},
	))

	// alb-waf-enabled
	checker.Register(EnabledCheck(
		"alb-waf-enabled",
		"This rule checks enabled state for ALB WAF.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			assoc, err := d.WAFv2WebACLForResource.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, lb := range lbs {
				if !isALB(lb) || lb.LoadBalancerArn == nil {
					continue
				}
				res = append(res, EnabledResource{ID: lbID(lb), Enabled: assoc[*lb.LoadBalancerArn]})
			}
			return res, nil
		},
	))
}
