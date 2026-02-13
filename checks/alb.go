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
		"Checks if Application Load Balancers and Network Load Balancers have listeners that are configured to use certificates from AWS Certificate Manager (ACM). This rule is NON_COMPLIANT if at least 1 load balancer has at least 1 listener that is configured without a certificate from ACM or is configured with a certificate different from an ACM certificate.",
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
		"Checks if listeners for the load balancers are configured with HTTPS or TLS termination. The rule is NON_COMPLIANT if listeners are not configured with HTTPS or TLS termination.",
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
		"Checks if an Elastic Load Balancer V2 (Application, Network, or Gateway Load Balancer) is mapped to multiple Availability Zones (AZs). The rule is NON_COMPLIANT if an Elastic Load Balancer V2 is mapped to less than 2 AZs. For more information, see Availability Zones for your Application Load Balancer.",
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
		"Checks if listeners for Application Load Balancers (ALBs) or Network Load Balancers (NLBs) use certain security policies. The rule is NON_COMPLIANT if an HTTPS listener for an ALB or a TLS listener for a NLB does not use the security policies you specify.",
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
		"Checks if Application Load Balancers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Application Load Balancer listeners have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if an Application Load Balancer scheme is internal. The rule is NON_COMPLIANT if configuration.scheme is not set to internal.",
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
		"Checks if HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers. The rule is NON_COMPLIANT if one or more HTTP listeners of Application Load Balancer do not have HTTP to HTTPS redirection configured. The rule is also NON_COMPLIANT if one of more HTTP listeners have forwarding to an HTTP listener instead of redirection.",
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
		"Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false",
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
		"Checks if an Application Load Balancer (ALB) is configured with a user defined desync mitigation mode. The rule is NON_COMPLIANT if ALB desync mitigation mode does not match with the user defined desync mitigation mode.",
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
		"Checks if Web Application Firewall (WAF) is enabled on Application Load Balancers (ALBs). This rule is NON_COMPLIANT if key: waf.enabled is set to false.",
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
