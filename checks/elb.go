package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// RegisterELBChecks registers classic ELB checks.
func RegisterELBChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"elb-acm-certificate-required",
		"This rule checks ELB ACM certificate required.",
		"elb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBClassicLBs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				id := elbID(lb)
				ok := true
				for _, l := range lb.ListenerDescriptions {
					if l.Listener == nil || !isELBEncryptedListener(l.Listener) {
						continue
					}
					cert := ""
					if l.Listener.SSLCertificateId != nil {
						cert = *l.Listener.SSLCertificateId
					}
					if !strings.Contains(cert, ":acm:") {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "ACM certificate required for TLS listeners"})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"elb-cross-zone-load-balancing-enabled",
		"This rule checks enabled state for ELB cross zone load balancing.",
		"elb",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			attrs, err := d.ELBClassicAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, attr := range attrs {
				enabled := attr.CrossZoneLoadBalancing != nil && attr.CrossZoneLoadBalancing.Enabled
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"elb-custom-security-policy-ssl-check",
		"This rule checks configuration for ELB custom security policy SSL.",
		"elb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBClassicLBs.Get()
			if err != nil {
				return nil, err
			}
			policies, err := d.ELBClassicPolicies.Get()
			if err != nil {
				return nil, err
			}
			customByLB := make(map[string]map[string]bool)
			for lbName, list := range policies {
				m := make(map[string]bool)
				for _, p := range list {
					if p.PolicyName == nil {
						continue
					}
					if p.PolicyTypeName != nil && *p.PolicyTypeName == "SSLNegotiationPolicyType" && !strings.HasPrefix(*p.PolicyName, "ELBSecurityPolicy-") {
						m[*p.PolicyName] = true
					}
				}
				customByLB[lbName] = m
			}
			var res []ConfigResource
			for _, lb := range lbs {
				id := elbID(lb)
				ok := true
				for _, l := range lb.ListenerDescriptions {
					if l.Listener == nil || !isELBEncryptedListener(l.Listener) {
						continue
					}
					listenerHasCustom := false
					customPolicies := customByLB[id]
					for _, pname := range l.PolicyNames {
						if customPolicies != nil && customPolicies[pname] {
							listenerHasCustom = true
							break
						}
					}
					if !listenerHasCustom {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Custom SSL policy attached"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"elb-deletion-protection-enabled",
		"This rule checks enabled state for ELB deletion protection.",
		"elb",
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
				if lb.LoadBalancerArn == nil {
					continue
				}
				m := attrs[*lb.LoadBalancerArn]
				enabled := m["deletion_protection.enabled"] == "true"
				res = append(res, ConfigResource{
					ID:      *lb.LoadBalancerArn,
					Passing: enabled,
					Detail:  fmt.Sprintf("Type: %s, deletion_protection.enabled: %v", lb.Type, enabled),
				})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"elb-internal-scheme-check",
		"This rule checks configuration for ELB internal scheme.",
		"elb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBClassicLBs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				internal := lb.Scheme != nil && *lb.Scheme == "internal"
				res = append(res, ConfigResource{ID: elbID(lb), Passing: internal, Detail: fmt.Sprintf("Scheme: %v", lb.Scheme)})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"elb-logging-enabled",
		"This rule checks logging is enabled for ELB.",
		"elb",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			attrs, err := d.ELBClassicAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, attr := range attrs {
				logging := attr.AccessLog != nil && attr.AccessLog.Enabled
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			lbAttrs, err := d.ELBv2LBAttributes.Get()
			if err != nil {
				return nil, err
			}
			for _, lb := range lbs {
				if lb.Type != elbv2types.LoadBalancerTypeEnumApplication || lb.LoadBalancerArn == nil {
					continue
				}
				m := lbAttrs[*lb.LoadBalancerArn]
				logging := m["access_logs.s3.enabled"] == "true"
				res = append(res, LoggingResource{ID: *lb.LoadBalancerArn, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"elb-predefined-security-policy-ssl-check",
		"This rule checks configuration for ELB predefined security policy SSL.",
		"elb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBClassicLBs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				id := elbID(lb)
				ok := true
				for _, l := range lb.ListenerDescriptions {
					if l.Listener == nil || !isELBEncryptedListener(l.Listener) {
						continue
					}
					listenerHasPredefined := false
					for _, pname := range l.PolicyNames {
						if strings.HasPrefix(pname, "ELBSecurityPolicy-") {
							listenerHasPredefined = true
							break
						}
					}
					if !listenerHasPredefined {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Predefined SSL policy attached"})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"elb-tagged",
		"This rule checks tagging for ELB exist.",
		"elb",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			lbs, err := d.ELBClassicLBs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.ELBClassicTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, lb := range lbs {
				name := elbID(lb)
				res = append(res, TaggedResource{ID: name, Tags: tags[name]})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"elb-tls-https-listeners-only",
		"This rule checks ELB TLS HTTPS listeners only.",
		"elb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBClassicLBs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				id := elbID(lb)
				ok := true
				for _, l := range lb.ListenerDescriptions {
					if l.Listener == nil {
						continue
					}
					if !isELBEncryptedListener(l.Listener) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Only TLS/HTTPS listeners allowed"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"clb-multiple-az",
		"This rule checks clb multiple az.",
		"elb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBClassicLBs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				id := elbID(lb)
				ok := len(lb.AvailabilityZones) > 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AZ count: %d", len(lb.AvailabilityZones))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"clb-desync-mode-check",
		"This rule checks clb desync mode check.",
		"elb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			attrs, err := d.ELBClassicAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, a := range attrs {
				mode := ""
				for _, extra := range a.AdditionalAttributes {
					if extra.Key != nil && *extra.Key == "elb.http.desync_mitigation_mode" {
						if extra.Value != nil {
							mode = *extra.Value
						}
						break
					}
				}
				mode = strings.ToLower(strings.TrimSpace(mode))
				ok := mode == "monitor" || mode == "defensive" || mode == "strictest"
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Desync mode: %s", mode)})
			}
			return res, nil
		},
	))
}

func elbID(lb elbtypes.LoadBalancerDescription) string {
	if lb.LoadBalancerName != nil {
		return *lb.LoadBalancerName
	}
	return "unknown"
}

func isELBEncryptedListener(l *elbtypes.Listener) bool {
	if l == nil || l.Protocol == nil {
		return false
	}
	p := strings.ToUpper(*l.Protocol)
	return p == "HTTPS" || p == "SSL"
}
