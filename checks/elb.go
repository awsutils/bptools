package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
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
				enabled := attr.CrossZoneLoadBalancing != nil && attr.CrossZoneLoadBalancing.Enabled != nil && *attr.CrossZoneLoadBalancing.Enabled
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
			attrs, err := d.ELBClassicAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, attr := range attrs {
				enabled := false
				for _, kv := range attr.AdditionalAttributes {
					if kv.Key != nil && *kv.Key == "deletion_protection.enabled" && kv.Value != nil && *kv.Value == "true" {
						enabled = true
						break
					}
				}
				res = append(res, ConfigResource{ID: name, Passing: enabled, Detail: fmt.Sprintf("deletion_protection.enabled: %v", enabled)})
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
				logging := attr.AccessLog != nil && attr.AccessLog.Enabled != nil && *attr.AccessLog.Enabled
				res = append(res, LoggingResource{ID: name, Logging: logging})
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
