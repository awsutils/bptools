package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// RegisterNLBChecks registers NLB checks.
func RegisterNLBChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"nlb-cross-zone-load-balancing-enabled",
		"Checks if cross-zone load balancing is enabled on Network Load Balancers (NLBs). The rule is NON_COMPLIANT if cross-zone load balancing is not enabled for an NLB.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			attrs, err := d.ELBv2LBAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, lb := range lbs {
				if lb.Type != elbv2types.LoadBalancerTypeEnumNetwork || lb.LoadBalancerArn == nil {
					continue
				}
				m := attrs[*lb.LoadBalancerArn]
				enabled := m["load_balancing.cross_zone.enabled"] == "true"
				res = append(res, EnabledResource{ID: lbID(lb), Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"nlb-internal-scheme-check",
		"Checks if a Network Load Balancer scheme is internal. The rule is NON_COMPLIANT if configuration.scheme is not set to internal.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lb := range lbs {
				if lb.Type != elbv2types.LoadBalancerTypeEnumNetwork {
					continue
				}
				internal := lb.Scheme == elbv2types.LoadBalancerSchemeEnumInternal
				res = append(res, ConfigResource{ID: lbID(lb), Passing: internal, Detail: fmt.Sprintf("Scheme: %s", lb.Scheme)})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"nlb-tagged",
		"Checks if Network Load Balancers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
				if lb.Type != elbv2types.LoadBalancerTypeEnumNetwork || lb.LoadBalancerArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: lbID(lb), Tags: tags[*lb.LoadBalancerArn]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"nlb-listener-tagged",
		"Checks if Network Load Balancer listeners have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
			nlbArns := make(map[string]bool)
			for _, lb := range lbs {
				if lb.Type == elbv2types.LoadBalancerTypeEnumNetwork && lb.LoadBalancerArn != nil {
					nlbArns[*lb.LoadBalancerArn] = true
				}
			}
			var res []TaggedResource
			for _, l := range listeners {
				if l.ListenerArn == nil || l.LoadBalancerArn == nil {
					continue
				}
				if !nlbArns[*l.LoadBalancerArn] {
					continue
				}
				res = append(res, TaggedResource{ID: *l.ListenerArn, Tags: tags[*l.ListenerArn]})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"nlb-logging-enabled",
		"Checks if access logging is enabled for Network Load Balancers. The rule is NON_COMPLIANT if access logging is not enabled for a Network Load balancer.",
		"elbv2",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			lbs, err := d.ELBv2LoadBalancers.Get()
			if err != nil {
				return nil, err
			}
			attrs, err := d.ELBv2LBAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, lb := range lbs {
				if lb.Type != elbv2types.LoadBalancerTypeEnumNetwork || lb.LoadBalancerArn == nil {
					continue
				}
				m := attrs[*lb.LoadBalancerArn]
				logging := m["access_logs.s3.enabled"] == "true"
				res = append(res, LoggingResource{ID: lbID(lb), Logging: logging})
			}
			return res, nil
		},
	))
}
