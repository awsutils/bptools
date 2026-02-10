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
		"This rule checks enabled state for nlb cross zone load balancing.",
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
		"This rule checks configuration for nlb internal scheme.",
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
		"This rule checks tagging for nlb exist.",
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
		"This rule checks tagging for nlb listener exist.",
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
		"This rule checks logging is enabled for nlb.",
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
