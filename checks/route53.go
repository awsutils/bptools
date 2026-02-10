package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterRoute53Checks registers Route53 checks.
func RegisterRoute53Checks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"route53-health-check-tagged",
		"This rule checks tagging for route53 health check exist.",
		"route53",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			hcs, err := d.Route53HealthChecks.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.Route53HealthCheckTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, hc := range hcs {
				id := "unknown"
				if hc.Id != nil {
					id = *hc.Id
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"route53-hosted-zone-tagged",
		"This rule checks tagging for route53 hosted zone exist.",
		"route53",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			zones, err := d.Route53HostedZones.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.Route53HostedZoneTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, z := range zones {
				id := "unknown"
				if z.Id != nil {
					id = *z.Id
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"route53-query-logging-enabled",
		"This rule checks route53 query logging enabled.",
		"route53",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			zones, err := d.Route53HostedZones.Get()
			if err != nil {
				return nil, err
			}
			configs, err := d.Route53QueryLoggingConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, z := range zones {
				id := "unknown"
				if z.Id != nil {
					id = *z.Id
				}
				logging := len(configs[id]) > 0
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"route53-resolver-firewall-domain-list-tagged",
		"This rule checks tagging for route53 resolver firewall domain list exist.",
		"route53resolver",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			lists, err := d.Route53ResolverFirewallDomainLists.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.Route53ResolverTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, l := range lists {
				id := "unknown"
				if l.Arn != nil {
					id = *l.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"route53-resolver-firewall-rule-group-association-tagged",
		"This rule checks tagging for route53 resolver firewall rule group association exist.",
		"route53resolver",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.Route53ResolverFirewallRuleGroupAssociations.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.Route53ResolverTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range items {
				id := "unknown"
				if a.Arn != nil {
					id = *a.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"route53-resolver-firewall-rule-group-tagged",
		"This rule checks tagging for route53 resolver firewall rule group exist.",
		"route53resolver",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.Route53ResolverFirewallRuleGroups.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.Route53ResolverTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range items {
				id := "unknown"
				if a.Arn != nil {
					id = *a.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"route53-resolver-resolver-rule-tagged",
		"This rule checks tagging for route53 resolver rule exist.",
		"route53resolver",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.Route53ResolverRules.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.Route53ResolverTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range items {
				id := "unknown"
				if a.Arn != nil {
					id = *a.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
