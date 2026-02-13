package checks

import (
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterRoute53Checks registers Route53 checks.
func RegisterRoute53Checks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"route53-health-check-tagged",
		"Checks if Amazon Route 53 health checks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Route 53 hosted zones have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if DNS query logging is enabled for your Amazon Route 53 public hosted zones. The rule is NON_COMPLIANT if DNS query logging is not enabled for your Amazon Route 53 public hosted zones.",
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
		"Checks if Amazon Route 53 Resolver firewall domain lists have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
				if route53ResolverFirewallDomainListIsAWSManaged(l.ManagedOwnerName) {
					continue
				}
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
		"Checks if Amazon Route 53 Resolver firewall rule group associations have tags. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Route 53 Resolver firewall rule groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Route 53 Resolver resolver rules have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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

func route53ResolverFirewallDomainListIsAWSManaged(managedOwnerName *string) bool {
	if managedOwnerName == nil {
		return false
	}
	return strings.TrimSpace(*managedOwnerName) != ""
}
