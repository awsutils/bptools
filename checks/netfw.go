package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterNetFWChecks registers Network Firewall checks.
func RegisterNetFWChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"netfw-deletion-protection-enabled",
		"Checks if AWS Network Firewall has deletion protection enabled. The rule is NON_COMPLIANT if Network Firewall does not have deletion protection enabled.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			details, err := d.NetworkFirewallDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, desc := range details {
				enabled := desc.Firewall != nil && desc.Firewall.DeleteProtection
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"netfw-logging-enabled",
		"Checks if AWS Network Firewall firewalls have logging enabled. The rule is NON_COMPLIANT if a logging type is not configured. You can specify which logging type you want the rule to check.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			logs, err := d.NetworkFirewallLogging.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for arn, cfg := range logs {
				logging := cfg.LoggingConfiguration != nil && len(cfg.LoggingConfiguration.LogDestinationConfigs) > 0
				res = append(res, LoggingResource{ID: arn, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"netfw-multi-az-enabled",
		"Checks if AWS Network Firewall firewalls are deployed across multiple Availability Zones. The rule is NON_COMPLIANT if firewalls are deployed in only one Availability Zone or in fewer zones than the number listed in the optional parameter.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			details, err := d.NetworkFirewallDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, desc := range details {
				count := 0
				if desc.Firewall != nil {
					count = len(desc.Firewall.SubnetMappings)
				}
				enabled := count >= 2
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"netfw-policy-default-action-fragment-packets",
		"Checks if an AWS Network Firewall policy is configured with a user defined stateless default action for fragmented packets. The rule is NON_COMPLIANT if stateless default action for fragmented packets does not match with user defined default action.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.NetworkFirewallPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, pol := range policies {
				actions := []string{}
				if pol.FirewallPolicy != nil {
					actions = pol.FirewallPolicy.StatelessFragmentDefaultActions
				}
				ok := actionHasDrop(actions)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Fragment actions: %v", actions)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"netfw-policy-default-action-full-packets",
		"Checks if an AWS Network Firewall policy is configured with a user defined default stateless action for full packets. This rule is NON_COMPLIANT if default stateless action for full packets does not match with user defined default stateless action.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.NetworkFirewallPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, pol := range policies {
				actions := []string{}
				if pol.FirewallPolicy != nil {
					actions = pol.FirewallPolicy.StatelessDefaultActions
				}
				ok := actionHasDrop(actions)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Default actions: %v", actions)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"netfw-policy-rule-group-associated",
		"Check AWS Network Firewall policy is associated with stateful OR stateless rule groups. This rule is NON_COMPLIANT if no stateful or stateless rule groups are associated with the Network Firewall policy else COMPLIANT if any one of the rule group exists.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.NetworkFirewallPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, pol := range policies {
				count := 0
				if pol.FirewallPolicy != nil {
					count = len(pol.FirewallPolicy.StatefulRuleGroupReferences) + len(pol.FirewallPolicy.StatelessRuleGroupReferences)
				}
				ok := count > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Rule groups: %d", count)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"netfw-stateless-rule-group-not-empty",
		"Checks if a Stateless Network Firewall Rule Group contains rules. The rule is NON_COMPLIANT if there are no rules in a Stateless Network Firewall Rule Group.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rgs, err := d.NetworkFirewallRuleGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, rg := range rgs {
				if rg.RuleGroupResponse == nil || rg.RuleGroupResponse.Type != "STATELESS" {
					continue
				}
				nonEmpty := false
				if rg.RuleGroup != nil && rg.RuleGroup.RulesSource != nil && rg.RuleGroup.RulesSource.StatelessRulesAndCustomActions != nil {
					if len(rg.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules) > 0 {
						nonEmpty = true
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: nonEmpty, Detail: "Stateless rules present"})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"netfw-subnet-change-protection-enabled",
		"Checks if AWS Network Firewall has subnet change protection enabled. The rule is NON_COMPLIANT if subnet change protection is not enabled.",
		"netfw",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			details, err := d.NetworkFirewallDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, desc := range details {
				enabled := desc.Firewall != nil && desc.Firewall.SubnetChangeProtection
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))
}

func actionHasDrop(actions []string) bool {
	for _, a := range actions {
		if strings.Contains(a, "drop") {
			return true
		}
	}
	return false
}
