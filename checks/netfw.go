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
		"This rule checks enabled state for netfw deletion protection.",
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
		"This rule checks logging is enabled for netfw.",
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
		"This rule checks enabled state for netfw multi az.",
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
		"This rule checks netfw policy default action fragment packets.",
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
		"This rule checks netfw policy default action full packets.",
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
		"This rule checks netfw policy rule group associated.",
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
		"This rule checks netfw stateless rule group not empty.",
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
		"This rule checks enabled state for netfw subnet change protection.",
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
