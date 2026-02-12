package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/waf"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"
)

// RegisterWAFChecks registers WAF checks (classic, regional, v2).
func RegisterWAFChecks(d *awsdata.Data) {
	checker.Register(LoggingCheck(
		"waf-classic-logging-enabled",
		"This rule checks logging is enabled for WAF classic.",
		"waf",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			acls, err := d.WAFWebACLs.Get()
			if err != nil {
				return nil, err
			}
			logs, err := d.WAFLoggingConfigurations.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, a := range acls {
				id := "unknown"
				if a.WebACLId != nil {
					id = *a.WebACLId
				}
				_, ok := logs[id]
				res = append(res, LoggingResource{ID: id, Logging: ok})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"waf-global-rulegroup-not-empty",
		"This rule checks WAF global rulegroup not empty.",
		"waf",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rgs, err := d.WAFRuleGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, rg := range rgs {
				if rg.RuleGroupId == nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing RuleGroupId"})
					continue
				}
				out, err := d.Clients.WAF.ListActivatedRulesInRuleGroup(d.Ctx, &waf.ListActivatedRulesInRuleGroupInput{RuleGroupId: rg.RuleGroupId})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("GetActivatedRulesInRuleGroup failed: %v", err)})
					continue
				}
				ruleCount := len(out.ActivatedRules)
				res = append(res, ConfigResource{ID: id, Passing: ruleCount > 0, Detail: fmt.Sprintf("Activated rules: %d", ruleCount)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"waf-global-rule-not-empty",
		"This rule checks WAF global rule not empty.",
		"waf",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rules, err := d.WAFRuleDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, r := range rules {
				ok := len(r.Predicates) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Predicates: %d", len(r.Predicates))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"waf-global-webacl-not-empty",
		"This rule checks WAF global webacl not empty.",
		"waf",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			acls, err := d.WAFWebACLDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, a := range acls {
				ok := len(a.Rules) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Rules: %d", len(a.Rules))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"waf-regional-rulegroup-not-empty",
		"This rule checks WAF regional rulegroup not empty.",
		"wafregional",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rgs, err := d.WAFRegionalRuleGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, rg := range rgs {
				if rg.RuleGroupId == nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing RuleGroupId"})
					continue
				}
				out, err := d.Clients.WAFRegional.ListActivatedRulesInRuleGroup(d.Ctx, &wafregional.ListActivatedRulesInRuleGroupInput{RuleGroupId: rg.RuleGroupId})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("GetActivatedRulesInRuleGroup failed: %v", err)})
					continue
				}
				ruleCount := len(out.ActivatedRules)
				res = append(res, ConfigResource{ID: id, Passing: ruleCount > 0, Detail: fmt.Sprintf("Activated rules: %d", ruleCount)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"waf-regional-rule-not-empty",
		"This rule checks WAF regional rule not empty.",
		"wafregional",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rules, err := d.WAFRegionalRuleDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, r := range rules {
				ok := len(r.Predicates) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Predicates: %d", len(r.Predicates))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"waf-regional-webacl-not-empty",
		"This rule checks WAF regional webacl not empty.",
		"wafregional",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			acls, err := d.WAFRegionalWebACLDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, a := range acls {
				ok := len(a.Rules) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Rules: %d", len(a.Rules))})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"wafv2-logging-enabled",
		"This rule checks logging is enabled for wafv2.",
		"wafv2",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			acls, err := d.WAFv2WebACLs.Get()
			if err != nil {
				return nil, err
			}
			logs, err := d.WAFv2LoggingConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, a := range acls {
				id := "unknown"
				if a.ARN != nil {
					id = *a.ARN
				}
				_, ok := logs[id]
				res = append(res, LoggingResource{ID: id, Logging: ok})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"wafv2-rulegroup-logging-enabled",
		"This rule checks logging is enabled for wafv2 rulegroup.",
		"wafv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rgs, err := d.WAFv2RuleGroups.Get()
			if err != nil {
				return nil, err
			}
			details, err := d.WAFv2RuleGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, rg := range rgs {
				id := "unknown"
				if rg.ARN != nil {
					id = *rg.ARN
				}
				detail, ok := details[id]
				if !ok {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Rule group details not found"})
					continue
				}
				metricsEnabled := detail.VisibilityConfig != nil && detail.VisibilityConfig.CloudWatchMetricsEnabled
				res = append(res, ConfigResource{ID: id, Passing: metricsEnabled, Detail: fmt.Sprintf("CloudWatchMetricsEnabled: %v", metricsEnabled)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"wafv2-rulegroup-not-empty",
		"This rule checks wafv2 rulegroup not empty.",
		"wafv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rgs, err := d.WAFv2RuleGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, rg := range rgs {
				ok := len(rg.Rules) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Rules: %d", len(rg.Rules))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"wafv2-webacl-not-empty",
		"This rule checks wafv2 webacl not empty.",
		"wafv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			acls, err := d.WAFv2WebACLDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, a := range acls {
				ok := len(a.Rules) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Rules: %d", len(a.Rules))})
			}
			return res, nil
		},
	))
}
