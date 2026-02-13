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
		"Checks if logging is enabled on AWS WAF classic global web access control lists (web ACLs). The rule is NON_COMPLIANT for a global web ACL, if it does not have logging enabled.",
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
		"Checks if an AWS WAF Classic rule group contains any rules. The rule is NON_COMPLIANT if there are no rules present within a rule group.",
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
		"Checks if an AWS WAF global rule contains any conditions. The rule is NON_COMPLIANT if no conditions are present within the WAF global rule.",
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
		"Checks whether a WAF Global Web ACL contains any WAF rules or rule groups. This rule is NON_COMPLIANT if a Web ACL does not contain any WAF rule or rule group.",
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
		"Checks if WAF Regional rule groups contain any rules. The rule is NON_COMPLIANT if there are no rules present within a WAF Regional rule group.",
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
		"Checks whether WAF regional rule contains conditions. This rule is COMPLIANT if the regional rule contains at least one condition and NON_COMPLIANT otherwise.",
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
		"Checks if a WAF regional Web ACL contains any WAF rules or rule groups. The rule is NON_COMPLIANT if there are no WAF rules or rule groups present within a Web ACL.",
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
		"Checks if logging is enabled on AWS WAFv2 regional and global web access control lists (web ACLs). The rule is NON_COMPLIANT if the logging is enabled but the logging destination does not match the value of the parameter.",
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
		"Checks if Amazon CloudWatch security metrics collection on AWS WAFv2 rule groups is enabled. The rule is NON_COMPLIANT if the 'VisibilityConfig.CloudWatchMetricsEnabled' field is set to false.",
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
		"Checks if WAFv2 Rule Groups contain rules. The rule is NON_COMPLIANT if there are no rules in a WAFv2 Rule Group.",
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
		"Checks if a WAFv2 Web ACL contains any WAF rules or WAF rule groups. This rule is NON_COMPLIANT if a Web ACL does not contain any WAF rules or WAF rule groups.",
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
