package fixes

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/waf"
	waftypes "github.com/aws/aws-sdk-go-v2/service/waf/types"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"
	wafregionaltypes "github.com/aws/aws-sdk-go-v2/service/wafregional/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func registerMultiBatch04(d *awsdata.Data) {
	register := func(checkID, desc string, fn func(*multiBatch04Fix, fix.FixContext, string) fix.FixResult) {
		fix.Register(&multiBatch04Fix{checkID: checkID, description: desc, clients: d.Clients, applyFn: fn})
	}

	register("waf-classic-logging-enabled", "Enable WAF Classic logging using an existing aws-waf-logs-* Firehose stream", applyWAFClassicLoggingEnabled)
	register("waf-global-rulegroup-not-empty", "Add a minimal COUNT rule to empty WAF Classic global rule groups", applyWAFGlobalRuleGroupNotEmpty)
	register("waf-global-rule-not-empty", "Add a minimal IP match predicate to empty WAF Classic global rules", applyWAFGlobalRuleNotEmpty)
	register("waf-global-webacl-not-empty", "Add a minimal COUNT rule to empty WAF Classic global web ACLs", applyWAFGlobalWebACLNotEmpty)
	register("waf-regional-rulegroup-not-empty", "Add a minimal COUNT rule to empty WAF Classic regional rule groups", applyWAFRegionalRuleGroupNotEmpty)
	register("waf-regional-rule-not-empty", "Add a minimal IP match predicate to empty WAF Classic regional rules", applyWAFRegionalRuleNotEmpty)
	register("waf-regional-webacl-not-empty", "Add a minimal COUNT rule to empty WAF Classic regional web ACLs", applyWAFRegionalWebACLNotEmpty)
	register("wafv2-logging-enabled", "Enable WAFv2 logging using an existing aws-waf-logs-* Firehose stream", applyWAFv2LoggingEnabled)
	register("wafv2-rulegroup-not-empty", "Add a minimal COUNT geo-match rule to empty WAFv2 rule groups", applyWAFv2RuleGroupNotEmpty)
	register("wafv2-webacl-not-empty", "Add a minimal COUNT geo-match rule to empty WAFv2 web ACLs", applyWAFv2WebACLNotEmpty)
}

type multiBatch04Fix struct {
	checkID     string
	description string
	clients     *awsdata.Clients
	applyFn     func(*multiBatch04Fix, fix.FixContext, string) fix.FixResult
}

func (f *multiBatch04Fix) CheckID() string             { return f.checkID }
func (f *multiBatch04Fix) Description() string         { return f.description }
func (f *multiBatch04Fix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *multiBatch04Fix) Severity() fix.SeverityLevel { return fix.SeverityMedium }
func (f *multiBatch04Fix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	return f.applyFn(f, fctx, strings.TrimSpace(resourceID))
}

func applyWAFClassicLoggingEnabled(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty web ACL ID"
		return base
	}

	getOut, err := f.clients.WAF.GetLoggingConfiguration(fctx.Ctx, &waf.GetLoggingConfigurationInput{ResourceArn: aws.String(resourceID)})
	if err == nil && getOut != nil && getOut.LoggingConfiguration != nil && len(getOut.LoggingConfiguration.LogDestinationConfigs) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "logging already enabled"
		return base
	}
	if err != nil && !isWAFClassicNotFound(err) {
		base.Status = fix.FixFailed
		base.Message = "get logging configuration: " + err.Error()
		return base
	}

	destinationARN, err := findWAFFirehoseDestinationARN(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "discover log destination: " + err.Error()
		return base
	}
	if destinationARN == "" {
		base.Status = fix.FixSkipped
		base.Message = "no Firehose delivery stream with prefix aws-waf-logs- found"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable WAF Classic logging", "would set destination " + destinationARN}
		return base
	}

	_, err = f.clients.WAF.PutLoggingConfiguration(fctx.Ctx, &waf.PutLoggingConfigurationInput{
		LoggingConfiguration: &waftypes.LoggingConfiguration{
			ResourceArn:           aws.String(resourceID),
			LogDestinationConfigs: []string{destinationARN},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put logging configuration: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "enabled WAF Classic logging"
	base.Steps = []string{"configured destination " + destinationARN}
	return base
}

func applyWAFGlobalRuleGroupNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty rule group ID"
		return base
	}

	rgOut, err := f.clients.WAF.GetRuleGroup(fctx.Ctx, &waf.GetRuleGroupInput{RuleGroupId: aws.String(resourceID)})
	if err != nil {
		if isWAFClassicNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "rule group not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get rule group: " + err.Error()
		return base
	}
	if rgOut.RuleGroup == nil {
		base.Status = fix.FixSkipped
		base.Message = "rule group not found"
		return base
	}
	activatedOut, err := f.clients.WAF.ListActivatedRulesInRuleGroup(fctx.Ctx, &waf.ListActivatedRulesInRuleGroupInput{
		RuleGroupId: aws.String(resourceID),
	})
	if err != nil {
		if isWAFClassicNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "rule group not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "list activated rules in rule group: " + err.Error()
		return base
	}
	if len(activatedOut.ActivatedRules) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "rule group already has activated rules"
		return base
	}

	ruleName := multiBatch04Name("BPTWAFRule")
	metricName := multiBatch04Name("BPTWAFMetric")
	priority := nextWAFClassicPriority(activatedOut.ActivatedRules)
	steps := []string{"create helper WAF classic rule", "insert helper rule into rule group"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	ruleID, err := createWAFClassicRule(fctx, f.clients, ruleName, metricName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create helper rule: " + err.Error()
		return base
	}

	changeToken, err := getWAFClassicChangeToken(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get change token: " + err.Error()
		return base
	}

	_, err = f.clients.WAF.UpdateRuleGroup(fctx.Ctx, &waf.UpdateRuleGroupInput{
		ChangeToken: aws.String(changeToken),
		RuleGroupId: aws.String(resourceID),
		Updates: []waftypes.RuleGroupUpdate{{
			Action: waftypes.ChangeActionInsert,
			ActivatedRule: &waftypes.ActivatedRule{
				RuleId:   aws.String(ruleID),
				Priority: aws.Int32(priority),
				Action:   &waftypes.WafAction{Type: waftypes.WafActionTypeCount},
				Type:     waftypes.WafRuleTypeRegular,
			},
		}},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update rule group: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "inserted helper rule into empty rule group"
	base.Steps = append(steps, "helper rule ID: "+ruleID)
	return base
}

func applyWAFGlobalRuleNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty rule ID"
		return base
	}

	ruleOut, err := f.clients.WAF.GetRule(fctx.Ctx, &waf.GetRuleInput{RuleId: aws.String(resourceID)})
	if err != nil {
		if isWAFClassicNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "rule not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get rule: " + err.Error()
		return base
	}
	if ruleOut.Rule == nil {
		base.Status = fix.FixSkipped
		base.Message = "rule not found"
		return base
	}
	if len(ruleOut.Rule.Predicates) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "rule already has predicates"
		return base
	}

	ipSetName := multiBatch04Name("BPTWAFIPSet")
	steps := []string{"create helper IP set", "add helper CIDR predicate to rule"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	ipSetID, err := createWAFClassicIPSetWithCIDR(fctx, f.clients, ipSetName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create helper IP set: " + err.Error()
		return base
	}

	changeToken, err := getWAFClassicChangeToken(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get change token: " + err.Error()
		return base
	}

	_, err = f.clients.WAF.UpdateRule(fctx.Ctx, &waf.UpdateRuleInput{
		ChangeToken: aws.String(changeToken),
		RuleId:      aws.String(resourceID),
		Updates: []waftypes.RuleUpdate{{
			Action: waftypes.ChangeActionInsert,
			Predicate: &waftypes.Predicate{
				DataId:  aws.String(ipSetID),
				Negated: aws.Bool(false),
				Type:    waftypes.PredicateTypeIpMatch,
			},
		}},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update rule: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "added helper predicate to empty rule"
	base.Steps = append(steps, "helper IP set ID: "+ipSetID)
	return base
}

func applyWAFGlobalWebACLNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty web ACL ID"
		return base
	}

	aclOut, err := f.clients.WAF.GetWebACL(fctx.Ctx, &waf.GetWebACLInput{WebACLId: aws.String(resourceID)})
	if err != nil {
		if isWAFClassicNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "web ACL not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get web ACL: " + err.Error()
		return base
	}
	if aclOut.WebACL == nil {
		base.Status = fix.FixSkipped
		base.Message = "web ACL not found"
		return base
	}
	if len(aclOut.WebACL.Rules) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "web ACL already has rules"
		return base
	}

	ruleName := multiBatch04Name("BPTWAFWebRule")
	metricName := multiBatch04Name("BPTWAFWebMetric")
	priority := nextWAFClassicPriority(aclOut.WebACL.Rules)
	steps := []string{"create helper WAF classic rule", "insert helper rule into web ACL"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	ruleID, err := createWAFClassicRule(fctx, f.clients, ruleName, metricName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create helper rule: " + err.Error()
		return base
	}

	changeToken, err := getWAFClassicChangeToken(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get change token: " + err.Error()
		return base
	}

	defaultAction := aclOut.WebACL.DefaultAction
	if defaultAction == nil {
		defaultAction = &waftypes.WafAction{Type: waftypes.WafActionTypeAllow}
	}

	_, err = f.clients.WAF.UpdateWebACL(fctx.Ctx, &waf.UpdateWebACLInput{
		ChangeToken:   aws.String(changeToken),
		WebACLId:      aws.String(resourceID),
		DefaultAction: defaultAction,
		Updates: []waftypes.WebACLUpdate{{
			Action: waftypes.ChangeActionInsert,
			ActivatedRule: &waftypes.ActivatedRule{
				RuleId:   aws.String(ruleID),
				Priority: aws.Int32(priority),
				Action:   &waftypes.WafAction{Type: waftypes.WafActionTypeCount},
				Type:     waftypes.WafRuleTypeRegular,
			},
		}},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update web ACL: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "inserted helper rule into empty web ACL"
	base.Steps = append(steps, "helper rule ID: "+ruleID)
	return base
}

func applyWAFRegionalRuleGroupNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty rule group ID"
		return base
	}

	rgOut, err := f.clients.WAFRegional.GetRuleGroup(fctx.Ctx, &wafregional.GetRuleGroupInput{RuleGroupId: aws.String(resourceID)})
	if err != nil {
		if isWAFRegionalNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "rule group not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get regional rule group: " + err.Error()
		return base
	}
	if rgOut.RuleGroup == nil {
		base.Status = fix.FixSkipped
		base.Message = "rule group not found"
		return base
	}
	activatedOut, err := f.clients.WAFRegional.ListActivatedRulesInRuleGroup(fctx.Ctx, &wafregional.ListActivatedRulesInRuleGroupInput{
		RuleGroupId: aws.String(resourceID),
	})
	if err != nil {
		if isWAFRegionalNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "rule group not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "list activated rules in regional rule group: " + err.Error()
		return base
	}
	if len(activatedOut.ActivatedRules) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "rule group already has activated rules"
		return base
	}

	ruleName := multiBatch04Name("BPTRWAFRule")
	metricName := multiBatch04Name("BPTRWAFMetric")
	priority := nextWAFRegionalPriority(activatedOut.ActivatedRules)
	steps := []string{"create helper WAF regional rule", "insert helper rule into regional rule group"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	ruleID, err := createWAFRegionalRule(fctx, f.clients, ruleName, metricName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create helper rule: " + err.Error()
		return base
	}

	changeToken, err := getWAFRegionalChangeToken(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get regional change token: " + err.Error()
		return base
	}

	_, err = f.clients.WAFRegional.UpdateRuleGroup(fctx.Ctx, &wafregional.UpdateRuleGroupInput{
		ChangeToken: aws.String(changeToken),
		RuleGroupId: aws.String(resourceID),
		Updates: []wafregionaltypes.RuleGroupUpdate{{
			Action: wafregionaltypes.ChangeActionInsert,
			ActivatedRule: &wafregionaltypes.ActivatedRule{
				RuleId:   aws.String(ruleID),
				Priority: aws.Int32(priority),
				Action:   &wafregionaltypes.WafAction{Type: wafregionaltypes.WafActionTypeCount},
				Type:     wafregionaltypes.WafRuleTypeRegular,
			},
		}},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update regional rule group: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "inserted helper rule into empty regional rule group"
	base.Steps = append(steps, "helper rule ID: "+ruleID)
	return base
}

func applyWAFRegionalRuleNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty rule ID"
		return base
	}

	ruleOut, err := f.clients.WAFRegional.GetRule(fctx.Ctx, &wafregional.GetRuleInput{RuleId: aws.String(resourceID)})
	if err != nil {
		if isWAFRegionalNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "rule not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get regional rule: " + err.Error()
		return base
	}
	if ruleOut.Rule == nil {
		base.Status = fix.FixSkipped
		base.Message = "rule not found"
		return base
	}
	if len(ruleOut.Rule.Predicates) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "rule already has predicates"
		return base
	}

	ipSetName := multiBatch04Name("BPTRWAFIPSet")
	steps := []string{"create helper regional IP set", "add helper CIDR predicate to regional rule"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	ipSetID, err := createWAFRegionalIPSetWithCIDR(fctx, f.clients, ipSetName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create helper IP set: " + err.Error()
		return base
	}

	changeToken, err := getWAFRegionalChangeToken(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get regional change token: " + err.Error()
		return base
	}

	_, err = f.clients.WAFRegional.UpdateRule(fctx.Ctx, &wafregional.UpdateRuleInput{
		ChangeToken: aws.String(changeToken),
		RuleId:      aws.String(resourceID),
		Updates: []wafregionaltypes.RuleUpdate{{
			Action: wafregionaltypes.ChangeActionInsert,
			Predicate: &wafregionaltypes.Predicate{
				DataId:  aws.String(ipSetID),
				Negated: aws.Bool(false),
				Type:    wafregionaltypes.PredicateTypeIpMatch,
			},
		}},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update regional rule: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "added helper predicate to empty regional rule"
	base.Steps = append(steps, "helper IP set ID: "+ipSetID)
	return base
}

func applyWAFRegionalWebACLNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty web ACL ID"
		return base
	}

	aclOut, err := f.clients.WAFRegional.GetWebACL(fctx.Ctx, &wafregional.GetWebACLInput{WebACLId: aws.String(resourceID)})
	if err != nil {
		if isWAFRegionalNotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "web ACL not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get regional web ACL: " + err.Error()
		return base
	}
	if aclOut.WebACL == nil {
		base.Status = fix.FixSkipped
		base.Message = "web ACL not found"
		return base
	}
	if len(aclOut.WebACL.Rules) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "web ACL already has rules"
		return base
	}

	ruleName := multiBatch04Name("BPTRWAFWebRl")
	metricName := multiBatch04Name("BPTRWAFWebMt")
	priority := nextWAFRegionalPriority(aclOut.WebACL.Rules)
	steps := []string{"create helper WAF regional rule", "insert helper rule into regional web ACL"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	ruleID, err := createWAFRegionalRule(fctx, f.clients, ruleName, metricName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create helper rule: " + err.Error()
		return base
	}

	changeToken, err := getWAFRegionalChangeToken(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get regional change token: " + err.Error()
		return base
	}

	defaultAction := aclOut.WebACL.DefaultAction
	if defaultAction == nil {
		defaultAction = &wafregionaltypes.WafAction{Type: wafregionaltypes.WafActionTypeAllow}
	}

	_, err = f.clients.WAFRegional.UpdateWebACL(fctx.Ctx, &wafregional.UpdateWebACLInput{
		ChangeToken:   aws.String(changeToken),
		WebACLId:      aws.String(resourceID),
		DefaultAction: defaultAction,
		Updates: []wafregionaltypes.WebACLUpdate{{
			Action: wafregionaltypes.ChangeActionInsert,
			ActivatedRule: &wafregionaltypes.ActivatedRule{
				RuleId:   aws.String(ruleID),
				Priority: aws.Int32(priority),
				Action:   &wafregionaltypes.WafAction{Type: wafregionaltypes.WafActionTypeCount},
				Type:     wafregionaltypes.WafRuleTypeRegular,
			},
		}},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update regional web ACL: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "inserted helper rule into empty regional web ACL"
	base.Steps = append(steps, "helper rule ID: "+ruleID)
	return base
}

func applyWAFv2LoggingEnabled(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	if resourceID == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty web ACL ARN"
		return base
	}

	getOut, err := f.clients.WAFv2.GetLoggingConfiguration(fctx.Ctx, &wafv2.GetLoggingConfigurationInput{ResourceArn: aws.String(resourceID)})
	if err == nil && getOut != nil && getOut.LoggingConfiguration != nil && len(getOut.LoggingConfiguration.LogDestinationConfigs) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "logging already enabled"
		return base
	}
	if err != nil && !isWAFv2NotFound(err) {
		base.Status = fix.FixFailed
		base.Message = "get logging configuration: " + err.Error()
		return base
	}

	destinationARN, err := findWAFFirehoseDestinationARN(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "discover log destination: " + err.Error()
		return base
	}
	if destinationARN == "" {
		base.Status = fix.FixSkipped
		base.Message = "no Firehose delivery stream with prefix aws-waf-logs- found"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable WAFv2 logging", "would set destination " + destinationARN}
		return base
	}

	_, err = f.clients.WAFv2.PutLoggingConfiguration(fctx.Ctx, &wafv2.PutLoggingConfigurationInput{
		LoggingConfiguration: &wafv2types.LoggingConfiguration{
			ResourceArn:           aws.String(resourceID),
			LogDestinationConfigs: []string{destinationARN},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put logging configuration: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "enabled WAFv2 logging"
	base.Steps = []string{"configured destination " + destinationARN}
	return base
}

func applyWAFv2RuleGroupNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	scope, name, id, err := parseWAFv2ResourceARN(resourceID, "rulegroup")
	if err != nil {
		base.Status = fix.FixSkipped
		base.Message = "invalid rule group ARN: " + err.Error()
		return base
	}

	client := wafv2ClientForScope(f.clients, scope)
	getOut, err := client.GetRuleGroup(fctx.Ctx, &wafv2.GetRuleGroupInput{Id: aws.String(id), Name: aws.String(name), Scope: scope})
	if err != nil {
		if isWAFv2NotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "rule group not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get rule group: " + err.Error()
		return base
	}
	if getOut.RuleGroup == nil {
		base.Status = fix.FixSkipped
		base.Message = "rule group not found"
		return base
	}
	if len(getOut.RuleGroup.Rules) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "rule group already has rules"
		return base
	}
	if getOut.LockToken == nil {
		base.Status = fix.FixFailed
		base.Message = "missing lock token"
		return base
	}

	rules := append([]wafv2types.Rule{}, getOut.RuleGroup.Rules...)
	rules = append(rules, minimalWAFv2Rule(rules, "bptools-rg"))
	steps := []string{"append helper COUNT geo-match rule to WAFv2 rule group"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	_, err = client.UpdateRuleGroup(fctx.Ctx, &wafv2.UpdateRuleGroupInput{
		Id:                   aws.String(id),
		Name:                 aws.String(name),
		Scope:                scope,
		LockToken:            getOut.LockToken,
		VisibilityConfig:     getOut.RuleGroup.VisibilityConfig,
		Description:          getOut.RuleGroup.Description,
		CustomResponseBodies: getOut.RuleGroup.CustomResponseBodies,
		Rules:                rules,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update rule group: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "added helper rule to empty WAFv2 rule group"
	base.Steps = steps
	return base
}

func applyWAFv2WebACLNotEmpty(f *multiBatch04Fix, fctx fix.FixContext, resourceID string) fix.FixResult {
	base := newMultiBatch04Result(f, resourceID)
	scope, name, id, err := parseWAFv2ResourceARN(resourceID, "webacl")
	if err != nil {
		base.Status = fix.FixSkipped
		base.Message = "invalid web ACL ARN: " + err.Error()
		return base
	}

	client := wafv2ClientForScope(f.clients, scope)
	getOut, err := client.GetWebACL(fctx.Ctx, &wafv2.GetWebACLInput{Id: aws.String(id), Name: aws.String(name), Scope: scope})
	if err != nil {
		if isWAFv2NotFound(err) {
			base.Status = fix.FixSkipped
			base.Message = "web ACL not found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get web ACL: " + err.Error()
		return base
	}
	if getOut.WebACL == nil {
		base.Status = fix.FixSkipped
		base.Message = "web ACL not found"
		return base
	}
	if len(getOut.WebACL.Rules) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "web ACL already has rules"
		return base
	}
	if getOut.LockToken == nil {
		base.Status = fix.FixFailed
		base.Message = "missing lock token"
		return base
	}

	rules := append([]wafv2types.Rule{}, getOut.WebACL.Rules...)
	rules = append(rules, minimalWAFv2Rule(rules, "bptools-acl"))
	steps := []string{"append helper COUNT geo-match rule to WAFv2 web ACL"}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = steps
		return base
	}

	_, err = client.UpdateWebACL(fctx.Ctx, &wafv2.UpdateWebACLInput{
		Id:                           aws.String(id),
		Name:                         aws.String(name),
		Scope:                        scope,
		LockToken:                    getOut.LockToken,
		DefaultAction:                getOut.WebACL.DefaultAction,
		VisibilityConfig:             getOut.WebACL.VisibilityConfig,
		Description:                  getOut.WebACL.Description,
		Rules:                        rules,
		CustomResponseBodies:         getOut.WebACL.CustomResponseBodies,
		CaptchaConfig:                getOut.WebACL.CaptchaConfig,
		ChallengeConfig:              getOut.WebACL.ChallengeConfig,
		TokenDomains:                 getOut.WebACL.TokenDomains,
		AssociationConfig:            getOut.WebACL.AssociationConfig,
		ApplicationConfig:            getOut.WebACL.ApplicationConfig,
		DataProtectionConfig:         getOut.WebACL.DataProtectionConfig,
		OnSourceDDoSProtectionConfig: getOut.WebACL.OnSourceDDoSProtectionConfig,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update web ACL: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Message = "added helper rule to empty WAFv2 web ACL"
	base.Steps = steps
	return base
}

func newMultiBatch04Result(f *multiBatch04Fix, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		id = "<unknown>"
	}
	return fix.FixResult{CheckID: f.CheckID(), ResourceID: id, Impact: f.Impact(), Severity: f.Severity()}
}

func getWAFClassicChangeToken(fctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	out, err := clients.WAF.GetChangeToken(fctx.Ctx, &waf.GetChangeTokenInput{})
	if err != nil {
		return "", err
	}
	if out.ChangeToken == nil || strings.TrimSpace(*out.ChangeToken) == "" {
		return "", errors.New("empty change token")
	}
	return *out.ChangeToken, nil
}

func getWAFRegionalChangeToken(fctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	out, err := clients.WAFRegional.GetChangeToken(fctx.Ctx, &wafregional.GetChangeTokenInput{})
	if err != nil {
		return "", err
	}
	if out.ChangeToken == nil || strings.TrimSpace(*out.ChangeToken) == "" {
		return "", errors.New("empty change token")
	}
	return *out.ChangeToken, nil
}

func createWAFClassicRule(fctx fix.FixContext, clients *awsdata.Clients, name, metric string) (string, error) {
	token, err := getWAFClassicChangeToken(fctx, clients)
	if err != nil {
		return "", err
	}
	out, err := clients.WAF.CreateRule(fctx.Ctx, &waf.CreateRuleInput{
		ChangeToken: aws.String(token),
		Name:        aws.String(name),
		MetricName:  aws.String(metric),
	})
	if err != nil {
		return "", err
	}
	if out.Rule == nil || out.Rule.RuleId == nil || strings.TrimSpace(*out.Rule.RuleId) == "" {
		return "", errors.New("create rule returned empty rule ID")
	}
	return *out.Rule.RuleId, nil
}

func createWAFRegionalRule(fctx fix.FixContext, clients *awsdata.Clients, name, metric string) (string, error) {
	token, err := getWAFRegionalChangeToken(fctx, clients)
	if err != nil {
		return "", err
	}
	out, err := clients.WAFRegional.CreateRule(fctx.Ctx, &wafregional.CreateRuleInput{
		ChangeToken: aws.String(token),
		Name:        aws.String(name),
		MetricName:  aws.String(metric),
	})
	if err != nil {
		return "", err
	}
	if out.Rule == nil || out.Rule.RuleId == nil || strings.TrimSpace(*out.Rule.RuleId) == "" {
		return "", errors.New("create regional rule returned empty rule ID")
	}
	return *out.Rule.RuleId, nil
}

func createWAFClassicIPSetWithCIDR(fctx fix.FixContext, clients *awsdata.Clients, name string) (string, error) {
	token, err := getWAFClassicChangeToken(fctx, clients)
	if err != nil {
		return "", err
	}
	createOut, err := clients.WAF.CreateIPSet(fctx.Ctx, &waf.CreateIPSetInput{
		ChangeToken: aws.String(token),
		Name:        aws.String(name),
	})
	if err != nil {
		return "", err
	}
	if createOut.IPSet == nil || createOut.IPSet.IPSetId == nil || strings.TrimSpace(*createOut.IPSet.IPSetId) == "" {
		return "", errors.New("create IP set returned empty ID")
	}
	ipSetID := *createOut.IPSet.IPSetId

	token, err = getWAFClassicChangeToken(fctx, clients)
	if err != nil {
		return "", err
	}
	_, err = clients.WAF.UpdateIPSet(fctx.Ctx, &waf.UpdateIPSetInput{
		ChangeToken: aws.String(token),
		IPSetId:     aws.String(ipSetID),
		Updates: []waftypes.IPSetUpdate{{
			Action: waftypes.ChangeActionInsert,
			IPSetDescriptor: &waftypes.IPSetDescriptor{
				Type:  waftypes.IPSetDescriptorTypeIpv4,
				Value: aws.String("203.0.113.0/24"),
			},
		}},
	})
	if err != nil {
		return "", err
	}
	return ipSetID, nil
}

func createWAFRegionalIPSetWithCIDR(fctx fix.FixContext, clients *awsdata.Clients, name string) (string, error) {
	token, err := getWAFRegionalChangeToken(fctx, clients)
	if err != nil {
		return "", err
	}
	createOut, err := clients.WAFRegional.CreateIPSet(fctx.Ctx, &wafregional.CreateIPSetInput{
		ChangeToken: aws.String(token),
		Name:        aws.String(name),
	})
	if err != nil {
		return "", err
	}
	if createOut.IPSet == nil || createOut.IPSet.IPSetId == nil || strings.TrimSpace(*createOut.IPSet.IPSetId) == "" {
		return "", errors.New("create regional IP set returned empty ID")
	}
	ipSetID := *createOut.IPSet.IPSetId

	token, err = getWAFRegionalChangeToken(fctx, clients)
	if err != nil {
		return "", err
	}
	_, err = clients.WAFRegional.UpdateIPSet(fctx.Ctx, &wafregional.UpdateIPSetInput{
		ChangeToken: aws.String(token),
		IPSetId:     aws.String(ipSetID),
		Updates: []wafregionaltypes.IPSetUpdate{{
			Action: wafregionaltypes.ChangeActionInsert,
			IPSetDescriptor: &wafregionaltypes.IPSetDescriptor{
				Type:  wafregionaltypes.IPSetDescriptorTypeIpv4,
				Value: aws.String("203.0.113.0/24"),
			},
		}},
	})
	if err != nil {
		return "", err
	}
	return ipSetID, nil
}

func nextWAFClassicPriority(rules []waftypes.ActivatedRule) int32 {
	var max int32 = -1
	for _, r := range rules {
		if r.Priority != nil && *r.Priority > max {
			max = *r.Priority
		}
	}
	return max + 1
}

func nextWAFRegionalPriority(rules []wafregionaltypes.ActivatedRule) int32 {
	var max int32 = -1
	for _, r := range rules {
		if r.Priority != nil && *r.Priority > max {
			max = *r.Priority
		}
	}
	return max + 1
}

func findWAFFirehoseDestinationARN(fctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	var startName *string
	for {
		out, err := clients.Firehose.ListDeliveryStreams(fctx.Ctx, &firehose.ListDeliveryStreamsInput{
			ExclusiveStartDeliveryStreamName: startName,
			Limit:                            aws.Int32(100),
		})
		if err != nil {
			return "", err
		}
		for _, name := range out.DeliveryStreamNames {
			if !strings.HasPrefix(name, "aws-waf-logs-") {
				continue
			}
			desc, err := clients.Firehose.DescribeDeliveryStream(fctx.Ctx, &firehose.DescribeDeliveryStreamInput{
				DeliveryStreamName: aws.String(name),
			})
			if err != nil {
				var nf *firehosetypes.ResourceNotFoundException
				if errors.As(err, &nf) {
					continue
				}
				return "", err
			}
			if desc.DeliveryStreamDescription != nil && desc.DeliveryStreamDescription.DeliveryStreamARN != nil {
				return *desc.DeliveryStreamDescription.DeliveryStreamARN, nil
			}
		}
		if !aws.ToBool(out.HasMoreDeliveryStreams) || len(out.DeliveryStreamNames) == 0 {
			break
		}
		startName = aws.String(out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1])
	}
	return "", nil
}

func parseWAFv2ResourceARN(arn, expectedKind string) (wafv2types.Scope, string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) < 6 {
		return "", "", "", errors.New("malformed ARN")
	}
	segments := strings.Split(parts[5], "/")
	if len(segments) < 4 {
		return "", "", "", errors.New("malformed WAFv2 resource segment")
	}

	kind := strings.ToLower(segments[1])
	if kind != expectedKind {
		return "", "", "", fmt.Errorf("expected %s ARN, got %s", expectedKind, kind)
	}

	var scope wafv2types.Scope
	switch strings.ToLower(segments[0]) {
	case "regional":
		scope = wafv2types.ScopeRegional
	case "global":
		scope = wafv2types.ScopeCloudfront
	default:
		return "", "", "", fmt.Errorf("unsupported scope segment %q", segments[0])
	}

	name := strings.TrimSpace(segments[2])
	id := strings.TrimSpace(segments[3])
	if name == "" || id == "" {
		return "", "", "", errors.New("missing resource name or ID")
	}
	return scope, name, id, nil
}

func wafv2ClientForScope(clients *awsdata.Clients, scope wafv2types.Scope) *wafv2.Client {
	if scope == wafv2types.ScopeCloudfront {
		opts := clients.WAFv2.Options()
		opts.Region = "us-east-1"
		return wafv2.New(opts)
	}
	return clients.WAFv2
}

func minimalWAFv2Rule(existing []wafv2types.Rule, prefix string) wafv2types.Rule {
	priority := int32(0)
	for _, r := range existing {
		if r.Priority >= priority {
			priority = r.Priority + 1
		}
	}
	name := uniqueWAFv2RuleName(existing, prefix)
	metric := strings.ReplaceAll(name, "-", "_")

	return wafv2types.Rule{
		Name:     aws.String(name),
		Priority: priority,
		Statement: &wafv2types.Statement{
			GeoMatchStatement: &wafv2types.GeoMatchStatement{
				CountryCodes: []wafv2types.CountryCode{wafv2types.CountryCode("US")},
			},
		},
		Action: &wafv2types.RuleAction{Count: &wafv2types.CountAction{}},
		VisibilityConfig: &wafv2types.VisibilityConfig{
			CloudWatchMetricsEnabled: true,
			SampledRequestsEnabled:   true,
			MetricName:               aws.String(metric),
		},
	}
}

func uniqueWAFv2RuleName(existing []wafv2types.Rule, prefix string) string {
	base := fmt.Sprintf("%s-%d", sanitizeAlphaNumHyphen(prefix), time.Now().UnixNano())
	cand := base
	for i := 0; i < 10; i++ {
		conflict := false
		for _, r := range existing {
			if r.Name != nil && *r.Name == cand {
				conflict = true
				break
			}
		}
		if !conflict {
			return truncate(cand, 128)
		}
		cand = truncate(base+"-"+strconv.Itoa(i+1), 128)
	}
	return truncate(base+"-x", 128)
}

func multiBatch04Name(prefix string) string {
	clean := sanitizeAlphaNum(prefix)
	if clean == "" {
		clean = "BPTWAF"
	}
	return truncate(clean+strconv.FormatInt(time.Now().UnixNano(), 10), 128)
}

func sanitizeAlphaNum(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeAlphaNumHyphen(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

func isWAFClassicNotFound(err error) bool {
	var nf *waftypes.WAFNonexistentItemException
	return errors.As(err, &nf)
}

func isWAFRegionalNotFound(err error) bool {
	var nf *wafregionaltypes.WAFNonexistentItemException
	return errors.As(err, &nf)
}

func isWAFv2NotFound(err error) bool {
	var nf *wafv2types.WAFNonexistentItemException
	return errors.As(err, &nf)
}
