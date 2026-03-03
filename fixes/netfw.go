package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
)

// ── netfw-deletion-protection-enabled ────────────────────────────────────────

type netfwDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *netfwDeletionProtectionFix) CheckID() string {
	return "netfw-deletion-protection-enabled"
}
func (f *netfwDeletionProtectionFix) Description() string {
	return "Enable deletion protection on Network Firewall"
}
func (f *netfwDeletionProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *netfwDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *netfwDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.NetworkFirewall.DescribeFirewall(fctx.Ctx, &networkfirewall.DescribeFirewallInput{
		FirewallArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Network Firewall: " + err.Error()
		return base
	}
	if out.Firewall != nil && out.Firewall.DeleteProtection {
		base.Status = fix.FixSkipped
		base.Message = "deletion protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable deletion protection on Network Firewall " + resourceID}
		return base
	}

	_, err = f.clients.NetworkFirewall.UpdateFirewallDeleteProtection(fctx.Ctx, &networkfirewall.UpdateFirewallDeleteProtectionInput{
		FirewallArn:      aws.String(resourceID),
		DeleteProtection: true,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update Network Firewall delete protection: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled deletion protection on Network Firewall " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── netfw-subnet-change-protection-enabled ───────────────────────────────────

type netfwSubnetChangeProtectionFix struct{ clients *awsdata.Clients }

func (f *netfwSubnetChangeProtectionFix) CheckID() string {
	return "netfw-subnet-change-protection-enabled"
}
func (f *netfwSubnetChangeProtectionFix) Description() string {
	return "Enable subnet change protection on Network Firewall"
}
func (f *netfwSubnetChangeProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *netfwSubnetChangeProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *netfwSubnetChangeProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.NetworkFirewall.DescribeFirewall(fctx.Ctx, &networkfirewall.DescribeFirewallInput{
		FirewallArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Network Firewall: " + err.Error()
		return base
	}
	if out.Firewall != nil && out.Firewall.SubnetChangeProtection {
		base.Status = fix.FixSkipped
		base.Message = "subnet change protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable subnet change protection on Network Firewall " + resourceID}
		return base
	}

	_, err = f.clients.NetworkFirewall.UpdateSubnetChangeProtection(fctx.Ctx, &networkfirewall.UpdateSubnetChangeProtectionInput{
		FirewallArn:            aws.String(resourceID),
		SubnetChangeProtection: true,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update subnet change protection: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled subnet change protection on Network Firewall " + resourceID}
	base.Status = fix.FixApplied
	return base
}
