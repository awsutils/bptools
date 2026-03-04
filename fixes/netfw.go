package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	netfwtypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
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

// ── netfw-logging-enabled ─────────────────────────────────────────────────────

type netfwLoggingFix struct{ clients *awsdata.Clients }

func (f *netfwLoggingFix) CheckID() string    { return "netfw-logging-enabled" }
func (f *netfwLoggingFix) Description() string { return "Enable alert logging on Network Firewall" }
func (f *netfwLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *netfwLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *netfwLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	logOut, err := f.clients.NetworkFirewall.DescribeLoggingConfiguration(fctx.Ctx, &networkfirewall.DescribeLoggingConfigurationInput{
		FirewallArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe logging configuration: " + err.Error()
		return base
	}
	if logOut.LoggingConfiguration != nil && len(logOut.LoggingConfiguration.LogDestinationConfigs) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "logging already enabled"
		return base
	}

	// Extract firewall name from ARN: arn:aws:network-firewall:region:account:firewall/name
	firewallName := resourceID
	if idx := strings.LastIndex(resourceID, "/"); idx >= 0 {
		firewallName = resourceID[idx+1:]
	}

	region := f.clients.CloudWatchLogs.Options().Region
	logGroupName := fmt.Sprintf("/aws/network-firewall/%s/alerts", firewallName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable ALERT logging on Network Firewall %s → CloudWatch Logs", firewallName),
		}
		return base
	}

	_, cgErr := f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	_, err = f.clients.NetworkFirewall.UpdateLoggingConfiguration(fctx.Ctx, &networkfirewall.UpdateLoggingConfigurationInput{
		FirewallArn: aws.String(resourceID),
		LoggingConfiguration: &netfwtypes.LoggingConfiguration{
			LogDestinationConfigs: []netfwtypes.LogDestinationConfig{
				{
					LogType:             netfwtypes.LogTypeAlert,
					LogDestinationType:  netfwtypes.LogDestinationTypeCloudwatchLogs,
					LogDestination:      map[string]string{"logGroup": logGroupName},
				},
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update logging configuration: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("created log group %s in %s", logGroupName, region),
		fmt.Sprintf("enabled ALERT logging on Network Firewall %s → CloudWatch Logs", firewallName),
	}
	base.Status = fix.FixApplied
	return base
}
