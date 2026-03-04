package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ── ebs-snapshot-block-public-access ─────────────────────────────────────────

type ebsSnapshotBlockPublicAccessFix struct{ clients *awsdata.Clients }

func (f *ebsSnapshotBlockPublicAccessFix) CheckID() string {
	return "ebs-snapshot-block-public-access"
}
func (f *ebsSnapshotBlockPublicAccessFix) Description() string {
	return "Block public access to EBS snapshots for this account/region"
}
func (f *ebsSnapshotBlockPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebsSnapshotBlockPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ebsSnapshotBlockPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	st, err := f.clients.EC2.GetSnapshotBlockPublicAccessState(fctx.Ctx, &ec2.GetSnapshotBlockPublicAccessStateInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get snapshot block public access state: " + err.Error()
		return base
	}
	if st.State != "" && st.State != ec2types.SnapshotBlockPublicAccessStateUnblocked {
		base.Status = fix.FixSkipped
		base.Message = "snapshot block public access already enabled (state: " + string(st.State) + ")"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set EBS snapshot block-public-access to block-all-sharing"}
		return base
	}

	_, err = f.clients.EC2.EnableSnapshotBlockPublicAccess(fctx.Ctx, &ec2.EnableSnapshotBlockPublicAccessInput{
		State: ec2types.SnapshotBlockPublicAccessStateBlockAllSharing,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable snapshot block public access: " + err.Error()
		return base
	}
	base.Steps = []string{"set EBS snapshot block-public-access to block-all-sharing"}
	base.Status = fix.FixApplied
	return base
}

type ec2EBSEncryptionFix struct{ clients *awsdata.Clients }

func (f *ec2EBSEncryptionFix) CheckID() string          { return "ec2-ebs-encryption-by-default" }
func (f *ec2EBSEncryptionFix) Description() string      { return "Enable account-level EBS encryption by default" }
func (f *ec2EBSEncryptionFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *ec2EBSEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ec2EBSEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.CheckID(),
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}

	// Idempotency: re-check current state.
	st, err := f.clients.EC2.GetEbsEncryptionByDefault(fctx.Ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get EBS encryption by default: " + err.Error()
		return base
	}
	if st.EbsEncryptionByDefault != nil && *st.EbsEncryptionByDefault {
		base.Status = fix.FixSkipped
		base.Message = "EBS encryption by default already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable EBS encryption by default for this account/region"}
		return base
	}

	_, err = f.clients.EC2.EnableEbsEncryptionByDefault(fctx.Ctx, &ec2.EnableEbsEncryptionByDefaultInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable EBS encryption by default: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled EBS encryption by default for this account/region"}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-instance-detailed-monitoring-enabled ─────────────────────────────────

type ec2DetailedMonitoringFix struct{ clients *awsdata.Clients }

func (f *ec2DetailedMonitoringFix) CheckID() string          { return "ec2-instance-detailed-monitoring-enabled" }
func (f *ec2DetailedMonitoringFix) Description() string      { return "Enable detailed CloudWatch monitoring on EC2 instance" }
func (f *ec2DetailedMonitoringFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *ec2DetailedMonitoringFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ec2DetailedMonitoringFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EC2.DescribeInstances(fctx.Ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe instance: " + err.Error()
		return base
	}
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			if i.Monitoring != nil && i.Monitoring.State == ec2types.MonitoringStateEnabled {
				base.Status = fix.FixSkipped
				base.Message = "detailed monitoring already enabled"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable detailed monitoring on instance %s", resourceID)}
		return base
	}

	_, err = f.clients.EC2.MonitorInstances(fctx.Ctx, &ec2.MonitorInstancesInput{
		InstanceIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "monitor instances: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled detailed monitoring on instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-imdsv2-check ──────────────────────────────────────────────────────────

type ec2IMDSv2Fix struct{ clients *awsdata.Clients }

func (f *ec2IMDSv2Fix) CheckID() string          { return "ec2-imdsv2-check" }
func (f *ec2IMDSv2Fix) Description() string      { return "Require IMDSv2 on EC2 instance" }
func (f *ec2IMDSv2Fix) Impact() fix.ImpactType   { return fix.ImpactDegradation }
func (f *ec2IMDSv2Fix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ec2IMDSv2Fix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EC2.DescribeInstances(fctx.Ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe instance: " + err.Error()
		return base
	}
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			if i.MetadataOptions != nil && i.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired {
				base.Status = fix.FixSkipped
				base.Message = "IMDSv2 already required"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set HttpTokens=required (IMDSv2) on instance %s", resourceID)}
		return base
	}

	_, err = f.clients.EC2.ModifyInstanceMetadataOptions(fctx.Ctx, &ec2.ModifyInstanceMetadataOptionsInput{
		InstanceId: aws.String(resourceID),
		HttpTokens: ec2types.HttpTokensStateRequired,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify instance metadata options: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set HttpTokens=required (IMDSv2) on instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-transit-gateway-auto-vpc-attach-disabled ─────────────────────────────

type ec2TransitGatewayAutoAttachFix struct{ clients *awsdata.Clients }

func (f *ec2TransitGatewayAutoAttachFix) CheckID() string {
	return "ec2-transit-gateway-auto-vpc-attach-disabled"
}
func (f *ec2TransitGatewayAutoAttachFix) Description() string {
	return "Disable AutoAcceptSharedAttachments on Transit Gateway"
}
func (f *ec2TransitGatewayAutoAttachFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2TransitGatewayAutoAttachFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ec2TransitGatewayAutoAttachFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EC2.DescribeTransitGateways(fctx.Ctx, &ec2.DescribeTransitGatewaysInput{
		TransitGatewayIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe transit gateways: " + err.Error()
		return base
	}
	if len(out.TransitGateways) > 0 {
		opts := out.TransitGateways[0].Options
		if opts != nil && opts.AutoAcceptSharedAttachments == ec2types.AutoAcceptSharedAttachmentsValueDisable {
			base.Status = fix.FixSkipped
			base.Message = "auto-accept shared attachments already disabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable AutoAcceptSharedAttachments on transit gateway %s", resourceID)}
		return base
	}

	_, err = f.clients.EC2.ModifyTransitGateway(fctx.Ctx, &ec2.ModifyTransitGatewayInput{
		TransitGatewayId: aws.String(resourceID),
		Options: &ec2types.ModifyTransitGatewayOptions{
			AutoAcceptSharedAttachments: ec2types.AutoAcceptSharedAttachmentsValueDisable,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify transit gateway: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("disabled AutoAcceptSharedAttachments on transit gateway %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-token-hop-limit-check ─────────────────────────────────────────────────

type ec2HopLimitFix struct{ clients *awsdata.Clients }

func (f *ec2HopLimitFix) CheckID() string          { return "ec2-token-hop-limit-check" }
func (f *ec2HopLimitFix) Description() string      { return "Set IMDSv2 hop limit to 1 on EC2 instance" }
func (f *ec2HopLimitFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2HopLimitFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ec2HopLimitFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EC2.DescribeInstances(fctx.Ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe instance: " + err.Error()
		return base
	}
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			if i.MetadataOptions != nil && i.MetadataOptions.HttpPutResponseHopLimit != nil && *i.MetadataOptions.HttpPutResponseHopLimit <= 1 {
				base.Status = fix.FixSkipped
				base.Message = fmt.Sprintf("hop limit already set to %d", *i.MetadataOptions.HttpPutResponseHopLimit)
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set HttpPutResponseHopLimit=1 on instance %s", resourceID)}
		return base
	}

	_, err = f.clients.EC2.ModifyInstanceMetadataOptions(fctx.Ctx, &ec2.ModifyInstanceMetadataOptionsInput{
		InstanceId:              aws.String(resourceID),
		HttpPutResponseHopLimit: aws.Int32(1),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify instance metadata options: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set HttpPutResponseHopLimit=1 on instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-enis-source-destination-check-enabled ─────────────────────────────────

type ec2ENISourceDestCheckFix struct{ clients *awsdata.Clients }

func (f *ec2ENISourceDestCheckFix) CheckID() string {
	return "ec2-enis-source-destination-check-enabled"
}
func (f *ec2ENISourceDestCheckFix) Description() string {
	return "Enable source/destination check on EC2 network interface"
}
func (f *ec2ENISourceDestCheckFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2ENISourceDestCheckFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ec2ENISourceDestCheckFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EC2.DescribeNetworkInterfaces(fctx.Ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe network interface: " + err.Error()
		return base
	}
	if len(out.NetworkInterfaces) == 0 {
		base.Status = fix.FixFailed
		base.Message = "network interface not found"
		return base
	}
	eni := out.NetworkInterfaces[0]
	if eni.SourceDestCheck != nil && *eni.SourceDestCheck {
		base.Status = fix.FixSkipped
		base.Message = "source/destination check already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable source/dest check on ENI %s", resourceID)}
		return base
	}

	_, err = f.clients.EC2.ModifyNetworkInterfaceAttribute(fctx.Ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(resourceID),
		SourceDestCheck:    &ec2types.AttributeBooleanValue{Value: aws.Bool(true)},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify network interface attribute: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled source/destination check on ENI %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-launch-template-imdsv2-check ─────────────────────────────────────────

type ec2LaunchTemplateIMDSv2Fix struct{ clients *awsdata.Clients }

func (f *ec2LaunchTemplateIMDSv2Fix) CheckID() string { return "ec2-launch-template-imdsv2-check" }
func (f *ec2LaunchTemplateIMDSv2Fix) Description() string {
	return "Enforce IMDSv2 on EC2 launch template default version"
}
func (f *ec2LaunchTemplateIMDSv2Fix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2LaunchTemplateIMDSv2Fix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ec2LaunchTemplateIMDSv2Fix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Look up launch template by name
	ltOut, err := f.clients.EC2.DescribeLaunchTemplates(fctx.Ctx, &ec2.DescribeLaunchTemplatesInput{
		LaunchTemplateNames: []string{resourceID},
	})
	if err != nil || len(ltOut.LaunchTemplates) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "describe launch template: " + err.Error()
		} else {
			base.Message = "launch template not found"
		}
		return base
	}
	lt := ltOut.LaunchTemplates[0]

	// Get the default version data
	verOut, err := f.clients.EC2.DescribeLaunchTemplateVersions(fctx.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		Versions:         []string{"$Default"},
	})
	if err != nil || len(verOut.LaunchTemplateVersions) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "describe launch template versions: " + err.Error()
		} else {
			base.Message = "no launch template versions"
		}
		return base
	}
	data := verOut.LaunchTemplateVersions[0].LaunchTemplateData
	if data != nil && data.MetadataOptions != nil && data.MetadataOptions.HttpTokens == ec2types.LaunchTemplateHttpTokensStateRequired {
		base.Status = fix.FixSkipped
		base.Message = "IMDSv2 already required"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would create new LT version with IMDSv2 required on %s", resourceID)}
		return base
	}

	// Create new version with IMDSv2 required, sourced from current default
	newVer, err := f.clients.EC2.CreateLaunchTemplateVersion(fctx.Ctx, &ec2.CreateLaunchTemplateVersionInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		SourceVersion:    aws.String("$Default"),
		LaunchTemplateData: &ec2types.RequestLaunchTemplateData{
			MetadataOptions: &ec2types.LaunchTemplateInstanceMetadataOptionsRequest{
				HttpTokens: ec2types.LaunchTemplateHttpTokensStateRequired,
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create launch template version: " + err.Error()
		return base
	}

	// Set new version as default
	newVersionNum := fmt.Sprintf("%d", *newVer.LaunchTemplateVersion.VersionNumber)
	_, err = f.clients.EC2.ModifyLaunchTemplate(fctx.Ctx, &ec2.ModifyLaunchTemplateInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		DefaultVersion:   aws.String(newVersionNum),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set default launch template version: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("created LT version %s with IMDSv2 required and set as default on %s", newVersionNum, resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-client-vpn-connection-log-enabled ────────────────────────────────────

type ec2ClientVPNLoggingFix struct{ clients *awsdata.Clients }

func (f *ec2ClientVPNLoggingFix) CheckID() string { return "ec2-client-vpn-connection-log-enabled" }
func (f *ec2ClientVPNLoggingFix) Description() string {
	return "Enable connection logging on Client VPN endpoint"
}
func (f *ec2ClientVPNLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2ClientVPNLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ec2ClientVPNLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EC2.DescribeClientVpnEndpoints(fctx.Ctx, &ec2.DescribeClientVpnEndpointsInput{
		ClientVpnEndpointIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe client VPN endpoint: " + err.Error()
		return base
	}
	if len(out.ClientVpnEndpoints) == 0 {
		base.Status = fix.FixFailed
		base.Message = "client VPN endpoint not found"
		return base
	}
	ep := out.ClientVpnEndpoints[0]
	if ep.ConnectionLogOptions != nil && ep.ConnectionLogOptions.Enabled != nil && *ep.ConnectionLogOptions.Enabled {
		base.Status = fix.FixSkipped
		base.Message = "connection logging already enabled"
		return base
	}

	logGroupName := "/aws/client-vpn/" + resourceID

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable connection logging on Client VPN endpoint %s", resourceID),
		}
		return base
	}

	// Create log group (ignore AlreadyExistsException)
	_, cgErr := f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	_, err = f.clients.EC2.ModifyClientVpnEndpoint(fctx.Ctx, &ec2.ModifyClientVpnEndpointInput{
		ClientVpnEndpointId: aws.String(resourceID),
		ConnectionLogOptions: &ec2types.ConnectionLogOptions{
			Enabled:            aws.Bool(true),
			CloudwatchLogGroup: aws.String(logGroupName),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify client VPN endpoint: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("created log group %s", logGroupName),
		fmt.Sprintf("enabled connection logging on Client VPN endpoint %s", resourceID),
	}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-vpn-connection-logging-enabled ───────────────────────────────────────

type ec2VPNConnectionLoggingFix struct{ clients *awsdata.Clients }

func (f *ec2VPNConnectionLoggingFix) CheckID() string {
	return "ec2-vpn-connection-logging-enabled"
}
func (f *ec2VPNConnectionLoggingFix) Description() string {
	return "Enable CloudWatch logging for Site-to-Site VPN connection tunnels"
}
func (f *ec2VPNConnectionLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2VPNConnectionLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ec2VPNConnectionLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EC2.DescribeVpnConnections(fctx.Ctx, &ec2.DescribeVpnConnectionsInput{
		VpnConnectionIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe VPN connections: " + err.Error()
		return base
	}
	if len(out.VpnConnections) == 0 {
		base.Status = fix.FixFailed
		base.Message = "VPN connection not found: " + resourceID
		return base
	}
	conn := out.VpnConnections[0]

	// Collect tunnels that need logging enabled
	type tunnelInfo struct {
		outsideIP string
		hasLog    bool
	}
	var tunnels []tunnelInfo
	if conn.Options != nil {
		for _, t := range conn.Options.TunnelOptions {
			hasLog := t.LogOptions != nil && t.LogOptions.CloudWatchLogOptions != nil &&
				t.LogOptions.CloudWatchLogOptions.LogEnabled != nil && *t.LogOptions.CloudWatchLogOptions.LogEnabled
			ip := aws.ToString(t.OutsideIpAddress)
			if ip != "" {
				tunnels = append(tunnels, tunnelInfo{outsideIP: ip, hasLog: hasLog})
			}
		}
	}

	// Check if all tunnels already have logging
	allLogged := len(tunnels) > 0
	for _, t := range tunnels {
		if !t.hasLog {
			allLogged = false
			break
		}
	}
	if allLogged {
		base.Status = fix.FixSkipped
		base.Message = "VPN tunnel logging already enabled on all tunnels"
		return base
	}

	region := f.clients.CloudWatchLogs.Options().Region
	callerOut, err := f.clients.STS.GetCallerIdentity(fctx.Ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get caller identity: " + err.Error()
		return base
	}
	account := aws.ToString(callerOut.Account)

	logGroupName := "/aws/vpn/" + resourceID
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", region, account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable CloudWatch logging on VPN connection %s tunnels", resourceID),
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

	var steps []string
	steps = append(steps, fmt.Sprintf("ensured log group %s exists", logGroupName))

	for _, t := range tunnels {
		if t.hasLog {
			continue
		}
		_, modErr := f.clients.EC2.ModifyVpnTunnelOptions(fctx.Ctx, &ec2.ModifyVpnTunnelOptionsInput{
			VpnConnectionId:          aws.String(resourceID),
			VpnTunnelOutsideIpAddress: aws.String(t.outsideIP),
			TunnelOptions: &ec2types.ModifyVpnTunnelOptionsSpecification{
				LogOptions: &ec2types.VpnTunnelLogOptionsSpecification{
					CloudWatchLogOptions: &ec2types.CloudWatchLogOptionsSpecification{
						LogEnabled:  aws.Bool(true),
						LogGroupArn: aws.String(logGroupArn),
					},
				},
			},
		})
		if modErr != nil {
			base.Status = fix.FixFailed
			base.Message = fmt.Sprintf("modify VPN tunnel %s: %s", t.outsideIP, modErr.Error())
			return base
		}
		steps = append(steps, fmt.Sprintf("enabled logging on VPN tunnel %s", t.outsideIP))
	}

	base.Steps = steps
	base.Status = fix.FixApplied
	return base
}

// ── ec2-launch-template-public-ip-disabled ───────────────────────────────────

type ec2LaunchTemplatePublicIPFix struct{ clients *awsdata.Clients }

func (f *ec2LaunchTemplatePublicIPFix) CheckID() string {
	return "ec2-launch-template-public-ip-disabled"
}
func (f *ec2LaunchTemplatePublicIPFix) Description() string {
	return "Disable AssociatePublicIpAddress on all network interfaces in EC2 launch template default version"
}
func (f *ec2LaunchTemplatePublicIPFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2LaunchTemplatePublicIPFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ec2LaunchTemplatePublicIPFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	ltOut, err := f.clients.EC2.DescribeLaunchTemplates(fctx.Ctx, &ec2.DescribeLaunchTemplatesInput{
		LaunchTemplateNames: []string{resourceID},
	})
	if err != nil || len(ltOut.LaunchTemplates) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "describe launch template: " + err.Error()
		} else {
			base.Message = "launch template not found"
		}
		return base
	}
	lt := ltOut.LaunchTemplates[0]

	verOut, err := f.clients.EC2.DescribeLaunchTemplateVersions(fctx.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		Versions:         []string{"$Default"},
	})
	if err != nil || len(verOut.LaunchTemplateVersions) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "describe launch template versions: " + err.Error()
		} else {
			base.Message = "no launch template versions"
		}
		return base
	}
	data := verOut.LaunchTemplateVersions[0].LaunchTemplateData

	hasPublicIP := false
	if data != nil {
		for _, ni := range data.NetworkInterfaces {
			if ni.AssociatePublicIpAddress != nil && *ni.AssociatePublicIpAddress {
				hasPublicIP = true
				break
			}
		}
	}
	if !hasPublicIP {
		base.Status = fix.FixSkipped
		base.Message = "no network interfaces with public IP enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would create new LT version with AssociatePublicIpAddress=false on %s", resourceID)}
		return base
	}

	var updatedNIs []ec2types.LaunchTemplateInstanceNetworkInterfaceSpecificationRequest
	for _, ni := range data.NetworkInterfaces {
		req := ltNIToRequest(ni)
		req.AssociatePublicIpAddress = aws.Bool(false)
		updatedNIs = append(updatedNIs, req)
	}

	newVer, err := f.clients.EC2.CreateLaunchTemplateVersion(fctx.Ctx, &ec2.CreateLaunchTemplateVersionInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		SourceVersion:    aws.String("$Default"),
		LaunchTemplateData: &ec2types.RequestLaunchTemplateData{
			NetworkInterfaces: updatedNIs,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create launch template version: " + err.Error()
		return base
	}

	newVersionNum := fmt.Sprintf("%d", *newVer.LaunchTemplateVersion.VersionNumber)
	_, err = f.clients.EC2.ModifyLaunchTemplate(fctx.Ctx, &ec2.ModifyLaunchTemplateInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		DefaultVersion:   aws.String(newVersionNum),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set default launch template version: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("created LT version %s with public IP disabled and set as default on %s", newVersionNum, resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ltNIToRequest converts a describe-response NI spec to a create/update request spec.
func ltNIToRequest(ni ec2types.LaunchTemplateInstanceNetworkInterfaceSpecification) ec2types.LaunchTemplateInstanceNetworkInterfaceSpecificationRequest {
	req := ec2types.LaunchTemplateInstanceNetworkInterfaceSpecificationRequest{
		AssociateCarrierIpAddress:      ni.AssociateCarrierIpAddress,
		AssociatePublicIpAddress:       ni.AssociatePublicIpAddress,
		DeleteOnTermination:            ni.DeleteOnTermination,
		Description:                    ni.Description,
		DeviceIndex:                    ni.DeviceIndex,
		Groups:                         ni.Groups,
		InterfaceType:                  ni.InterfaceType,
		Ipv4PrefixCount:                ni.Ipv4PrefixCount,
		Ipv6AddressCount:               ni.Ipv6AddressCount,
		Ipv6PrefixCount:                ni.Ipv6PrefixCount,
		NetworkCardIndex:               ni.NetworkCardIndex,
		NetworkInterfaceId:             ni.NetworkInterfaceId,
		PrimaryIpv6:                    ni.PrimaryIpv6,
		PrivateIpAddress:               ni.PrivateIpAddress,
		PrivateIpAddresses:             ni.PrivateIpAddresses,
		SecondaryPrivateIpAddressCount: ni.SecondaryPrivateIpAddressCount,
		SubnetId:                       ni.SubnetId,
	}
	for _, p := range ni.Ipv4Prefixes {
		req.Ipv4Prefixes = append(req.Ipv4Prefixes, ec2types.Ipv4PrefixSpecificationRequest{Ipv4Prefix: p.Ipv4Prefix})
	}
	for _, p := range ni.Ipv6Prefixes {
		req.Ipv6Prefixes = append(req.Ipv6Prefixes, ec2types.Ipv6PrefixSpecificationRequest{Ipv6Prefix: p.Ipv6Prefix})
	}
	for _, a := range ni.Ipv6Addresses {
		req.Ipv6Addresses = append(req.Ipv6Addresses, ec2types.InstanceIpv6AddressRequest{Ipv6Address: a.Ipv6Address})
	}
	if ni.ConnectionTrackingSpecification != nil {
		req.ConnectionTrackingSpecification = &ec2types.ConnectionTrackingSpecificationRequest{
			TcpEstablishedTimeout: ni.ConnectionTrackingSpecification.TcpEstablishedTimeout,
			UdpStreamTimeout:      ni.ConnectionTrackingSpecification.UdpStreamTimeout,
			UdpTimeout:            ni.ConnectionTrackingSpecification.UdpTimeout,
		}
	}
	if ni.EnaSrdSpecification != nil {
		enaSrd := &ec2types.EnaSrdSpecificationRequest{
			EnaSrdEnabled: ni.EnaSrdSpecification.EnaSrdEnabled,
		}
		if ni.EnaSrdSpecification.EnaSrdUdpSpecification != nil {
			enaSrd.EnaSrdUdpSpecification = &ec2types.EnaSrdUdpSpecificationRequest{
				EnaSrdUdpEnabled: ni.EnaSrdSpecification.EnaSrdUdpSpecification.EnaSrdUdpEnabled,
			}
		}
		req.EnaSrdSpecification = enaSrd
	}
	return req
}

// ── ebs-snapshot-public-restorable-check ─────────────────────────────────────

type ebsSnapshotPublicFix struct{ clients *awsdata.Clients }

func (f *ebsSnapshotPublicFix) CheckID() string {
	return "ebs-snapshot-public-restorable-check"
}
func (f *ebsSnapshotPublicFix) Description() string {
	return "Remove public create-volume permission from EBS snapshot"
}
func (f *ebsSnapshotPublicFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebsSnapshotPublicFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ebsSnapshotPublicFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attr, err := f.clients.EC2.DescribeSnapshotAttribute(fctx.Ctx, &ec2.DescribeSnapshotAttributeInput{
		SnapshotId: aws.String(resourceID),
		Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe snapshot attribute: " + err.Error()
		return base
	}

	public := false
	for _, p := range attr.CreateVolumePermissions {
		if p.Group == ec2types.PermissionGroupAll {
			public = true
			break
		}
	}
	if !public {
		base.Status = fix.FixSkipped
		base.Message = "snapshot is already private"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would remove public createVolumePermission from snapshot %s", resourceID)}
		return base
	}

	_, err = f.clients.EC2.ModifySnapshotAttribute(fctx.Ctx, &ec2.ModifySnapshotAttributeInput{
		SnapshotId: aws.String(resourceID),
		Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
		CreateVolumePermission: &ec2types.CreateVolumePermissionModifications{
			Remove: []ec2types.CreateVolumePermission{
				{Group: ec2types.PermissionGroupAll},
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify snapshot attribute: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed public createVolumePermission from snapshot %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ec2-launch-templates-ebs-volume-encrypted ────────────────────────────────

type ec2LaunchTemplateEBSEncryptionFix struct{ clients *awsdata.Clients }

func (f *ec2LaunchTemplateEBSEncryptionFix) CheckID() string {
	return "ec2-launch-templates-ebs-volume-encrypted"
}
func (f *ec2LaunchTemplateEBSEncryptionFix) Description() string {
	return "Enable EBS volume encryption in EC2 launch template default version"
}
func (f *ec2LaunchTemplateEBSEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2LaunchTemplateEBSEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ec2LaunchTemplateEBSEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	ltOut, err := f.clients.EC2.DescribeLaunchTemplates(fctx.Ctx, &ec2.DescribeLaunchTemplatesInput{
		LaunchTemplateNames: []string{resourceID},
	})
	if err != nil || len(ltOut.LaunchTemplates) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "describe launch template: " + err.Error()
		} else {
			base.Message = "launch template not found"
		}
		return base
	}
	lt := ltOut.LaunchTemplates[0]

	verOut, err := f.clients.EC2.DescribeLaunchTemplateVersions(fctx.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		Versions:         []string{"$Default"},
	})
	if err != nil || len(verOut.LaunchTemplateVersions) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "describe launch template versions: " + err.Error()
		} else {
			base.Message = "no launch template versions"
		}
		return base
	}
	data := verOut.LaunchTemplateVersions[0].LaunchTemplateData

	hasUnencrypted := false
	if data != nil {
		for _, bd := range data.BlockDeviceMappings {
			if bd.Ebs != nil && (bd.Ebs.Encrypted == nil || !*bd.Ebs.Encrypted) {
				hasUnencrypted = true
				break
			}
		}
	}
	if !hasUnencrypted {
		base.Status = fix.FixSkipped
		base.Message = "all EBS volumes already encrypted in launch template"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would create new LT version with EBS encryption enabled on %s", resourceID)}
		return base
	}

	var updatedBDs []ec2types.LaunchTemplateBlockDeviceMappingRequest
	for _, bd := range data.BlockDeviceMappings {
		req := ec2types.LaunchTemplateBlockDeviceMappingRequest{
			DeviceName:  bd.DeviceName,
			NoDevice:    bd.NoDevice,
			VirtualName: bd.VirtualName,
		}
		if bd.Ebs != nil {
			req.Ebs = &ec2types.LaunchTemplateEbsBlockDeviceRequest{
				DeleteOnTermination: bd.Ebs.DeleteOnTermination,
				EbsCardIndex:        bd.Ebs.EbsCardIndex,
				Encrypted:           aws.Bool(true),
				Iops:                bd.Ebs.Iops,
				KmsKeyId:            bd.Ebs.KmsKeyId,
				SnapshotId:          bd.Ebs.SnapshotId,
				Throughput:          bd.Ebs.Throughput,
				VolumeSize:          bd.Ebs.VolumeSize,
			}
		}
		updatedBDs = append(updatedBDs, req)
	}

	newVer, err := f.clients.EC2.CreateLaunchTemplateVersion(fctx.Ctx, &ec2.CreateLaunchTemplateVersionInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		SourceVersion:    aws.String("$Default"),
		LaunchTemplateData: &ec2types.RequestLaunchTemplateData{
			BlockDeviceMappings: updatedBDs,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create launch template version: " + err.Error()
		return base
	}

	newVersionNum := fmt.Sprintf("%d", *newVer.LaunchTemplateVersion.VersionNumber)
	_, err = f.clients.EC2.ModifyLaunchTemplate(fctx.Ctx, &ec2.ModifyLaunchTemplateInput{
		LaunchTemplateId: lt.LaunchTemplateId,
		DefaultVersion:   aws.String(newVersionNum),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set default launch template version: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("created LT version %s with EBS encryption enabled and set as default on %s", newVersionNum, resourceID)}
	base.Status = fix.FixApplied
	return base
}
