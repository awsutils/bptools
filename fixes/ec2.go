package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
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
