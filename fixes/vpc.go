package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ── vpc-default-security-group-closed ────────────────────────────────────────

type vpcDefaultSGClosedFix struct{ clients *awsdata.Clients }

func (f *vpcDefaultSGClosedFix) CheckID() string {
	return "vpc-default-security-group-closed"
}
func (f *vpcDefaultSGClosedFix) Description() string {
	return "Remove all rules from the default security group in a VPC"
}
func (f *vpcDefaultSGClosedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *vpcDefaultSGClosedFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *vpcDefaultSGClosedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Find the default security group for this VPC
	sgOut, err := f.clients.EC2.DescribeSecurityGroups(fctx.Ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{resourceID}},
			{Name: aws.String("group-name"), Values: []string{"default"}},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe security groups: " + err.Error()
		return base
	}
	if len(sgOut.SecurityGroups) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "default security group not found"
		return base
	}
	sg := sgOut.SecurityGroups[0]
	sgID := aws.ToString(sg.GroupId)

	if len(sg.IpPermissions) == 0 && len(sg.IpPermissionsEgress) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "default security group already has no rules"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would revoke %d inbound and %d outbound rules from default SG %s in VPC %s",
				len(sg.IpPermissions), len(sg.IpPermissionsEgress), sgID, resourceID),
		}
		return base
	}

	var steps []string

	if len(sg.IpPermissions) > 0 {
		_, err = f.clients.EC2.RevokeSecurityGroupIngress(fctx.Ctx, &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: sg.IpPermissions,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "revoke ingress rules: " + err.Error()
			return base
		}
		steps = append(steps, fmt.Sprintf("revoked %d inbound rules from default SG %s", len(sg.IpPermissions), sgID))
	}

	if len(sg.IpPermissionsEgress) > 0 {
		_, err = f.clients.EC2.RevokeSecurityGroupEgress(fctx.Ctx, &ec2.RevokeSecurityGroupEgressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: sg.IpPermissionsEgress,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "revoke egress rules: " + err.Error()
			return base
		}
		steps = append(steps, fmt.Sprintf("revoked %d outbound rules from default SG %s", len(sg.IpPermissionsEgress), sgID))
	}

	base.Steps = steps
	base.Status = fix.FixApplied
	return base
}

// ── subnet-auto-assign-public-ip-disabled ────────────────────────────────────

type subnetAutoAssignPublicIPFix struct{ clients *awsdata.Clients }

func (f *subnetAutoAssignPublicIPFix) CheckID() string {
	return "subnet-auto-assign-public-ip-disabled"
}
func (f *subnetAutoAssignPublicIPFix) Description() string {
	return "Disable auto-assign public IP on subnet"
}
func (f *subnetAutoAssignPublicIPFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *subnetAutoAssignPublicIPFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *subnetAutoAssignPublicIPFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	snOut, err := f.clients.EC2.DescribeSubnets(fctx.Ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe subnet: " + err.Error()
		return base
	}
	if len(snOut.Subnets) == 0 {
		base.Status = fix.FixFailed
		base.Message = "subnet not found: " + resourceID
		return base
	}
	sn := snOut.Subnets[0]
	ipv4Enabled := sn.MapPublicIpOnLaunch != nil && *sn.MapPublicIpOnLaunch
	ipv6Enabled := sn.AssignIpv6AddressOnCreation != nil && *sn.AssignIpv6AddressOnCreation
	if !ipv4Enabled && !ipv6Enabled {
		base.Status = fix.FixSkipped
		base.Message = "auto-assign public IP already disabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable auto-assign public IP on subnet %s", resourceID)}
		return base
	}

	var steps []string

	if ipv4Enabled {
		_, err = f.clients.EC2.ModifySubnetAttribute(fctx.Ctx, &ec2.ModifySubnetAttributeInput{
			SubnetId:            aws.String(resourceID),
			MapPublicIpOnLaunch: &ec2types.AttributeBooleanValue{Value: aws.Bool(false)},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "disable IPv4 auto-assign: " + err.Error()
			return base
		}
		steps = append(steps, "disabled MapPublicIpOnLaunch on subnet "+resourceID)
	}

	if ipv6Enabled {
		_, err = f.clients.EC2.ModifySubnetAttribute(fctx.Ctx, &ec2.ModifySubnetAttributeInput{
			SubnetId:                     aws.String(resourceID),
			AssignIpv6AddressOnCreation: &ec2types.AttributeBooleanValue{Value: aws.Bool(false)},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "disable IPv6 auto-assign: " + err.Error()
			return base
		}
		steps = append(steps, "disabled AssignIpv6AddressOnCreation on subnet "+resourceID)
	}

	base.Steps = steps
	base.Status = fix.FixApplied
	return base
}
