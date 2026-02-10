package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// RegisterVPCChecks registers VPC checks.
func RegisterVPCChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"vpc-default-security-group-closed",
		"This rule checks VPC default security group closed.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vpcs, err := d.EC2VPCs.Get()
			if err != nil {
				return nil, err
			}
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, v := range vpcs {
				vpcID := "unknown"
				if v.VpcId != nil {
					vpcID = *v.VpcId
				}
				ok := true
				for _, sg := range sgs {
					if sg.VpcId == nil || sg.GroupName == nil || *sg.GroupName != "default" || *sg.VpcId != vpcID {
						continue
					}
					if hasPublicRule(sg.IpPermissions) || hasPublicRule(sg.IpPermissionsEgress) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: vpcID, Passing: ok, Detail: "Default SG has no public rules"})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"vpc-endpoint-enabled",
		"This rule checks enabled state for VPC endpoint.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			vpcs, err := d.EC2VPCs.Get()
			if err != nil {
				return nil, err
			}
			endpoints, err := d.EC2VPCEndpoints.Get()
			if err != nil {
				return nil, err
			}
			count := make(map[string]int)
			for _, ep := range endpoints {
				if ep.VpcId != nil {
					count[*ep.VpcId]++
				}
			}
			var res []EnabledResource
			for _, v := range vpcs {
				id := "unknown"
				if v.VpcId != nil {
					id = *v.VpcId
				}
				enabled := count[id] > 0
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"vpc-flow-logs-enabled",
		"This rule checks enabled state for VPC flow logs.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			vpcs, err := d.EC2VPCs.Get()
			if err != nil {
				return nil, err
			}
			flows, err := d.EC2FlowLogs.Get()
			if err != nil {
				return nil, err
			}
			count := make(map[string]int)
			for _, f := range flows {
				if f.ResourceId != nil {
					count[*f.ResourceId]++
				}
			}
			var res []EnabledResource
			for _, v := range vpcs {
				id := "unknown"
				if v.VpcId != nil {
					id = *v.VpcId
				}
				enabled := count[id] > 0
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"vpc-network-acl-unused-check",
		"This rule checks configuration for VPC network acl unused.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			acls, err := d.EC2NetworkACLs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, acl := range acls {
				id := "unknown"
				if acl.NetworkAclId != nil {
					id = *acl.NetworkAclId
				}
				ok := len(acl.Associations) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Associations: %d", len(acl.Associations))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"vpc-peering-dns-resolution-check",
		"This rule checks configuration for VPC peering DNS resolution.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			peers, err := d.EC2VPCPeeringConnections.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range peers {
				id := "unknown"
				if p.VpcPeeringConnectionId != nil {
					id = *p.VpcPeeringConnectionId
				}
				ok := p.AccepterVpcInfo != nil && p.RequesterVpcInfo != nil &&
					p.AccepterVpcInfo.PeeringOptions != nil &&
					p.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil &&
					*p.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc &&
					p.RequesterVpcInfo.PeeringOptions != nil &&
					p.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil &&
					*p.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "DNS resolution enabled on both sides"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"vpc-sg-open-only-to-authorized-ports",
		"This rule checks VPC sg open only to authorized ports.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := sgID(sg)
				ok := true
				for _, perm := range sg.IpPermissions {
					if !permissionIsPublic(perm) {
						continue
					}
					if !portIsAuthorized(perm) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Public ingress limited to 80/443"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"vpc-sg-port-restriction-check",
		"This rule checks configuration for VPC sg port restriction.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := sgID(sg)
				ok := true
				for _, perm := range sg.IpPermissions {
					if !permissionIsPublic(perm) {
						continue
					}
					if permissionIsUnrestricted(perm) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No unrestricted public ingress"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"vpc-vpn-2-tunnels-up",
		"This rule checks VPC VPN 2 tunnels up.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vpns, err := d.EC2VPNConnections.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, v := range vpns {
				id := "unknown"
				if v.VpnConnectionId != nil {
					id = *v.VpnConnectionId
				}
				up := 0
				for _, t := range v.VgwTelemetry {
					if t.Status == ec2types.TelemetryStatusUp {
						up++
					}
				}
				ok := up >= 2
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Tunnels up: %d", up)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"subnet-auto-assign-public-ip-disabled",
		"This rule checks subnet auto assign public ip disabled.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			subnets, err := d.EC2Subnets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range subnets {
				id := "unknown"
				if s.SubnetId != nil {
					id = *s.SubnetId
				}
				enabled := s.MapPublicIpOnLaunch != nil && *s.MapPublicIpOnLaunch
				res = append(res, ConfigResource{ID: id, Passing: !enabled, Detail: fmt.Sprintf("MapPublicIpOnLaunch: %v", enabled)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"restricted-common-ports",
		"This rule checks restricted common ports.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := sgID(sg)
				ok := true
				for _, perm := range sg.IpPermissions {
					if !permissionIsPublic(perm) {
						continue
					}
					if permissionHitsCommonPorts(perm) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No public access to common ports"})
			}
			return res, nil
		},
	))

	checker.Register(SingleCheck(
		"service-vpc-endpoint-enabled",
		"This rule checks service vpc endpoint enabled.",
		"vpc",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			endpoints, err := d.EC2VPCEndpoints.Get()
			if err != nil {
				return false, err.Error(), err
			}
			if len(endpoints) > 0 {
				return true, "VPC endpoints configured", nil
			}
			return false, "No VPC endpoints configured", nil
		},
	))
}

func sgID(sg ec2types.SecurityGroup) string {
	if sg.GroupId != nil {
		return *sg.GroupId
	}
	if sg.GroupName != nil {
		return *sg.GroupName
	}
	return "unknown"
}

func hasPublicRule(perms []ec2types.IpPermission) bool {
	for _, p := range perms {
		if permissionIsPublic(p) {
			return true
		}
	}
	return false
}

func permissionIsPublic(p ec2types.IpPermission) bool {
	for _, r := range p.IpRanges {
		if r.CidrIp != nil && *r.CidrIp == "0.0.0.0/0" {
			return true
		}
	}
	for _, r := range p.Ipv6Ranges {
		if r.CidrIpv6 != nil && *r.CidrIpv6 == "::/0" {
			return true
		}
	}
	return false
}

func permissionIsUnrestricted(p ec2types.IpPermission) bool {
	if p.IpProtocol != nil && *p.IpProtocol == "-1" {
		return true
	}
	if p.FromPort != nil && p.ToPort != nil {
		if *p.FromPort <= 0 && *p.ToPort >= 65535 {
			return true
		}
	}
	return false
}

func permissionHitsCommonPorts(p ec2types.IpPermission) bool {
	if p.IpProtocol != nil && *p.IpProtocol != "tcp" && *p.IpProtocol != "-1" {
		return false
	}
	common := []int32{20, 21, 22, 23, 25, 110, 143, 445, 3389, 3306, 5432, 1433, 1521, 27017}
	if p.FromPort == nil || p.ToPort == nil {
		return true
	}
	for _, port := range common {
		if port >= *p.FromPort && port <= *p.ToPort {
			return true
		}
	}
	return false
}

func portIsAuthorized(p ec2types.IpPermission) bool {
	if p.FromPort == nil || p.ToPort == nil {
		return false
	}
	return (*p.FromPort == 80 && *p.ToPort == 80) || (*p.FromPort == 443 && *p.ToPort == 443)
}
