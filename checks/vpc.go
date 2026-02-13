package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// RegisterVPCChecks registers VPC checks.
func RegisterVPCChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"vpc-default-security-group-closed",
		"Checks if the default security group of any Amazon Virtual Private Cloud (Amazon VPC) does not allow inbound or outbound traffic. The rule is NON_COMPLIANT if the default security group has one or more inbound or outbound traffic rules.",
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
				ok := false
				for _, sg := range sgs {
					if sg.VpcId == nil || sg.GroupName == nil || *sg.GroupName != "default" || *sg.VpcId != vpcID {
						continue
					}
					ok = len(sg.IpPermissions) == 0 && len(sg.IpPermissionsEgress) == 0
					if !ok {
						ok = false
					}
					break
				}
				res = append(res, ConfigResource{ID: vpcID, Passing: ok, Detail: "Default SG has no ingress or egress rules"})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"vpc-endpoint-enabled",
		"Checks if each service specified in the parameter has an Amazon VPC endpoint. The rule is NON_COMPLIANT if Amazon VPC does not have a VPC endpoint created for each specified service. Optionally, you can specify certain VPCs for the rule to check.",
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
			requiredService, configured := vpcRequiredEndpointService()
			if !configured {
				return []EnabledResource{{ID: "account", Enabled: false}}, nil
			}
			hasEndpoint := vpcEndpointCoverage(endpoints, requiredService)
			var res []EnabledResource
			for _, v := range vpcs {
				id := "unknown"
				if v.VpcId != nil {
					id = *v.VpcId
				}
				enabled := hasEndpoint[id]
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"vpc-flow-logs-enabled",
		"Checks if Amazon Virtual Private Cloud (Amazon VPC) flow logs are found and enabled for all Amazon VPCs. The rule is NON_COMPLIANT if flow logs are not enabled for at least one Amazon VPC.",
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
		"Checks if there are unused network access control lists (network ACLs). The rule is COMPLIANT if each network ACL is associated with a subnet. The rule is NON_COMPLIANT if a network ACL is not associated with a subnet.",
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
		"Checks if DNS resolution from accepter/requester VPC to private IP is enabled. The rule is NON_COMPLIANT if DNS resolution from accepter/requester VPC to private IP is not enabled.",
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
		"Checks if security groups allowing unrestricted incoming traffic ('0.0.0.0/0' or '::/0') only allow inbound TCP or UDP connections on authorized ports. The rule is NON_COMPLIANT if such security groups do not have ports specified in the rule parameters.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			allowedPorts := parsePortListWithDefault("BPTOOLS_AUTHORIZED_PUBLIC_PORTS", []int32{80, 443})
			var res []ConfigResource
			for _, sg := range sgs {
				id := sgID(sg)
				ok := true
				for _, perm := range sg.IpPermissions {
					if !permissionIsPublic(perm) {
						continue
					}
					if !permissionOnlyAllowsPorts(perm, allowedPorts) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Public ingress limited to authorized ports: %v", allowedPorts)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"vpc-sg-port-restriction-check",
		"Checks if security groups restrict incoming traffic to restricted ports explicitly from 0.0.0.0/0 or ::/0. The rule is NON_COMPLIANT if security groups allow incoming traffic from 0.0.0.0/0 or ::/0 over TCP/UDP ports 22/3389 or as specified in parameters.",
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
					if permissionOpensPort(perm, 22) || permissionOpensPort(perm, 3389) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No public ingress on port 22 or 3389"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"vpc-vpn-2-tunnels-up",
		"Checks if both virtual private network (VPN) tunnels provided by AWS Site-to-Site VPN are in UP status. The rule is NON_COMPLIANT if one or both tunnels are in DOWN status.",
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
		"Checks if Amazon Virtual Private Cloud (Amazon VPC) subnets are configured to automatically assign public IP addresses to instances launched within them. This rule is COMPLIANT if subnets do not auto-assign public IPv4 or IPv6 addresses. This rule is NON_COMPLIANT if subnets auto-assign public IPv4 or IPv6 addresses.",
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
				ipv4Enabled := s.MapPublicIpOnLaunch != nil && *s.MapPublicIpOnLaunch
				ipv6Enabled := s.AssignIpv6AddressOnCreation != nil && *s.AssignIpv6AddressOnCreation
				res = append(res, ConfigResource{
					ID:      id,
					Passing: !ipv4Enabled && !ipv6Enabled,
					Detail:  fmt.Sprintf("IPv4 auto-assign: %v, IPv6 auto-assign: %v", ipv4Enabled, ipv6Enabled),
				})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"restricted-common-ports",
		"Checks if the security groups in use do not allow unrestricted incoming Transmission Control Protocol (TCP) traffic to specified ports. The rule is COMPLIANT if:",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			restrictedPorts := parsePortListWithDefault("BPTOOLS_RESTRICTED_COMMON_PORTS", []int32{20, 21, 3306, 3389, 4333})
			var res []ConfigResource
			for _, sg := range sgs {
				id := sgID(sg)
				ok := true
				for _, perm := range sg.IpPermissions {
					if !permissionIsPublic(perm) {
						continue
					}
					if permissionHitsPorts(perm, restrictedPorts) {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("No public access to restricted common ports: %v", restrictedPorts)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"service-vpc-endpoint-enabled",
		"Checks if Service Endpoint for the service provided in rule parameter is created for each Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if an Amazon VPC doesn't have an Amazon VPC endpoint created for the service.",
		"vpc",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vpcs, err := d.EC2VPCs.Get()
			if err != nil {
				return nil, err
			}
			endpoints, err := d.EC2VPCEndpoints.Get()
			if err != nil {
				return nil, err
			}
			requiredService, _ := vpcRequiredEndpointService()
			hasEndpoint := vpcEndpointCoverage(endpoints, requiredService)
			var res []ConfigResource
			for _, v := range vpcs {
				id := "unknown"
				if v.VpcId != nil {
					id = *v.VpcId
				}
				ok := hasEndpoint[id]
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail:  fmt.Sprintf("Required endpoint service '%s' configured: %v", requiredService, ok),
				})
			}
			return res, nil
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

func permissionOpensPort(p ec2types.IpPermission, port int32) bool {
	if p.IpProtocol != nil {
		proto := *p.IpProtocol
		if proto != "tcp" && proto != "udp" && proto != "-1" {
			return false
		}
	}
	if p.FromPort == nil || p.ToPort == nil {
		return true
	}
	return port >= *p.FromPort && port <= *p.ToPort
}

func permissionHitsPorts(p ec2types.IpPermission, ports []int32) bool {
	if p.IpProtocol != nil && *p.IpProtocol != "tcp" && *p.IpProtocol != "-1" {
		return false
	}
	if p.FromPort == nil || p.ToPort == nil {
		return true
	}
	for _, port := range ports {
		if port >= *p.FromPort && port <= *p.ToPort {
			return true
		}
	}
	return false
}

func permissionOnlyAllowsPorts(p ec2types.IpPermission, allowed []int32) bool {
	if p.IpProtocol != nil && *p.IpProtocol != "tcp" && *p.IpProtocol != "udp" {
		return false
	}
	if p.FromPort == nil || p.ToPort == nil {
		return false
	}
	for port := *p.FromPort; port <= *p.ToPort; port++ {
		if !containsPort(allowed, port) {
			return false
		}
	}
	return true
}

func containsPort(ports []int32, want int32) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

func parsePortListWithDefault(envVar string, defaults []int32) []int32 {
	value := strings.TrimSpace(os.Getenv(envVar))
	if value == "" {
		return defaults
	}
	parts := strings.Split(value, ",")
	var ports []int32
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		ports = append(ports, int32(n))
	}
	if len(ports) == 0 {
		return defaults
	}
	return ports
}

func vpcRequiredEndpointService() (string, bool) {
	service := strings.TrimSpace(os.Getenv("BPTOOLS_REQUIRED_VPC_ENDPOINT_SERVICE"))
	if service == "" {
		return "s3", true
	}
	return strings.ToLower(service), true
}

func vpcEndpointCoverage(endpoints []ec2types.VpcEndpoint, requiredService string) map[string]bool {
	coverage := make(map[string]bool)
	for _, ep := range endpoints {
		if ep.VpcId == nil || ep.ServiceName == nil {
			continue
		}
		switch ep.State {
		case ec2types.StateAvailable, ec2types.StatePendingAcceptance:
		default:
			continue
		}
		serviceName := strings.ToLower(strings.TrimSpace(*ep.ServiceName))
		if !endpointServiceMatches(serviceName, requiredService) {
			continue
		}
		coverage[*ep.VpcId] = true
	}
	return coverage
}

func endpointServiceMatches(serviceName, requiredService string) bool {
	requiredService = strings.ToLower(strings.TrimSpace(requiredService))
	if requiredService == "" {
		return true
	}
	if serviceName == requiredService {
		return true
	}
	return strings.HasSuffix(serviceName, "."+requiredService)
}
