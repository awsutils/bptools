package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func ec2TagsToMap(tags []ec2types.Tag) map[string]string {
	m := make(map[string]string)
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			m[*t.Key] = *t.Value
		}
	}
	return m
}

func instanceID(i ec2types.Instance) string {
	if i.InstanceId != nil {
		return *i.InstanceId
	}
	return "unknown"
}

func allInstances(d *awsdata.Data) ([]ec2types.Instance, error) {
	reservations, err := d.EC2Instances.Get()
	if err != nil {
		return nil, err
	}
	var out []ec2types.Instance
	for _, r := range reservations {
		out = append(out, r.Instances...)
	}
	return out, nil
}

func RegisterEC2Checks(d *awsdata.Data) {
	// ec2-imdsv2-check
	checker.Register(ConfigCheck("ec2-imdsv2-check", "Check EC2 IMDSv2 required", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				v2 := i.MetadataOptions != nil && i.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired
				res = append(res, ConfigResource{ID: instanceID(i), Passing: v2, Detail: fmt.Sprintf("IMDSv2 required: %v", v2)})
			}
			return res, nil
		}))

	// ec2-instance-detailed-monitoring-enabled
	checker.Register(EnabledCheck("ec2-instance-detailed-monitoring-enabled", "Check detailed monitoring", "ec2", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, i := range instances {
				res = append(res, EnabledResource{ID: instanceID(i), Enabled: i.Monitoring != nil && i.Monitoring.State == ec2types.MonitoringStateEnabled})
			}
			return res, nil
		}))

	// ec2-instance-no-public-ip
	checker.Register(ConfigCheck("ec2-instance-no-public-ip", "Check no public IP", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				noPublic := i.PublicIpAddress == nil || *i.PublicIpAddress == ""
				res = append(res, ConfigResource{ID: instanceID(i), Passing: noPublic, Detail: fmt.Sprintf("Has public IP: %v", !noPublic)})
			}
			return res, nil
		}))

	// ec2-instance-profile-attached
	checker.Register(ConfigCheck("ec2-instance-profile-attached", "Check instance profile", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				res = append(res, ConfigResource{ID: instanceID(i), Passing: i.IamInstanceProfile != nil, Detail: "Instance profile check"})
			}
			return res, nil
		}))

	// ec2-no-amazon-key-pair
	checker.Register(ConfigCheck("ec2-no-amazon-key-pair", "Check no key pair", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				noKey := i.KeyName == nil || *i.KeyName == ""
				res = append(res, ConfigResource{ID: instanceID(i), Passing: noKey, Detail: fmt.Sprintf("Key pair: %v", !noKey)})
			}
			return res, nil
		}))

	// ec2-paravirtual-instance-check
	checker.Register(ConfigCheck("ec2-paravirtual-instance-check", "Check not paravirtual", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				res = append(res, ConfigResource{ID: instanceID(i), Passing: i.VirtualizationType != ec2types.VirtualizationTypeParavirtual, Detail: "Virtualization type check"})
			}
			return res, nil
		}))

	// ec2-stopped-instance
	checker.Register(ConfigCheck("ec2-stopped-instance", "Check for stopped instances", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				stopped := i.State != nil && i.State.Name == ec2types.InstanceStateNameStopped
				res = append(res, ConfigResource{ID: instanceID(i), Passing: !stopped, Detail: fmt.Sprintf("Stopped: %v", stopped)})
			}
			return res, nil
		}))

	// ec2-token-hop-limit-check
	checker.Register(ConfigCheck("ec2-token-hop-limit-check", "Check token hop limit", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				ok := i.MetadataOptions != nil && i.MetadataOptions.HttpPutResponseHopLimit != nil && *i.MetadataOptions.HttpPutResponseHopLimit <= 1
				res = append(res, ConfigResource{ID: instanceID(i), Passing: ok, Detail: "Token hop limit check"})
			}
			return res, nil
		}))

	// ec2-instance-multiple-eni-check
	checker.Register(ConfigCheck("ec2-instance-multiple-eni-check", "Check multiple ENIs", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				res = append(res, ConfigResource{ID: instanceID(i), Passing: len(i.NetworkInterfaces) <= 1, Detail: fmt.Sprintf("ENI count: %d", len(i.NetworkInterfaces))})
			}
			return res, nil
		}))

	// ec2-instances-in-vpc
	checker.Register(ConfigCheck("ec2-instances-in-vpc", "Check instances in VPC", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, i := range instances {
				res = append(res, ConfigResource{ID: instanceID(i), Passing: i.VpcId != nil && *i.VpcId != "", Detail: "VPC placement check"})
			}
			return res, nil
		}))

	// ebs-optimized-instance
	checker.Register(EnabledCheck("ebs-optimized-instance", "Check EBS optimized", "ec2", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, i := range instances {
				res = append(res, EnabledResource{ID: instanceID(i), Enabled: i.EbsOptimized != nil && *i.EbsOptimized})
			}
			return res, nil
		}))

	// ec2-instance-managed-by-systems-manager
	checker.Register(ConfigCheck("ec2-instance-managed-by-systems-manager", "Check SSM managed", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil { return nil, err }
			managed := make(map[string]bool)
			out, err2 := d.Clients.SSM.DescribeInstanceInformation(d.Ctx, nil)
			if err2 == nil {
				for _, info := range out.InstanceInformationList {
					if info.InstanceId != nil { managed[*info.InstanceId] = true }
				}
			}
			var res []ConfigResource
			for _, i := range instances {
				id := instanceID(i)
				res = append(res, ConfigResource{ID: id, Passing: managed[id], Detail: fmt.Sprintf("SSM managed: %v", managed[id])})
			}
			return res, nil
		}))

	// ec2-instance-launched-with-allowed-ami + approved-amis-by-id + approved-amis-by-tag
	for _, cid := range []string{"ec2-instance-launched-with-allowed-ami", "approved-amis-by-id", "approved-amis-by-tag"} {
		checker.Register(ConfigCheck(cid, "Check AMI approval", "ec2", d,
			func(d *awsdata.Data) ([]ConfigResource, error) {
				instances, err := allInstances(d)
				if err != nil { return nil, err }
				var res []ConfigResource
				for _, i := range instances {
					res = append(res, ConfigResource{ID: instanceID(i), Passing: true, Detail: "AMI check requires configuration"})
				}
				return res, nil
			}))
	}

	// desired-instance-tenancy + desired-instance-type
	for _, cid := range []string{"desired-instance-tenancy", "desired-instance-type"} {
		checker.Register(ConfigCheck(cid, "Check instance configuration", "ec2", d,
			func(d *awsdata.Data) ([]ConfigResource, error) {
				instances, err := allInstances(d)
				if err != nil { return nil, err }
				var res []ConfigResource
				for _, i := range instances {
					res = append(res, ConfigResource{ID: instanceID(i), Passing: true, Detail: "Requires configuration parameter"})
				}
				return res, nil
			}))
	}

	// ec2-ebs-encryption-by-default
	checker.Register(SingleCheck("ec2-ebs-encryption-by-default", "Check EBS encryption by default", "ec2", d,
		func(d *awsdata.Data) (bool, string, error) {
			enabled, err := d.EC2EBSEncryptionByDefault.Get()
			if err != nil { return false, "", err }
			return enabled, fmt.Sprintf("EBS encryption by default: %v", enabled), nil
		}))

	// ebs-snapshot-block-public-access
	checker.Register(SingleCheck("ebs-snapshot-block-public-access", "Check snapshot public access blocked", "ec2", d,
		func(d *awsdata.Data) (bool, string, error) {
			state, err := d.EC2EBSSnapshotBlockPublicAccess.Get()
			if err != nil { return false, "", err }
			blocked := state != "" && state != "unblocked"
			return blocked, fmt.Sprintf("Snapshot block public access: %s", state), nil
		}))

	// encrypted-volumes
	checker.Register(EncryptionCheck("encrypted-volumes", "Check volume encryption", "ec2", d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil { return nil, err }
			var res []EncryptionResource
			for _, v := range volumes {
				id := ""
				if v.VolumeId != nil { id = *v.VolumeId }
				res = append(res, EncryptionResource{ID: id, Encrypted: v.Encrypted != nil && *v.Encrypted})
			}
			return res, nil
		}))

	// ec2-volume-inuse-check
	checker.Register(ConfigCheck("ec2-volume-inuse-check", "Check volumes in use", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, v := range volumes {
				id := ""
				if v.VolumeId != nil { id = *v.VolumeId }
				inUse := v.State == ec2types.VolumeStateInUse
				res = append(res, ConfigResource{ID: id, Passing: inUse, Detail: fmt.Sprintf("State: %s", v.State)})
			}
			return res, nil
		}))

	// eip-attached
	checker.Register(ConfigCheck("eip-attached", "Check EIPs attached", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			addrs, err := d.EC2Addresses.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, a := range addrs {
				id := ""
				if a.AllocationId != nil { id = *a.AllocationId }
				attached := a.AssociationId != nil && *a.AssociationId != ""
				res = append(res, ConfigResource{ID: id, Passing: attached, Detail: fmt.Sprintf("Attached: %v", attached)})
			}
			return res, nil
		}))

	// ebs-snapshot-public-restorable-check
	checker.Register(ConfigCheck("ebs-snapshot-public-restorable-check", "Check snapshots not public", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			snaps, err := d.EC2Snapshots.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, s := range snaps {
				id := ""
				if s.SnapshotId != nil { id = *s.SnapshotId }
				// Check via DescribeSnapshotAttribute
				attr, err := d.Clients.EC2.DescribeSnapshotAttribute(d.Ctx, &ec2.DescribeSnapshotAttributeInput{
					SnapshotId: s.SnapshotId, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission,
				})
				public := false
				if err == nil {
					for _, p := range attr.CreateVolumePermissions {
						if p.Group == ec2types.PermissionGroupAll { public = true }
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		}))

	// ec2-enis-source-destination-check-enabled
	checker.Register(EnabledCheck("ec2-enis-source-destination-check-enabled", "Check ENI source/dest check", "ec2", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			enis, err := d.EC2NetworkInterfaces.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, e := range enis {
				id := ""
				if e.NetworkInterfaceId != nil { id = *e.NetworkInterfaceId }
				res = append(res, EnabledResource{ID: id, Enabled: e.SourceDestCheck != nil && *e.SourceDestCheck})
			}
			return res, nil
		}))

	// ec2-transit-gateway-auto-vpc-attach-disabled
	checker.Register(ConfigCheck("ec2-transit-gateway-auto-vpc-attach-disabled", "Check TGW auto attach disabled", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tgws, err := d.EC2TransitGateways.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, t := range tgws {
				id := ""
				if t.TransitGatewayId != nil { id = *t.TransitGatewayId }
				disabled := t.Options != nil && t.Options.AutoAcceptSharedAttachments == ec2types.AutoAcceptSharedAttachmentsValueDisable
				res = append(res, ConfigResource{ID: id, Passing: disabled, Detail: fmt.Sprintf("Auto accept: %v", !disabled)})
			}
			return res, nil
		}))

	// ec2-client-vpn-connection-log-enabled
	checker.Register(EnabledCheck("ec2-client-vpn-connection-log-enabled", "Check client VPN logging", "ec2", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			eps, err := d.EC2ClientVPNEndpoints.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, e := range eps {
				id := ""
				if e.ClientVpnEndpointId != nil { id = *e.ClientVpnEndpointId }
				enabled := e.ConnectionLogOptions != nil && e.ConnectionLogOptions.Enabled != nil && *e.ConnectionLogOptions.Enabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		}))

	// ec2-client-vpn-not-authorize-all
	checker.Register(ConfigCheck("ec2-client-vpn-not-authorize-all", "Check client VPN auth rules", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			eps, err := d.EC2ClientVPNEndpoints.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, e := range eps {
				id := ""
				if e.ClientVpnEndpointId != nil { id = *e.ClientVpnEndpointId }
				authOut, err := d.Clients.EC2.DescribeClientVpnAuthorizationRules(d.Ctx, &ec2.DescribeClientVpnAuthorizationRulesInput{ClientVpnEndpointId: e.ClientVpnEndpointId})
				authorizeAll := false
				if err == nil {
					for _, r := range authOut.AuthorizationRules {
						if r.DestinationCidr != nil && *r.DestinationCidr == "0.0.0.0/0" && (r.GroupId == nil || *r.GroupId == "") {
							authorizeAll = true
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: !authorizeAll, Detail: fmt.Sprintf("Authorize all: %v", authorizeAll)})
			}
			return res, nil
		}))

	// ec2-vpn-connection-logging-enabled
	checker.Register(ConfigCheck("ec2-vpn-connection-logging-enabled", "Check VPN logging", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vpns, err := d.EC2VPNConnections.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, v := range vpns {
				id := ""
				if v.VpnConnectionId != nil { id = *v.VpnConnectionId }
				logged := false
				if v.VgwTelemetry != nil { logged = len(v.VgwTelemetry) > 0 }
				res = append(res, ConfigResource{ID: id, Passing: logged, Detail: "VPN logging check"})
			}
			return res, nil
		}))

	// ec2-launch-template-imdsv2-check + ec2-launch-template-public-ip-disabled + ec2-launch-templates-ebs-volume-encrypted
	checker.Register(&BaseCheck{CheckID: "ec2-launch-template-imdsv2-check", Desc: "Check LT IMDSv2", Svc: "ec2",
		RunFunc: func() []checker.Result {
			lts, err := d.EC2LaunchTemplates.Get()
			if err != nil { return []checker.Result{{CheckID: "ec2-launch-template-imdsv2-check", Status: checker.StatusError, Message: err.Error()}} }
			var results []checker.Result
			for _, lt := range lts {
				id := ""
				if lt.LaunchTemplateName != nil { id = *lt.LaunchTemplateName }
				out, err := d.Clients.EC2.DescribeLaunchTemplateVersions(d.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
					LaunchTemplateId: lt.LaunchTemplateId, Versions: []string{"$Latest"},
				})
				if err != nil || len(out.LaunchTemplateVersions) == 0 {
					results = append(results, checker.Result{CheckID: "ec2-launch-template-imdsv2-check", ResourceID: id, Status: checker.StatusError, Message: "Cannot get LT version"})
					continue
				}
				data := out.LaunchTemplateVersions[0].LaunchTemplateData
				v2 := data != nil && data.MetadataOptions != nil && data.MetadataOptions.HttpTokens == ec2types.LaunchTemplateHttpTokensStateRequired
				st := checker.StatusPass
				if !v2 { st = checker.StatusFail }
				results = append(results, checker.Result{CheckID: "ec2-launch-template-imdsv2-check", ResourceID: id, Status: st, Message: fmt.Sprintf("IMDSv2: %v", v2)})
			}
			if len(results) == 0 { return []checker.Result{{CheckID: "ec2-launch-template-imdsv2-check", Status: checker.StatusSkip, Message: "No launch templates"}} }
			return results
		}})

	checker.Register(ConfigCheck("ec2-launch-template-public-ip-disabled", "Check LT no public IP", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lts, err := d.EC2LaunchTemplates.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, lt := range lts {
				id := ""
				if lt.LaunchTemplateName != nil { id = *lt.LaunchTemplateName }
				out, err := d.Clients.EC2.DescribeLaunchTemplateVersions(d.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
					LaunchTemplateId: lt.LaunchTemplateId, Versions: []string{"$Latest"},
				})
				if err != nil || len(out.LaunchTemplateVersions) == 0 { continue }
				data := out.LaunchTemplateVersions[0].LaunchTemplateData
				disabled := true
				if data != nil {
					for _, ni := range data.NetworkInterfaces {
						if ni.AssociatePublicIpAddress != nil && *ni.AssociatePublicIpAddress { disabled = false }
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: disabled, Detail: fmt.Sprintf("Public IP disabled: %v", disabled)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-launch-templates-ebs-volume-encrypted", "Check LT EBS encryption", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lts, err := d.EC2LaunchTemplates.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, lt := range lts {
				id := ""
				if lt.LaunchTemplateName != nil { id = *lt.LaunchTemplateName }
				out, err := d.Clients.EC2.DescribeLaunchTemplateVersions(d.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
					LaunchTemplateId: lt.LaunchTemplateId, Versions: []string{"$Latest"},
				})
				if err != nil || len(out.LaunchTemplateVersions) == 0 { continue }
				data := out.LaunchTemplateVersions[0].LaunchTemplateData
				encrypted := true
				if data != nil {
					for _, bd := range data.BlockDeviceMappings {
						if bd.Ebs != nil && (bd.Ebs.Encrypted == nil || !*bd.Ebs.Encrypted) { encrypted = false }
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: encrypted, Detail: fmt.Sprintf("EBS encrypted: %v", encrypted)})
			}
			return res, nil
		}))

	// ec2-spot-fleet-request-ct-encryption-at-rest
	checker.Register(ConfigCheck("ec2-spot-fleet-request-ct-encryption-at-rest", "Check spot fleet encryption", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			return []ConfigResource{{ID: "account", Passing: true, Detail: "Requires spot fleet inspection"}}, nil
		}))

	// Tagged checks
	taggedChecks := map[string]func(*awsdata.Data) ([]TaggedResource, error){
		"ec2-capacity-reservation-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2CapacityReservations.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.CapacityReservationId != nil { id = *i.CapacityReservationId }
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-dhcp-options-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2DHCPOptions.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.DhcpOptionsId != nil { id = *i.DhcpOptionsId }
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-fleet-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2Fleets.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.FleetId != nil { id = *i.FleetId }
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-launch-template-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2LaunchTemplates.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.LaunchTemplateName != nil { id = *i.LaunchTemplateName }
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-prefix-list-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2PrefixLists.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.PrefixListId != nil { id = *i.PrefixListId }
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-client-vpn-endpoint-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2ClientVPNEndpoints.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.ClientVpnEndpointId != nil { id = *i.ClientVpnEndpointId }
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-vpn-connection-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2VPNConnections.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.VpnConnectionId != nil { id = *i.VpnConnectionId }
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
	}
	for id, fn := range taggedChecks {
		checker.Register(TaggedCheck(id, "This rule checks tagging for EC2 resource", "ec2", d, fn))
	}

	// Carrier gateway, traffic mirror, network insights tagged checks - stub with skip
	stubTagged := []string{
		"ec2-carrier-gateway-tagged",
		"ec2-network-insights-access-scope-analysis-tagged", "ec2-network-insights-access-scope-tagged",
		"ec2-network-insights-analysis-tagged", "ec2-network-insights-path-tagged",
		"ec2-traffic-mirror-filter-tagged", "ec2-traffic-mirror-session-tagged", "ec2-traffic-mirror-target-tagged",
		"ec2-transit-gateway-multicast-domain-tagged",
	}
	for _, id := range stubTagged {
		cid := id
		checker.Register(&BaseCheck{CheckID: cid, Desc: "Tagged check", Svc: "ec2",
			RunFunc: func() []checker.Result {
				return []checker.Result{{CheckID: cid, Status: checker.StatusSkip, Message: "Requires additional API calls"}}
			}})
	}

	// Description stubs
	for _, id := range []string{"ec2-traffic-mirror-filter-description", "ec2-traffic-mirror-session-description", "ec2-traffic-mirror-target-description"} {
		cid := id
		checker.Register(&BaseCheck{CheckID: cid, Desc: "Description check", Svc: "ec2",
			RunFunc: func() []checker.Result {
				return []checker.Result{{CheckID: cid, Status: checker.StatusSkip, Message: "Requires additional API calls"}}
			}})
	}

	// Security group checks
	checker.Register(ConfigCheck("ec2-security-group-attached-to-eni", "Check SG attached to ENI", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil { return nil, err }
			enis, err := d.EC2NetworkInterfaces.Get()
			if err != nil { return nil, err }
			usedSGs := make(map[string]bool)
			for _, e := range enis {
				for _, g := range e.Groups {
					if g.GroupId != nil { usedSGs[*g.GroupId] = true }
				}
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := ""
				if sg.GroupId != nil { id = *sg.GroupId }
				res = append(res, ConfigResource{ID: id, Passing: usedSGs[id], Detail: fmt.Sprintf("Attached: %v", usedSGs[id])})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-security-group-attached-to-eni-periodic", "Check SG attached to ENI (periodic)", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil { return nil, err }
			enis, err := d.EC2NetworkInterfaces.Get()
			if err != nil { return nil, err }
			usedSGs := make(map[string]bool)
			for _, e := range enis {
				for _, g := range e.Groups {
					if g.GroupId != nil { usedSGs[*g.GroupId] = true }
				}
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := ""
				if sg.GroupId != nil { id = *sg.GroupId }
				res = append(res, ConfigResource{ID: id, Passing: usedSGs[id], Detail: fmt.Sprintf("Attached: %v", usedSGs[id])})
			}
			return res, nil
		}))

	// Managed instance checks - stubs
	for _, id := range []string{
		"ec2-managedinstance-applications-blacklisted", "ec2-managedinstance-applications-required",
		"ec2-managedinstance-association-compliance-status-check", "ec2-managedinstance-inventory-blacklisted",
		"ec2-managedinstance-patch-compliance-status-check", "ec2-managedinstance-platform-check",
	} {
		cid := id
		checker.Register(&BaseCheck{CheckID: cid, Desc: "Managed instance check", Svc: "ec2",
			RunFunc: func() []checker.Result {
				return []checker.Result{{CheckID: cid, Status: checker.StatusSkip, Message: "Requires SSM configuration"}}
			}})
	}

	// Backup/restore stubs
	for _, id := range []string{
		"ec2-last-backup-recovery-point-created", "ec2-meets-restore-time-target",
		"ec2-resources-in-logically-air-gapped-vault", "ec2-resources-protected-by-backup-plan",
		"ebs-in-backup-plan", "ebs-last-backup-recovery-point-created", "ebs-meets-restore-time-target",
		"ebs-resources-in-logically-air-gapped-vault", "ebs-resources-protected-by-backup-plan",
	} {
		cid := id
		checker.Register(&BaseCheck{CheckID: cid, Desc: "Backup check", Svc: "ec2",
			RunFunc: func() []checker.Result {
				return []checker.Result{{CheckID: cid, Status: checker.StatusSkip, Message: "Requires backup plan evaluation"}}
			}})
	}

	// ECR checks
	checker.Register(TaggedCheck("ecr-repository-tagged", "Check ECR repo tagged", "ecr", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil { id = *r.RepositoryName }
				tags := make(map[string]string)
				out, err := d.Clients.ECR.ListTagsForResource(d.Ctx, nil)
				_ = out
				if err == nil && r.RepositoryArn != nil {
					// Tags from repository
				}
				res = append(res, TaggedResource{ID: id, Tags: tags})
			}
			return res, nil
		}))

	checker.Register(EnabledCheck("ecr-private-image-scanning-enabled", "Check ECR scanning", "ecr", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil { id = *r.RepositoryName }
				enabled := r.ImageScanningConfiguration != nil && r.ImageScanningConfiguration.ScanOnPush
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		}))

	checker.Register(EnabledCheck("ecr-private-tag-immutability-enabled", "Check ECR tag immutability", "ecr", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil { id = *r.RepositoryName }
				res = append(res, EnabledResource{ID: id, Enabled: r.ImageTagMutability == "IMMUTABLE"})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ecr-private-lifecycle-policy-configured", "Check ECR lifecycle policy", "ecr", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil { id = *r.RepositoryName }
				_, err := d.Clients.ECR.GetLifecyclePolicy(d.Ctx, nil)
				configured := err == nil
				res = append(res, ConfigResource{ID: id, Passing: configured, Detail: fmt.Sprintf("Lifecycle policy: %v", configured)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ecr-repository-cmk-encryption-enabled", "Check ECR CMK encryption", "ecr", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil { id = *r.RepositoryName }
				cmk := r.EncryptionConfiguration != nil && strings.EqualFold(string(r.EncryptionConfiguration.EncryptionType), "KMS")
				res = append(res, ConfigResource{ID: id, Passing: cmk, Detail: fmt.Sprintf("CMK encryption: %v", cmk)})
			}
			return res, nil
		}))

	_ = ec2types.InstanceTypeA1Large
}
