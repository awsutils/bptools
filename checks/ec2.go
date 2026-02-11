package checks

import (
	"fmt"
	"os"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
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
			if err != nil {
				return nil, err
			}
			managed := make(map[string]bool)
			out, err2 := d.Clients.SSM.DescribeInstanceInformation(d.Ctx, nil)
			if err2 == nil {
				for _, info := range out.InstanceInformationList {
					if info.InstanceId != nil {
						managed[*info.InstanceId] = true
					}
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
	parseCSV := func(value string) []string {
		var out []string
		for _, v := range strings.Split(value, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			out = append(out, v)
		}
		return out
	}
	type tagFilter struct {
		key   string
		value string
	}
	parseTagFilters := func(value string) []tagFilter {
		parts := parseCSV(value)
		var filters []tagFilter
		for _, p := range parts {
			kv := strings.SplitN(p, "=", 2)
			key := strings.TrimSpace(kv[0])
			if key == "" {
				continue
			}
			filter := tagFilter{key: key}
			if len(kv) == 2 {
				filter.value = strings.TrimSpace(kv[1])
			}
			filters = append(filters, filter)
		}
		return filters
	}
	containsAnyAllowedTag := func(tags []ec2types.Tag, filters []tagFilter) bool {
		for _, f := range filters {
			for _, t := range tags {
				if t.Key == nil || *t.Key != f.key {
					continue
				}
				if f.value == "" {
					return true
				}
				if t.Value != nil && *t.Value == f.value {
					return true
				}
			}
		}
		return false
	}
	loadImagesByID := func(imageIDs []string) (map[string]ec2types.Image, error) {
		out := make(map[string]ec2types.Image)
		seen := make(map[string]bool)
		for _, id := range imageIDs {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
		}
		var ids []string
		for id := range seen {
			ids = append(ids, id)
		}
		for start := 0; start < len(ids); start += 100 {
			end := start + 100
			if end > len(ids) {
				end = len(ids)
			}
			resp, err := d.Clients.EC2.DescribeImages(d.Ctx, &ec2.DescribeImagesInput{ImageIds: ids[start:end]})
			if err != nil {
				return nil, err
			}
			for _, img := range resp.Images {
				if img.ImageId != nil {
					out[*img.ImageId] = img
				}
			}
		}
		return out, nil
	}

	checker.Register(ConfigCheck("approved-amis-by-id", "This rule checks approved amis by id.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			allowed := make(map[string]bool)
			for _, id := range parseCSV(os.Getenv("BPTOOLS_APPROVED_AMI_IDS")) {
				allowed[id] = true
			}
			var res []ConfigResource
			for _, i := range instances {
				id := instanceID(i)
				imageID := ""
				if i.ImageId != nil {
					imageID = *i.ImageId
				}
				if len(allowed) == 0 {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No approved AMI IDs configured (BPTOOLS_APPROVED_AMI_IDS)"})
					continue
				}
				ok := allowed[imageID]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AMI %s approved-by-id: %v", imageID, ok)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("approved-amis-by-tag", "This rule checks approved amis by tag.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			filters := parseTagFilters(os.Getenv("BPTOOLS_APPROVED_AMI_TAGS"))
			if len(filters) == 0 {
				var res []ConfigResource
				for _, i := range instances {
					res = append(res, ConfigResource{ID: instanceID(i), Passing: false, Detail: "No approved AMI tag filters configured (BPTOOLS_APPROVED_AMI_TAGS)"})
				}
				return res, nil
			}
			var imageIDs []string
			for _, i := range instances {
				if i.ImageId != nil {
					imageIDs = append(imageIDs, *i.ImageId)
				}
			}
			imagesByID, err := loadImagesByID(imageIDs)
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, i := range instances {
				id := instanceID(i)
				imageID := ""
				if i.ImageId != nil {
					imageID = *i.ImageId
				}
				img, ok := imagesByID[imageID]
				if !ok {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("AMI metadata not found: %s", imageID)})
					continue
				}
				passing := containsAnyAllowedTag(img.Tags, filters)
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: fmt.Sprintf("AMI %s approved-by-tag: %v", imageID, passing)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-instance-launched-with-allowed-ami", "This rule checks EC2 instance launched with allowed AMI.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			allowedIDs := make(map[string]bool)
			for _, id := range parseCSV(os.Getenv("BPTOOLS_APPROVED_AMI_IDS")) {
				allowedIDs[id] = true
			}
			filters := parseTagFilters(os.Getenv("BPTOOLS_APPROVED_AMI_TAGS"))
			var imageIDs []string
			for _, i := range instances {
				if i.ImageId != nil {
					imageIDs = append(imageIDs, *i.ImageId)
				}
			}
			imagesByID, err := loadImagesByID(imageIDs)
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, i := range instances {
				id := instanceID(i)
				imageID := ""
				if i.ImageId != nil {
					imageID = *i.ImageId
				}
				byID := len(allowedIDs) > 0 && allowedIDs[imageID]
				byTag := false
				if len(filters) > 0 {
					if img, ok := imagesByID[imageID]; ok {
						byTag = containsAnyAllowedTag(img.Tags, filters)
					}
				}
				if len(allowedIDs) == 0 && len(filters) == 0 {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No AMI allowlist configured (BPTOOLS_APPROVED_AMI_IDS or BPTOOLS_APPROVED_AMI_TAGS)"})
					continue
				}
				passing := byID || byTag
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: fmt.Sprintf("AMI %s allowed (by-id=%v by-tag=%v)", imageID, byID, byTag)})
			}
			return res, nil
		}))

	// desired-instance-tenancy + desired-instance-type
	checker.Register(ConfigCheck("desired-instance-tenancy", "This rule checks desired instance tenancy.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			allowed := make(map[string]bool)
			for _, v := range parseCSV(os.Getenv("BPTOOLS_ALLOWED_INSTANCE_TENANCIES")) {
				allowed[strings.ToLower(v)] = true
			}
			var res []ConfigResource
			for _, i := range instances {
				id := instanceID(i)
				tenancy := strings.ToLower(string(i.Placement.Tenancy))
				if tenancy == "" {
					tenancy = "default"
				}
				if len(allowed) == 0 {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No allowed tenancies configured (BPTOOLS_ALLOWED_INSTANCE_TENANCIES)"})
					continue
				}
				ok := allowed[tenancy]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Tenancy=%s allowed=%v", tenancy, ok)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("desired-instance-type", "This rule checks desired instance type.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			allowed := make(map[string]bool)
			for _, v := range parseCSV(os.Getenv("BPTOOLS_ALLOWED_INSTANCE_TYPES")) {
				allowed[strings.ToLower(v)] = true
			}
			var res []ConfigResource
			for _, i := range instances {
				id := instanceID(i)
				itype := strings.ToLower(string(i.InstanceType))
				if len(allowed) == 0 {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No allowed instance types configured (BPTOOLS_ALLOWED_INSTANCE_TYPES)"})
					continue
				}
				ok := allowed[itype]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("InstanceType=%s allowed=%v", itype, ok)})
			}
			return res, nil
		}))

	// ec2-ebs-encryption-by-default
	checker.Register(SingleCheck("ec2-ebs-encryption-by-default", "Check EBS encryption by default", "ec2", d,
		func(d *awsdata.Data) (bool, string, error) {
			enabled, err := d.EC2EBSEncryptionByDefault.Get()
			if err != nil {
				return false, "", err
			}
			return enabled, fmt.Sprintf("EBS encryption by default: %v", enabled), nil
		}))

	// ebs-snapshot-block-public-access
	checker.Register(SingleCheck("ebs-snapshot-block-public-access", "Check snapshot public access blocked", "ec2", d,
		func(d *awsdata.Data) (bool, string, error) {
			state, err := d.EC2EBSSnapshotBlockPublicAccess.Get()
			if err != nil {
				return false, "", err
			}
			blocked := state != "" && state != "unblocked"
			return blocked, fmt.Sprintf("Snapshot block public access: %s", state), nil
		}))

	// encrypted-volumes
	checker.Register(EncryptionCheck("encrypted-volumes", "Check volume encryption", "ec2", d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, v := range volumes {
				id := ""
				if v.VolumeId != nil {
					id = *v.VolumeId
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: v.Encrypted != nil && *v.Encrypted})
			}
			return res, nil
		}))

	// ec2-volume-inuse-check
	checker.Register(ConfigCheck("ec2-volume-inuse-check", "Check volumes in use", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, v := range volumes {
				id := ""
				if v.VolumeId != nil {
					id = *v.VolumeId
				}
				inUse := v.State == ec2types.VolumeStateInUse
				res = append(res, ConfigResource{ID: id, Passing: inUse, Detail: fmt.Sprintf("State: %s", v.State)})
			}
			return res, nil
		}))

	// eip-attached
	checker.Register(ConfigCheck("eip-attached", "Check EIPs attached", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			addrs, err := d.EC2Addresses.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, a := range addrs {
				id := ""
				if a.AllocationId != nil {
					id = *a.AllocationId
				}
				attached := a.AssociationId != nil && *a.AssociationId != ""
				res = append(res, ConfigResource{ID: id, Passing: attached, Detail: fmt.Sprintf("Attached: %v", attached)})
			}
			return res, nil
		}))

	// ebs-snapshot-public-restorable-check
	checker.Register(ConfigCheck("ebs-snapshot-public-restorable-check", "Check snapshots not public", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			snaps, err := d.EC2Snapshots.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range snaps {
				id := ""
				if s.SnapshotId != nil {
					id = *s.SnapshotId
				}
				// Check via DescribeSnapshotAttribute
				attr, err := d.Clients.EC2.DescribeSnapshotAttribute(d.Ctx, &ec2.DescribeSnapshotAttributeInput{
					SnapshotId: s.SnapshotId, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission,
				})
				public := false
				if err == nil {
					for _, p := range attr.CreateVolumePermissions {
						if p.Group == ec2types.PermissionGroupAll {
							public = true
						}
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
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, e := range enis {
				id := ""
				if e.NetworkInterfaceId != nil {
					id = *e.NetworkInterfaceId
				}
				res = append(res, EnabledResource{ID: id, Enabled: e.SourceDestCheck != nil && *e.SourceDestCheck})
			}
			return res, nil
		}))

	// ec2-transit-gateway-auto-vpc-attach-disabled
	checker.Register(ConfigCheck("ec2-transit-gateway-auto-vpc-attach-disabled", "Check TGW auto attach disabled", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tgws, err := d.EC2TransitGateways.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, t := range tgws {
				id := ""
				if t.TransitGatewayId != nil {
					id = *t.TransitGatewayId
				}
				disabled := t.Options != nil && t.Options.AutoAcceptSharedAttachments == ec2types.AutoAcceptSharedAttachmentsValueDisable
				res = append(res, ConfigResource{ID: id, Passing: disabled, Detail: fmt.Sprintf("Auto accept: %v", !disabled)})
			}
			return res, nil
		}))

	// ec2-client-vpn-connection-log-enabled
	checker.Register(EnabledCheck("ec2-client-vpn-connection-log-enabled", "Check client VPN logging", "ec2", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			eps, err := d.EC2ClientVPNEndpoints.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, e := range eps {
				id := ""
				if e.ClientVpnEndpointId != nil {
					id = *e.ClientVpnEndpointId
				}
				enabled := e.ConnectionLogOptions != nil && e.ConnectionLogOptions.Enabled != nil && *e.ConnectionLogOptions.Enabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		}))

	// ec2-client-vpn-not-authorize-all
	checker.Register(ConfigCheck("ec2-client-vpn-not-authorize-all", "Check client VPN auth rules", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			eps, err := d.EC2ClientVPNEndpoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range eps {
				id := ""
				if e.ClientVpnEndpointId != nil {
					id = *e.ClientVpnEndpointId
				}
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
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, v := range vpns {
				id := ""
				if v.VpnConnectionId != nil {
					id = *v.VpnConnectionId
				}
				logged := false
				if v.VgwTelemetry != nil {
					logged = len(v.VgwTelemetry) > 0
				}
				res = append(res, ConfigResource{ID: id, Passing: logged, Detail: "VPN logging check"})
			}
			return res, nil
		}))

	// ec2-launch-template-imdsv2-check + ec2-launch-template-public-ip-disabled + ec2-launch-templates-ebs-volume-encrypted
	checker.Register(&BaseCheck{CheckID: "ec2-launch-template-imdsv2-check", Desc: "Check LT IMDSv2", Svc: "ec2",
		RunFunc: func() []checker.Result {
			lts, err := d.EC2LaunchTemplates.Get()
			if err != nil {
				return []checker.Result{{CheckID: "ec2-launch-template-imdsv2-check", Status: checker.StatusError, Message: err.Error()}}
			}
			var results []checker.Result
			for _, lt := range lts {
				id := ""
				if lt.LaunchTemplateName != nil {
					id = *lt.LaunchTemplateName
				}
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
				if !v2 {
					st = checker.StatusFail
				}
				results = append(results, checker.Result{CheckID: "ec2-launch-template-imdsv2-check", ResourceID: id, Status: st, Message: fmt.Sprintf("IMDSv2: %v", v2)})
			}
			if len(results) == 0 {
				return []checker.Result{{CheckID: "ec2-launch-template-imdsv2-check", Status: checker.StatusSkip, Message: "No launch templates"}}
			}
			return results
		}})

	checker.Register(ConfigCheck("ec2-launch-template-public-ip-disabled", "Check LT no public IP", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lts, err := d.EC2LaunchTemplates.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lt := range lts {
				id := ""
				if lt.LaunchTemplateName != nil {
					id = *lt.LaunchTemplateName
				}
				out, err := d.Clients.EC2.DescribeLaunchTemplateVersions(d.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
					LaunchTemplateId: lt.LaunchTemplateId, Versions: []string{"$Latest"},
				})
				if err != nil || len(out.LaunchTemplateVersions) == 0 {
					continue
				}
				data := out.LaunchTemplateVersions[0].LaunchTemplateData
				disabled := true
				if data != nil {
					for _, ni := range data.NetworkInterfaces {
						if ni.AssociatePublicIpAddress != nil && *ni.AssociatePublicIpAddress {
							disabled = false
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: disabled, Detail: fmt.Sprintf("Public IP disabled: %v", disabled)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-launch-templates-ebs-volume-encrypted", "Check LT EBS encryption", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lts, err := d.EC2LaunchTemplates.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lt := range lts {
				id := ""
				if lt.LaunchTemplateName != nil {
					id = *lt.LaunchTemplateName
				}
				out, err := d.Clients.EC2.DescribeLaunchTemplateVersions(d.Ctx, &ec2.DescribeLaunchTemplateVersionsInput{
					LaunchTemplateId: lt.LaunchTemplateId, Versions: []string{"$Latest"},
				})
				if err != nil || len(out.LaunchTemplateVersions) == 0 {
					continue
				}
				data := out.LaunchTemplateVersions[0].LaunchTemplateData
				encrypted := true
				if data != nil {
					for _, bd := range data.BlockDeviceMappings {
						if bd.Ebs != nil && (bd.Ebs.Encrypted == nil || !*bd.Ebs.Encrypted) {
							encrypted = false
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: encrypted, Detail: fmt.Sprintf("EBS encrypted: %v", encrypted)})
			}
			return res, nil
		}))

	// ec2-spot-fleet-request-ct-encryption-at-rest
	checker.Register(ConfigCheck("ec2-spot-fleet-request-ct-encryption-at-rest", "Check spot fleet encryption", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			ebsDefault, err := d.EC2EBSEncryptionByDefault.Get()
			if err != nil {
				return nil, err
			}
			resolveLaunchTemplateData := func(spec *ec2types.FleetLaunchTemplateSpecification) (*ec2types.ResponseLaunchTemplateData, error) {
				if spec == nil {
					return nil, nil
				}
				version := "$Default"
				if spec.Version != nil && *spec.Version != "" {
					version = *spec.Version
				}
				in := &ec2.DescribeLaunchTemplateVersionsInput{Versions: []string{version}}
				if spec.LaunchTemplateId != nil && *spec.LaunchTemplateId != "" {
					in.LaunchTemplateId = spec.LaunchTemplateId
				} else if spec.LaunchTemplateName != nil && *spec.LaunchTemplateName != "" {
					in.LaunchTemplateName = spec.LaunchTemplateName
				} else {
					return nil, nil
				}
				out, err := d.Clients.EC2.DescribeLaunchTemplateVersions(d.Ctx, in)
				if err != nil {
					return nil, err
				}
				if len(out.LaunchTemplateVersions) == 0 {
					return nil, nil
				}
				return out.LaunchTemplateVersions[0].LaunchTemplateData, nil
			}
			specEncrypted := func(spec ec2types.SpotFleetLaunchSpecification) bool {
				hasEBS := false
				allEncrypted := true
				for _, bdm := range spec.BlockDeviceMappings {
					if bdm.Ebs == nil {
						continue
					}
					hasEBS = true
					if bdm.Ebs.Encrypted == nil || !*bdm.Ebs.Encrypted {
						allEncrypted = false
					}
				}
				if hasEBS {
					return allEncrypted
				}
				return ebsDefault
			}
			ltDataEncrypted := func(data *ec2types.ResponseLaunchTemplateData) bool {
				if data == nil {
					return ebsDefault
				}
				hasEBS := false
				allEncrypted := true
				for _, bdm := range data.BlockDeviceMappings {
					if bdm.Ebs == nil {
						continue
					}
					hasEBS = true
					if bdm.Ebs.Encrypted == nil || !*bdm.Ebs.Encrypted {
						allEncrypted = false
					}
				}
				if hasEBS {
					return allEncrypted
				}
				return ebsDefault
			}
			var next *string
			var requests []ec2types.SpotFleetRequestConfig
			for {
				out, err := d.Clients.EC2.DescribeSpotFleetRequests(d.Ctx, &ec2.DescribeSpotFleetRequestsInput{NextToken: next})
				if err != nil {
					return nil, err
				}
				requests = append(requests, out.SpotFleetRequestConfigs...)
				if out.NextToken == nil || *out.NextToken == "" {
					break
				}
				next = out.NextToken
			}
			var res []ConfigResource
			for _, req := range requests {
				reqID := ""
				if req.SpotFleetRequestId != nil {
					reqID = *req.SpotFleetRequestId
				}
				if req.SpotFleetRequestConfig == nil {
					res = append(res, ConfigResource{ID: reqID, Passing: false, Detail: "Missing spot fleet configuration"})
					continue
				}
				cfg := req.SpotFleetRequestConfig
				passing := true
				detail := "All EBS mappings encrypted"
				for _, spec := range cfg.LaunchSpecifications {
					if !specEncrypted(spec) {
						passing = false
						detail = "Unencrypted EBS block device in launch specification"
						break
					}
				}
				if passing {
					for _, cfgLT := range cfg.LaunchTemplateConfigs {
						data, err := resolveLaunchTemplateData(cfgLT.LaunchTemplateSpecification)
						if err != nil {
							passing = false
							detail = fmt.Sprintf("Cannot inspect launch template: %v", err)
							break
						}
						if !ltDataEncrypted(data) {
							passing = false
							detail = "Unencrypted EBS block device in launch template"
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: reqID, Passing: passing, Detail: detail})
			}
			return res, nil
		}))

	// Tagged checks
	taggedChecks := map[string]func(*awsdata.Data) ([]TaggedResource, error){
		"ec2-capacity-reservation-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2CapacityReservations.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.CapacityReservationId != nil {
					id = *i.CapacityReservationId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-dhcp-options-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2DHCPOptions.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.DhcpOptionsId != nil {
					id = *i.DhcpOptionsId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-fleet-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2Fleets.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.FleetId != nil {
					id = *i.FleetId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-launch-template-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2LaunchTemplates.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.LaunchTemplateName != nil {
					id = *i.LaunchTemplateName
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-prefix-list-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2PrefixLists.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.PrefixListId != nil {
					id = *i.PrefixListId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-client-vpn-endpoint-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2ClientVPNEndpoints.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.ClientVpnEndpointId != nil {
					id = *i.ClientVpnEndpointId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
		"ec2-vpn-connection-tagged": func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.EC2VPNConnections.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, i := range items {
				id := ""
				if i.VpnConnectionId != nil {
					id = *i.VpnConnectionId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(i.Tags)})
			}
			return res, nil
		},
	}
	for id, fn := range taggedChecks {
		checker.Register(TaggedCheck(id, "This rule checks tagging for EC2 resource", "ec2", d, fn))
	}

	checker.Register(TaggedCheck("ec2-carrier-gateway-tagged", "This rule checks tagging for EC2 carrier gateway exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeCarrierGateways(d.Ctx, &ec2.DescribeCarrierGatewaysInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.CarrierGateways {
				id := ""
				if item.CarrierGatewayId != nil {
					id = *item.CarrierGatewayId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-network-insights-access-scope-tagged", "This rule checks tagging for EC2 network insights access scope exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeNetworkInsightsAccessScopes(d.Ctx, &ec2.DescribeNetworkInsightsAccessScopesInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.NetworkInsightsAccessScopes {
				id := ""
				if item.NetworkInsightsAccessScopeId != nil {
					id = *item.NetworkInsightsAccessScopeId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-network-insights-access-scope-analysis-tagged", "This rule checks tagging for EC2 network insights access scope analysis exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeNetworkInsightsAccessScopeAnalyses(d.Ctx, &ec2.DescribeNetworkInsightsAccessScopeAnalysesInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.NetworkInsightsAccessScopeAnalyses {
				id := ""
				if item.NetworkInsightsAccessScopeAnalysisId != nil {
					id = *item.NetworkInsightsAccessScopeAnalysisId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-network-insights-analysis-tagged", "This rule checks tagging for EC2 network insights analysis exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeNetworkInsightsAnalyses(d.Ctx, &ec2.DescribeNetworkInsightsAnalysesInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.NetworkInsightsAnalyses {
				id := ""
				if item.NetworkInsightsAnalysisId != nil {
					id = *item.NetworkInsightsAnalysisId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-network-insights-path-tagged", "This rule checks tagging for EC2 network insights path exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeNetworkInsightsPaths(d.Ctx, &ec2.DescribeNetworkInsightsPathsInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.NetworkInsightsPaths {
				id := ""
				if item.NetworkInsightsPathId != nil {
					id = *item.NetworkInsightsPathId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-traffic-mirror-filter-tagged", "This rule checks tagging for EC2 traffic mirror filter exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeTrafficMirrorFilters(d.Ctx, &ec2.DescribeTrafficMirrorFiltersInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.TrafficMirrorFilters {
				id := ""
				if item.TrafficMirrorFilterId != nil {
					id = *item.TrafficMirrorFilterId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-traffic-mirror-session-tagged", "This rule checks tagging for EC2 traffic mirror session exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeTrafficMirrorSessions(d.Ctx, &ec2.DescribeTrafficMirrorSessionsInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.TrafficMirrorSessions {
				id := ""
				if item.TrafficMirrorSessionId != nil {
					id = *item.TrafficMirrorSessionId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-traffic-mirror-target-tagged", "This rule checks tagging for EC2 traffic mirror target exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeTrafficMirrorTargets(d.Ctx, &ec2.DescribeTrafficMirrorTargetsInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.TrafficMirrorTargets {
				id := ""
				if item.TrafficMirrorTargetId != nil {
					id = *item.TrafficMirrorTargetId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(TaggedCheck("ec2-transit-gateway-multicast-domain-tagged", "This rule checks tagging for EC2 transit gateway multicast domain exist.", "ec2", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			out, err := d.Clients.EC2.DescribeTransitGatewayMulticastDomains(d.Ctx, &ec2.DescribeTransitGatewayMulticastDomainsInput{})
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, item := range out.TransitGatewayMulticastDomains {
				id := ""
				if item.TransitGatewayMulticastDomainId != nil {
					id = *item.TransitGatewayMulticastDomainId
				}
				res = append(res, TaggedResource{ID: id, Tags: ec2TagsToMap(item.Tags)})
			}
			return res, nil
		}))

	checker.Register(DescriptionCheck("ec2-traffic-mirror-filter-description", "This rule checks descriptions for EC2 traffic mirror filter exist.", "ec2", d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			out, err := d.Clients.EC2.DescribeTrafficMirrorFilters(d.Ctx, &ec2.DescribeTrafficMirrorFiltersInput{})
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, item := range out.TrafficMirrorFilters {
				id := ""
				if item.TrafficMirrorFilterId != nil {
					id = *item.TrafficMirrorFilterId
				}
				res = append(res, DescriptionResource{ID: id, Description: item.Description, HasDescription: item.Description != nil && *item.Description != ""})
			}
			return res, nil
		}))

	checker.Register(DescriptionCheck("ec2-traffic-mirror-session-description", "This rule checks descriptions for EC2 traffic mirror session exist.", "ec2", d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			out, err := d.Clients.EC2.DescribeTrafficMirrorSessions(d.Ctx, &ec2.DescribeTrafficMirrorSessionsInput{})
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, item := range out.TrafficMirrorSessions {
				id := ""
				if item.TrafficMirrorSessionId != nil {
					id = *item.TrafficMirrorSessionId
				}
				res = append(res, DescriptionResource{ID: id, Description: item.Description, HasDescription: item.Description != nil && *item.Description != ""})
			}
			return res, nil
		}))

	checker.Register(DescriptionCheck("ec2-traffic-mirror-target-description", "This rule checks descriptions for EC2 traffic mirror target exist.", "ec2", d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			out, err := d.Clients.EC2.DescribeTrafficMirrorTargets(d.Ctx, &ec2.DescribeTrafficMirrorTargetsInput{})
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, item := range out.TrafficMirrorTargets {
				id := ""
				if item.TrafficMirrorTargetId != nil {
					id = *item.TrafficMirrorTargetId
				}
				res = append(res, DescriptionResource{ID: id, Description: item.Description, HasDescription: item.Description != nil && *item.Description != ""})
			}
			return res, nil
		}))

	// Security group checks
	checker.Register(ConfigCheck("ec2-security-group-attached-to-eni", "Check SG attached to ENI", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			enis, err := d.EC2NetworkInterfaces.Get()
			if err != nil {
				return nil, err
			}
			usedSGs := make(map[string]bool)
			for _, e := range enis {
				for _, g := range e.Groups {
					if g.GroupId != nil {
						usedSGs[*g.GroupId] = true
					}
				}
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := ""
				if sg.GroupId != nil {
					id = *sg.GroupId
				}
				res = append(res, ConfigResource{ID: id, Passing: usedSGs[id], Detail: fmt.Sprintf("Attached: %v", usedSGs[id])})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-security-group-attached-to-eni-periodic", "Check SG attached to ENI (periodic)", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			enis, err := d.EC2NetworkInterfaces.Get()
			if err != nil {
				return nil, err
			}
			usedSGs := make(map[string]bool)
			for _, e := range enis {
				for _, g := range e.Groups {
					if g.GroupId != nil {
						usedSGs[*g.GroupId] = true
					}
				}
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := ""
				if sg.GroupId != nil {
					id = *sg.GroupId
				}
				res = append(res, ConfigResource{ID: id, Passing: usedSGs[id], Detail: fmt.Sprintf("Attached: %v", usedSGs[id])})
			}
			return res, nil
		}))

	loadManagedInstances := func() ([]ssmtypes.InstanceInformation, error) {
		var out []ssmtypes.InstanceInformation
		var next *string
		for {
			resp, err := d.Clients.SSM.DescribeInstanceInformation(d.Ctx, &ssm.DescribeInstanceInformationInput{NextToken: next})
			if err != nil {
				return nil, err
			}
			out = append(out, resp.InstanceInformationList...)
			if resp.NextToken == nil || *resp.NextToken == "" {
				break
			}
			next = resp.NextToken
		}
		return out, nil
	}

	loadInventoryByType := func(typeName string) (map[string][]map[string]string, error) {
		var next *string
		out := make(map[string][]map[string]string)
		for {
			resp, err := d.Clients.SSM.GetInventory(d.Ctx, &ssm.GetInventoryInput{
				NextToken: next,
				ResultAttributes: []ssmtypes.ResultAttribute{
					{TypeName: aws.String(typeName)},
				},
			})
			if err != nil {
				return nil, err
			}
			for _, ent := range resp.Entities {
				if ent.Id == nil {
					continue
				}
				item, ok := ent.Data[typeName]
				if !ok {
					continue
				}
				out[*ent.Id] = append(out[*ent.Id], item.Content...)
			}
			if resp.NextToken == nil || *resp.NextToken == "" {
				break
			}
			next = resp.NextToken
		}
		return out, nil
	}

	checker.Register(ConfigCheck("ec2-managedinstance-platform-check", "This rule checks configuration for EC2 managedinstance platform.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, info := range infos {
				id := ""
				if info.InstanceId != nil {
					id = *info.InstanceId
				}
				pt := string(info.PlatformType)
				ok := info.PlatformType == ssmtypes.PlatformTypeLinux || info.PlatformType == ssmtypes.PlatformTypeWindows || info.PlatformType == ssmtypes.PlatformTypeMacos
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("PlatformType: %s", pt)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-managedinstance-association-compliance-status-check", "This rule checks configuration for EC2 managedinstance association compliance status.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, info := range infos {
				id := ""
				if info.InstanceId != nil {
					id = *info.InstanceId
				}
				status := ""
				if info.AssociationStatus != nil {
					status = *info.AssociationStatus
				}
				ok := strings.EqualFold(status, "Success")
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AssociationStatus: %s", status)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-managedinstance-patch-compliance-status-check", "This rule checks configuration for EC2 managedinstance patch compliance status.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			var ids []string
			for _, info := range infos {
				if info.InstanceId != nil {
					ids = append(ids, *info.InstanceId)
				}
			}
			if len(ids) == 0 {
				return []ConfigResource{}, nil
			}
			states := make(map[string]ssmtypes.InstancePatchState)
			for start := 0; start < len(ids); start += 50 {
				end := start + 50
				if end > len(ids) {
					end = len(ids)
				}
				out, err := d.Clients.SSM.DescribeInstancePatchStates(d.Ctx, &ssm.DescribeInstancePatchStatesInput{InstanceIds: ids[start:end]})
				if err != nil {
					return nil, err
				}
				for _, st := range out.InstancePatchStates {
					if st.InstanceId != nil {
						states[*st.InstanceId] = st
					}
				}
			}
			var res []ConfigResource
			for _, id := range ids {
				state, ok := states[id]
				if !ok {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No patch state available"})
					continue
				}
				pendingReboot := state.InstalledPendingRebootCount != nil && *state.InstalledPendingRebootCount > 0
				passing := state.MissingCount == 0 && state.FailedCount == 0 && !pendingReboot
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: fmt.Sprintf("Missing=%d Failed=%d PendingReboot=%v", state.MissingCount, state.FailedCount, pendingReboot)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-managedinstance-applications-required", "This rule checks EC2 managedinstance applications required.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			apps, err := loadInventoryByType("AWS:Application")
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, info := range infos {
				if info.InstanceId == nil {
					continue
				}
				id := *info.InstanceId
				count := len(apps[id])
				res = append(res, ConfigResource{ID: id, Passing: count > 0, Detail: fmt.Sprintf("Discovered applications: %d", count)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-managedinstance-applications-blacklisted", "This rule checks EC2 managedinstance applications blacklisted.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			apps, err := loadInventoryByType("AWS:Application")
			if err != nil {
				return nil, err
			}
			blacklisted := []string{"telnet", "rsh", "rlogin", "vsftpd", "wu-ftp"}
			var res []ConfigResource
			for _, info := range infos {
				if info.InstanceId == nil {
					continue
				}
				id := *info.InstanceId
				found := ""
				for _, app := range apps[id] {
					name := strings.ToLower(app["Name"])
					pkg := strings.ToLower(app["PackageId"])
					for _, bad := range blacklisted {
						if strings.Contains(name, bad) || strings.Contains(pkg, bad) {
							found = bad
							break
						}
					}
					if found != "" {
						break
					}
				}
				passing := found == ""
				detail := "No blacklisted applications detected"
				if !passing {
					detail = fmt.Sprintf("Blacklisted application detected: %s", found)
				}
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-managedinstance-inventory-blacklisted", "This rule checks EC2 managedinstance inventory blacklisted.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			apps, err := loadInventoryByType("AWS:Application")
			if err != nil {
				return nil, err
			}
			comps, err := loadInventoryByType("AWS:AWSComponent")
			if err != nil {
				return nil, err
			}
			blacklisted := []string{"telnet", "rsh", "rlogin", "ftp"}
			var res []ConfigResource
			for _, info := range infos {
				if info.InstanceId == nil {
					continue
				}
				id := *info.InstanceId
				found := ""
				checkItems := append([]map[string]string{}, apps[id]...)
				checkItems = append(checkItems, comps[id]...)
				for _, item := range checkItems {
					for _, value := range item {
						lv := strings.ToLower(value)
						for _, bad := range blacklisted {
							if strings.Contains(lv, bad) {
								found = bad
								break
							}
						}
						if found != "" {
							break
						}
					}
					if found != "" {
						break
					}
				}
				passing := found == ""
				detail := "No blacklisted inventory items detected"
				if !passing {
					detail = fmt.Sprintf("Blacklisted inventory content detected: %s", found)
				}
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: detail})
			}
			return res, nil
		}))

	buildEC2InstanceARN := func(region, account, instanceID string) string {
		return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, account, instanceID)
	}
	buildEBSVolumeARN := func(region, account, volumeID string) string {
		return fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", region, account, volumeID)
	}

	loadBackupState := func() (map[string]bool, map[string]time.Time, map[string]bool, error) {
		protected, err := d.BackupProtectedResources.Get()
		if err != nil {
			return nil, nil, nil, err
		}
		vaults, err := d.BackupVaultLockConfigs.Get()
		if err != nil {
			return nil, nil, nil, err
		}
		isProtected := make(map[string]bool)
		lastBackup := make(map[string]time.Time)
		inProtectedVault := make(map[string]bool)
		for arn, resource := range protected {
			isProtected[arn] = true
			if resource.LastBackupTime != nil {
				lastBackup[arn] = *resource.LastBackupTime
			}
			vaultProtected := false
			if resource.LastBackupVaultArn != nil {
				parts := strings.Split(*resource.LastBackupVaultArn, ":")
				if len(parts) > 0 {
					name := parts[len(parts)-1]
					name = strings.TrimPrefix(name, "backup-vault/")
					if vault, ok := vaults[name]; ok {
						if vault.Locked != nil && *vault.Locked {
							vaultProtected = true
						}
						if strings.Contains(strings.ToUpper(string(vault.VaultType)), "LOGICALLY_AIR_GAPPED") {
							vaultProtected = true
						}
					}
				}
			}
			inProtectedVault[arn] = vaultProtected
		}
		return isProtected, lastBackup, inProtectedVault, nil
	}

	checker.Register(ConfigCheck("ec2-resources-protected-by-backup-plan", "This rule checks EC2 resources protected by backup plan.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			isProtected, _, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, instance := range instances {
				id := instanceID(instance)
				arn := buildEC2InstanceARN(region, accountID, id)
				res = append(res, ConfigResource{ID: id, Passing: isProtected[arn], Detail: fmt.Sprintf("Protected by backup plan: %v", isProtected[arn])})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-last-backup-recovery-point-created", "This rule checks EC2 last backup recovery point created.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			_, lastBackup, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, instance := range instances {
				id := instanceID(instance)
				arn := buildEC2InstanceARN(region, accountID, id)
				t, ok := lastBackup[arn]
				detail := "No recovery point found"
				if ok {
					detail = fmt.Sprintf("Last backup: %s", t.Format(time.RFC3339))
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-meets-restore-time-target", "This rule checks EC2 meets restore time target.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			_, lastBackup, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			target := 24 * time.Hour
			var res []ConfigResource
			for _, instance := range instances {
				id := instanceID(instance)
				arn := buildEC2InstanceARN(region, accountID, id)
				t, ok := lastBackup[arn]
				passing := ok && time.Since(t) <= target
				detail := "No recent backup found"
				if ok {
					detail = fmt.Sprintf("Backup age: %s", time.Since(t).Round(time.Minute))
				}
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-resources-in-logically-air-gapped-vault", "This rule checks EC2 resources in logically air gapped vault.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			_, _, inProtectedVault, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, instance := range instances {
				id := instanceID(instance)
				arn := buildEC2InstanceARN(region, accountID, id)
				res = append(res, ConfigResource{ID: id, Passing: inProtectedVault[arn], Detail: fmt.Sprintf("In locked/air-gapped vault: %v", inProtectedVault[arn])})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ebs-in-backup-plan", "This rule checks ebs in backup plan.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			isProtected, _, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, volume := range volumes {
				if volume.VolumeId == nil {
					continue
				}
				id := *volume.VolumeId
				arn := buildEBSVolumeARN(region, accountID, id)
				res = append(res, ConfigResource{ID: id, Passing: isProtected[arn], Detail: fmt.Sprintf("Protected by backup plan: %v", isProtected[arn])})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ebs-resources-protected-by-backup-plan", "This rule checks ebs resources protected by backup plan.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			isProtected, _, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, volume := range volumes {
				if volume.VolumeId == nil {
					continue
				}
				id := *volume.VolumeId
				arn := buildEBSVolumeARN(region, accountID, id)
				res = append(res, ConfigResource{ID: id, Passing: isProtected[arn], Detail: fmt.Sprintf("Protected by backup plan: %v", isProtected[arn])})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ebs-last-backup-recovery-point-created", "This rule checks ebs last backup recovery point created.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			_, lastBackup, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, volume := range volumes {
				if volume.VolumeId == nil {
					continue
				}
				id := *volume.VolumeId
				arn := buildEBSVolumeARN(region, accountID, id)
				t, ok := lastBackup[arn]
				detail := "No recovery point found"
				if ok {
					detail = fmt.Sprintf("Last backup: %s", t.Format(time.RFC3339))
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ebs-meets-restore-time-target", "This rule checks ebs meets restore time target.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			_, lastBackup, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			target := 24 * time.Hour
			var res []ConfigResource
			for _, volume := range volumes {
				if volume.VolumeId == nil {
					continue
				}
				id := *volume.VolumeId
				arn := buildEBSVolumeARN(region, accountID, id)
				t, ok := lastBackup[arn]
				passing := ok && time.Since(t) <= target
				detail := "No recent backup found"
				if ok {
					detail = fmt.Sprintf("Backup age: %s", time.Since(t).Round(time.Minute))
				}
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ebs-resources-in-logically-air-gapped-vault", "This rule checks ebs resources in logically air gapped vault.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			volumes, err := d.EC2Volumes.Get()
			if err != nil {
				return nil, err
			}
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			region := d.Clients.EC2.Options().Region
			_, _, inProtectedVault, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, volume := range volumes {
				if volume.VolumeId == nil {
					continue
				}
				id := *volume.VolumeId
				arn := buildEBSVolumeARN(region, accountID, id)
				res = append(res, ConfigResource{ID: id, Passing: inProtectedVault[arn], Detail: fmt.Sprintf("In locked/air-gapped vault: %v", inProtectedVault[arn])})
			}
			return res, nil
		}))

	// ECR checks
	checker.Register(TaggedCheck("ecr-repository-tagged", "Check ECR repo tagged", "ecr", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil {
					id = *r.RepositoryName
				}
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
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil {
					id = *r.RepositoryName
				}
				enabled := r.ImageScanningConfiguration != nil && r.ImageScanningConfiguration.ScanOnPush
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		}))

	checker.Register(EnabledCheck("ecr-private-tag-immutability-enabled", "Check ECR tag immutability", "ecr", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil {
					id = *r.RepositoryName
				}
				res = append(res, EnabledResource{ID: id, Enabled: r.ImageTagMutability == "IMMUTABLE"})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ecr-private-lifecycle-policy-configured", "Check ECR lifecycle policy", "ecr", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil {
					id = *r.RepositoryName
				}
				_, err := d.Clients.ECR.GetLifecyclePolicy(d.Ctx, nil)
				configured := err == nil
				res = append(res, ConfigResource{ID: id, Passing: configured, Detail: fmt.Sprintf("Lifecycle policy: %v", configured)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ecr-repository-cmk-encryption-enabled", "Check ECR CMK encryption", "ecr", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			repos, err := d.ECRRepositories.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, r := range repos {
				id := ""
				if r.RepositoryName != nil {
					id = *r.RepositoryName
				}
				cmk := r.EncryptionConfiguration != nil && strings.EqualFold(string(r.EncryptionConfiguration.EncryptionType), "KMS")
				res = append(res, ConfigResource{ID: id, Passing: cmk, Detail: fmt.Sprintf("CMK encryption: %v", cmk)})
			}
			return res, nil
		}))

	_ = ec2types.InstanceTypeA1Large
}
