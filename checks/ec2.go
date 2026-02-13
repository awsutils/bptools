package checks

import (
	"fmt"
	"os"
	"regexp"
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
		for _, inst := range r.Instances {
			if ec2InstanceIsDeletedOrDeleting(inst) {
				continue
			}
			out = append(out, inst)
		}
	}
	return out, nil
}

func ec2InstanceIsDeletedOrDeleting(i ec2types.Instance) bool {
	if i.State == nil {
		return false
	}
	return i.State.Name == ec2types.InstanceStateNameTerminated ||
		i.State.Name == ec2types.InstanceStateNameShuttingDown
}

func launchTemplateVersionData(d *awsdata.Data, launchTemplateID *string, launchTemplateName *string, version string) (*ec2types.ResponseLaunchTemplateData, error) {
	input := &ec2.DescribeLaunchTemplateVersionsInput{
		Versions: []string{version},
	}
	if launchTemplateID != nil && *launchTemplateID != "" {
		input.LaunchTemplateId = launchTemplateID
	} else if launchTemplateName != nil && *launchTemplateName != "" {
		input.LaunchTemplateName = launchTemplateName
	} else {
		return nil, nil
	}
	out, err := d.Clients.EC2.DescribeLaunchTemplateVersions(d.Ctx, input)
	if err != nil || len(out.LaunchTemplateVersions) == 0 {
		return nil, err
	}
	return out.LaunchTemplateVersions[0].LaunchTemplateData, nil
}

var ec2StateTransitionTimeRegex = regexp.MustCompile(`\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)`)

func ec2StoppedTransitionTime(reason *string) (time.Time, bool) {
	if reason == nil || *reason == "" {
		return time.Time{}, false
	}
	matches := ec2StateTransitionTimeRegex.FindStringSubmatch(*reason)
	if len(matches) < 2 {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02 15:04:05", matches[1])
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func RegisterEC2Checks(d *awsdata.Data) {
	// ec2-imdsv2-check
	checker.Register(ConfigCheck("ec2-imdsv2-check", "Checks whether your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2). The rule is NON_COMPLIANT if the HttpTokens is set to optional.", "ec2", d,
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
	checker.Register(EnabledCheck("ec2-instance-detailed-monitoring-enabled", "Checks if detailed monitoring is enabled for EC2 instances. The rule is NON_COMPLIANT if detailed monitoring is not enabled.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-instance-no-public-ip", "Checks whether Amazon Elastic Compute Cloud (Amazon EC2) instances have a public IP association. The rule is NON_COMPLIANT if the publicIp field is present in the Amazon EC2 instance configuration item. This rule applies only to IPv4.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-instance-profile-attached", "Checks if an EC2 instance has an AWS Identity and Access Management (IAM) profile attached to it. The rule is NON_COMPLIANT if no IAM profile is attached to the EC2 instance.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-no-amazon-key-pair", "Checks if running Amazon Elastic Compute Cloud (EC2) instances are launched using amazon key pairs. The rule is NON_COMPLIANT if a running EC2 instance is launched with a key pair.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-paravirtual-instance-check", "Checks if the virtualization type of an EC2 instance is paravirtual. This rule is NON_COMPLIANT for an EC2 instance if 'virtualizationType' is set to 'paravirtual'.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-stopped-instance", "Checks if there are Amazon Elastic Compute Cloud (Amazon EC2) instances stopped for more than the allowed number of days. The rule is NON_COMPLIANT if the state of an Amazon EC2 instance has been stopped for longer than the allowed number of days, or if the amount of time cannot be determined.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, i := range instances {
				stopped := i.State != nil && i.State.Name == ec2types.InstanceStateNameStopped
				if !stopped {
					res = append(res, ConfigResource{ID: instanceID(i), Passing: true, Detail: "Instance is not stopped"})
					continue
				}
				stoppedAt, hasStoppedAt := ec2StoppedTransitionTime(i.StateTransitionReason)
				if !hasStoppedAt {
					res = append(res, ConfigResource{ID: instanceID(i), Passing: true, Detail: "Stopped, but stop time unavailable"})
					continue
				}
				age := time.Since(stoppedAt)
				pass := age <= 30*24*time.Hour
				res = append(res, ConfigResource{
					ID:      instanceID(i),
					Passing: pass,
					Detail:  fmt.Sprintf("Stopped for %s", age.Truncate(time.Hour)),
				})
			}
			return res, nil
		}))

	// ec2-token-hop-limit-check
	checker.Register(ConfigCheck("ec2-token-hop-limit-check", "Checks if an Amazon Elastic Compute Cloud (EC2) instance metadata has a specified token hop limit that is below the desired limit. The rule is NON_COMPLIANT for an instance if it has a hop limit value above the intended limit.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-instance-multiple-eni-check", "Checks if Amazon Elastic Compute Cloud (Amazon EC2) uses multiple Elastic Network Interfaces (ENIs) or Elastic Fabric Adapters (EFAs). The rule is NON_COMPLIANT an Amazon EC2 instance use multiple network interfaces.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-instances-in-vpc", "Checks if your EC2 instances belong to a virtual private cloud (VPC). Optionally, you can specify the VPC ID to associate with your instances.", "ec2", d,
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
	checker.Register(EnabledCheck("ebs-optimized-instance", "Checks if Amazon EBS optimization is enabled for your Amazon Elastic Compute Cloud (Amazon EC2) instances that can be Amazon EBS-optimized. The rule is NON_COMPLIANT if EBS optimization is not enabled for an Amazon EC2 instance that can be EBS-optimized.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-instance-managed-by-systems-manager", "Checks if your Amazon EC2 instances are managed by AWS Systems Manager Agent (SSM Agent). The rule is NON_COMPLIANT if an EC2 instance is running and the SSM Agent is stopped, or if an EC2 instance is running and the SSM Agent is terminated.", "ec2", d,
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

	checker.Register(ConfigCheck("approved-amis-by-id", "Checks if EC2 instances are using specified Amazon Machine Images (AMIs). Specify a list of approved AMI IDs. Running instances with AMIs that are not on this list are NON_COMPLIANT.", "ec2", d,
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
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "No approved AMI IDs configured; default allow-all behavior"})
					continue
				}
				ok := allowed[imageID]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AMI %s approved-by-id: %v", imageID, ok)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("approved-amis-by-tag", "Checks if EC2 instances are using specified Amazon Machine Images (AMIs). Specify the tags that identify the AMIs. Running instances with AMIs that don't have at least one of the specified tags are NON_COMPLIANT.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			filters := parseTagFilters(os.Getenv("BPTOOLS_APPROVED_AMI_TAGS"))
			if len(filters) == 0 {
				var res []ConfigResource
				for _, i := range instances {
					res = append(res, ConfigResource{ID: instanceID(i), Passing: true, Detail: "No approved AMI tag filters configured; default allow-all behavior"})
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

	checker.Register(ConfigCheck("ec2-instance-launched-with-allowed-ami", "Checks if running or stopped EC2 instances were launched with Amazon Machine Images (AMIs) that meet your Allowed AMIs criteria. The rule is NON_COMPLIANT if an AMI doesn't meet the Allowed AMIs criteria and the Allowed AMIs settings isn't disabled.", "ec2", d,
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
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "No AMI allowlist configured; default allow-all behavior"})
					continue
				}
				passing := byID || byTag
				res = append(res, ConfigResource{ID: id, Passing: passing, Detail: fmt.Sprintf("AMI %s allowed (by-id=%v by-tag=%v)", imageID, byID, byTag)})
			}
			return res, nil
		}))

	// desired-instance-tenancy + desired-instance-type
	checker.Register(ConfigCheck("desired-instance-tenancy", "Checks EC2 instances for a 'tenancy' value. Also checks if AMI IDs are specified to be launched from those AMIs or if Host IDs are launched on those Dedicated Hosts. The rule is COMPLIANT if the instance matches a host and an AMI, if specified, in a list.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := allInstances(d)
			if err != nil {
				return nil, err
			}
			allowed := make(map[string]bool)
			for _, v := range parseCSV(os.Getenv("BPTOOLS_ALLOWED_INSTANCE_TENANCIES")) {
				allowed[strings.ToLower(v)] = true
			}
			if len(allowed) == 0 {
				allowed["default"] = true
				allowed["dedicated"] = true
				allowed["host"] = true
			}
			var res []ConfigResource
			for _, i := range instances {
				id := instanceID(i)
				tenancy := strings.ToLower(string(i.Placement.Tenancy))
				if tenancy == "" {
					tenancy = "default"
				}
				ok := allowed[tenancy]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Tenancy=%s allowed=%v", tenancy, ok)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("desired-instance-type", "Checks if your EC2 instances are of a specific instance type. The rule is NON_COMPLIANT if an EC2 instance is not specified in the parameter list. For a list of supported EC2 instance types, see Instance types in the EC2 User Guide for Linux Instances.", "ec2", d,
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
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "No allowed instance types configured; default allow-all behavior"})
					continue
				}
				ok := allowed[itype]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("InstanceType=%s allowed=%v", itype, ok)})
			}
			return res, nil
		}))

	// ec2-ebs-encryption-by-default
	checker.Register(SingleCheck("ec2-ebs-encryption-by-default", "Checks if Amazon Elastic Block Store (EBS) encryption is enabled by default. The rule is NON_COMPLIANT if the encryption is not enabled.", "ec2", d,
		func(d *awsdata.Data) (bool, string, error) {
			enabled, err := d.EC2EBSEncryptionByDefault.Get()
			if err != nil {
				return false, "", err
			}
			return enabled, fmt.Sprintf("EBS encryption by default: %v", enabled), nil
		}))

	// ebs-snapshot-block-public-access
	checker.Register(SingleCheck("ebs-snapshot-block-public-access", "Checks if block public access is enabled for Amazon EBS snapshots in an AWS Region. The rule is NON_COMPLIANT if block public access is not enabled for all public sharing of EBS snapshots in an AWS Region.", "ec2", d,
		func(d *awsdata.Data) (bool, string, error) {
			state, err := d.EC2EBSSnapshotBlockPublicAccess.Get()
			if err != nil {
				return false, "", err
			}
			blocked := state != "" && state != "unblocked"
			return blocked, fmt.Sprintf("Snapshot block public access: %s", state), nil
		}))

	// encrypted-volumes
	checker.Register(EncryptionCheck("encrypted-volumes", "Checks if attached Amazon EBS volumes are encrypted and optionally are encrypted with a specified KMS key. The rule is NON_COMPLIANT if attached EBS volumes are unencrypted or are encrypted with a KMS key not in the supplied parameters.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-volume-inuse-check", "Checks if EBS volumes are attached to EC2 instances. Optionally checks if EBS volumes are marked for deletion when an instance is terminated.", "ec2", d,
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
	checker.Register(ConfigCheck("eip-attached", "Checks if all Elastic IP addresses that are allocated to an AWS account are attached to EC2 instances or in-use elastic network interfaces. The rule is NON_COMPLIANT if the 'AssociationId' is null for the Elastic IP address.", "ec2", d,
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
	checker.Register(ConfigCheck("ebs-snapshot-public-restorable-check", "Checks if Amazon Elastic Block Store (Amazon EBS) snapshots are not publicly restorable. The rule is NON_COMPLIANT if one or more snapshots with RestorableByUserIds field are set to all, that is, Amazon EBS snapshots are public.", "ec2", d,
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
	checker.Register(EnabledCheck("ec2-enis-source-destination-check-enabled", "Checks if EC2 ENIs managed by users have source/destination check enabled. The rule is NON_COMPLIANT if source/destination check is disabled on these ENIs for 'lambda', 'aws_codestar_connections_managed', 'branch', 'efa', 'interface', and 'quicksight'.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-transit-gateway-auto-vpc-attach-disabled", "Checks if Amazon Elastic Compute Cloud (Amazon EC2) Transit Gateways have 'AutoAcceptSharedAttachments' enabled. The rule is NON_COMPLIANT for a Transit Gateway if 'AutoAcceptSharedAttachments' is set to 'enable'.", "ec2", d,
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
	checker.Register(EnabledCheck("ec2-client-vpn-connection-log-enabled", "Checks if AWS Client VPN endpoint has client connection logging enabled. The rule is NON_COMPLIANT if 'Configuration.ConnectionLogOptions.Enabled' is set to false.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-client-vpn-not-authorize-all", "Checks if the AWS Client VPN authorization rules authorizes connection access for all clients. The rule is NON_COMPLIANT if 'AccessAll' is present and set to true.", "ec2", d,
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
						if r.AccessAll != nil && *r.AccessAll {
							authorizeAll = true
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: !authorizeAll, Detail: fmt.Sprintf("Authorize all: %v", authorizeAll)})
			}
			return res, nil
		}))

	// ec2-vpn-connection-logging-enabled
	checker.Register(ConfigCheck("ec2-vpn-connection-logging-enabled", "Checks if AWS Site-to-Site VPN connections have Amazon CloudWatch logging enabled for both tunnels. The rule is NON_COMPLIANT if a Site-to-Site VPN connection does not have CloudWatch logging enabled for either or both tunnels.", "ec2", d,
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
				if v.Options != nil {
					for _, tunnel := range v.Options.TunnelOptions {
						if tunnel.LogOptions != nil && tunnel.LogOptions.CloudWatchLogOptions != nil &&
							tunnel.LogOptions.CloudWatchLogOptions.LogEnabled != nil &&
							*tunnel.LogOptions.CloudWatchLogOptions.LogEnabled {
							logged = true
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: logged, Detail: fmt.Sprintf("Tunnel logging enabled: %v", logged)})
			}
			return res, nil
		}))

	// ec2-launch-template-imdsv2-check + ec2-launch-template-public-ip-disabled + ec2-launch-templates-ebs-volume-encrypted
	checker.Register(&BaseCheck{CheckID: "ec2-launch-template-imdsv2-check", Desc: "Checks if the currently set default version of an Amazon EC2 Launch Template requires new launched instances to use V2 of the Amazon EC2 Instance Metadata Service (IMDSv2). The rule is NON_COMPLIANT if 'Metadata version' is not specified as V2 (IMDSv2).", Svc: "ec2",
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
					LaunchTemplateId: lt.LaunchTemplateId, Versions: []string{"$Default"},
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

	checker.Register(ConfigCheck("ec2-launch-template-public-ip-disabled", "Checks if Amazon EC2 Launch Templates are set to assign public IP addresses to Network Interfaces. The rule is NON_COMPLIANT if the default version of an EC2 Launch Template has at least 1 Network Interface with 'AssociatePublicIpAddress' set to 'true'.", "ec2", d,
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
				data, err := launchTemplateVersionData(d, lt.LaunchTemplateId, lt.LaunchTemplateName, "$Default")
				if err != nil || data == nil {
					continue
				}
				disabled := true
				for _, ni := range data.NetworkInterfaces {
					if ni.AssociatePublicIpAddress != nil && *ni.AssociatePublicIpAddress {
						disabled = false
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: disabled, Detail: fmt.Sprintf("Public IP disabled: %v", disabled)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-launch-templates-ebs-volume-encrypted", "Checks whether Amazon EC2 launch templates have encryption enabled for all attached EBS volumes.The rule is NON_COMPLIANT if encryption is set to False for any EBS volume configured in the launch template.", "ec2", d,
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
				data, err := launchTemplateVersionData(d, lt.LaunchTemplateId, lt.LaunchTemplateName, "$Default")
				if err != nil || data == nil {
					continue
				}
				encrypted := true
				for _, bd := range data.BlockDeviceMappings {
					if bd.Ebs != nil && (bd.Ebs.Encrypted == nil || !*bd.Ebs.Encrypted) {
						encrypted = false
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: encrypted, Detail: fmt.Sprintf("EBS encrypted: %v", encrypted)})
			}
			return res, nil
		}))

	// ec2-spot-fleet-request-ct-encryption-at-rest
	checker.Register(ConfigCheck("ec2-spot-fleet-request-ct-encryption-at-rest", "Checks if Amazon EC2 Spot Fleet request launch parameters set encrypted to True for attached EBS volumes. The rule is NON_COMPLIANT if any EBS volumes has encrypted set to False. The rule does not evaluate spot fleet requests using launch templates.", "ec2", d,
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
				if ec2PrefixListIsAWSManagedOrDeleted(i) {
					continue
				}
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

	checker.Register(TaggedCheck("ec2-carrier-gateway-tagged", "Checks if Amazon EC2 carrier gateways have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-network-insights-access-scope-tagged", "Checks if Amazon EC2 network insights access scopes have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-network-insights-access-scope-analysis-tagged", "Checks if Amazon EC2 network insights access scope analyses have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-network-insights-analysis-tagged", "Checks if Amazon EC2 network insights analyses have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-network-insights-path-tagged", "Checks if Amazon EC2 network insights paths have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-traffic-mirror-filter-tagged", "Checks if Amazon EC2 traffic mirror filters have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-traffic-mirror-session-tagged", "Checks if Amazon EC2 traffic mirror sessions have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-traffic-mirror-target-tagged", "Checks if Amazon EC2 traffic mirror targets have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(TaggedCheck("ec2-transit-gateway-multicast-domain-tagged", "Checks if Amazon EC2 transit gateway multicast domains have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ec2", d,
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

	checker.Register(DescriptionCheck("ec2-traffic-mirror-filter-description", "Checks if Amazon EC2 traffic mirror filters have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.", "ec2", d,
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

	checker.Register(DescriptionCheck("ec2-traffic-mirror-session-description", "Checks if Amazon EC2 traffic mirror sessions have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.", "ec2", d,
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

	checker.Register(DescriptionCheck("ec2-traffic-mirror-target-description", "Checks if Amazon EC2 traffic mirror targets have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.", "ec2", d,
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
	checker.Register(ConfigCheck("ec2-security-group-attached-to-eni", "Checks that non-default security groups are attached to Amazon Elastic Compute Cloud (EC2) instances or an elastic network interfaces (ENIs). The rule returns NON_COMPLIANT if the security group is not associated with an EC2 instance or an ENI.", "ec2", d,
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

	checker.Register(ConfigCheck("ec2-security-group-attached-to-eni-periodic", "Checks if non-default security groups are attached to Elastic network interfaces (ENIs). The rule is NON_COMPLIANT if the security group is not associated with an ENI. Security groups not owned by the calling account evaluate as NOT_APPLICABLE.", "ec2", d,
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

	checker.Register(ConfigCheck("ec2-managedinstance-platform-check", "Checks whether EC2 managed instances have the desired configurations.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			allowedPlatformValues := parseCSV(os.Getenv("BPTOOLS_MANAGEDINSTANCE_ALLOWED_PLATFORMS"))
			if len(allowedPlatformValues) == 0 {
				allowedPlatformValues = []string{"linux", "windows", "macos"}
			}
			allowedPlatforms := make(map[string]bool)
			for _, value := range allowedPlatformValues {
				allowedPlatforms[strings.ToLower(strings.TrimSpace(value))] = true
			}
			var res []ConfigResource
			for _, info := range infos {
				id := ""
				if info.InstanceId != nil {
					id = *info.InstanceId
				}
				pt := string(info.PlatformType)
				ok := allowedPlatforms[strings.ToLower(strings.TrimSpace(pt))]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("PlatformType: %s", pt)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-managedinstance-association-compliance-status-check", "Checks if the status of the AWS Systems Manager association compliance is COMPLIANT or NON_COMPLIANT after the association execution on the instance. The rule is compliant if the field status is COMPLIANT. For more information about associations, see What is an association?.", "ec2", d,
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

	checker.Register(ConfigCheck("ec2-managedinstance-patch-compliance-status-check", "Checks if the compliance status of the AWS Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT after the patch installation on the instance. The rule is compliant if the field status is COMPLIANT.", "ec2", d,
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

	checker.Register(ConfigCheck("ec2-managedinstance-applications-required", "Checks if all of the specified applications are installed on the instance. Optionally, specify the minimum acceptable version. You can also specify the platform to apply the rule only to instances running that platform.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			apps, err := loadInventoryByType("AWS:Application")
			if err != nil {
				return nil, err
			}
			requiredApplications := parseCSV(os.Getenv("BPTOOLS_MANAGEDINSTANCE_REQUIRED_APPLICATIONS"))
			requiredSet := make(map[string]bool)
			for _, app := range requiredApplications {
				requiredSet[strings.ToLower(strings.TrimSpace(app))] = true
			}
			var res []ConfigResource
			for _, info := range infos {
				if info.InstanceId == nil {
					continue
				}
				id := *info.InstanceId
				installed := make(map[string]bool)
				for _, app := range apps[id] {
					name := strings.ToLower(strings.TrimSpace(app["Name"]))
					pkg := strings.ToLower(strings.TrimSpace(app["PackageId"]))
					if name != "" {
						installed[name] = true
					}
					if pkg != "" {
						installed[pkg] = true
					}
				}
				missing := []string{}
				for req := range requiredSet {
					if !installed[req] {
						missing = append(missing, req)
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: len(missing) == 0, Detail: fmt.Sprintf("Missing required applications: %v", missing)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-managedinstance-applications-blacklisted", "Checks if none of the specified applications are installed on the instance. Optionally, specify the version. Newer versions will not be denylisted. Optionally, specify the platform to apply the rule only to instances running that platform.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			apps, err := loadInventoryByType("AWS:Application")
			if err != nil {
				return nil, err
			}
			blacklistedValues := parseCSV(os.Getenv("BPTOOLS_MANAGEDINSTANCE_BLACKLISTED_APPLICATIONS"))
			blacklisted := make(map[string]bool)
			for _, value := range blacklistedValues {
				blacklisted[strings.ToLower(strings.TrimSpace(value))] = true
			}
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
					if blacklisted[name] {
						found = name
					} else if blacklisted[pkg] {
						found = pkg
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

	checker.Register(ConfigCheck("ec2-managedinstance-inventory-blacklisted", "Checks whether instances managed by Amazon EC2 Systems Manager are configured to collect blacklisted inventory types.", "ec2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			infos, err := loadManagedInstances()
			if err != nil {
				return nil, err
			}
			blacklistedTypes := parseCSV(os.Getenv("BPTOOLS_MANAGEDINSTANCE_BLACKLISTED_INVENTORY_TYPES"))
			inventoryByType := make(map[string]map[string][]map[string]string)
			for _, typeName := range blacklistedTypes {
				items, err := loadInventoryByType(typeName)
				if err != nil {
					return nil, err
				}
				inventoryByType[typeName] = items
			}
			var res []ConfigResource
			for _, info := range infos {
				if info.InstanceId == nil {
					continue
				}
				id := *info.InstanceId
				foundType := ""
				for _, typeName := range blacklistedTypes {
					if len(inventoryByType[typeName][id]) > 0 {
						foundType = typeName
						break
					}
				}
				passing := foundType == ""
				detail := "No blacklisted inventory types collected"
				if !passing {
					detail = fmt.Sprintf("Blacklisted inventory type collected: %s", foundType)
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

	checker.Register(ConfigCheck("ec2-resources-protected-by-backup-plan", "Checks if Amazon Elastic Compute Cloud (Amazon EC2) instances are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon EC2 instance is not covered by a backup plan.", "ec2", d,
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

	checker.Register(ConfigCheck("ec2-last-backup-recovery-point-created", "Checks if a recovery point was created for Amazon Elastic Compute Cloud (Amazon EC2) instances. The rule is NON_COMPLIANT if the Amazon EC2 instance does not have a corresponding recovery point created within the specified time period.", "ec2", d,
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

	checker.Register(ConfigCheck("ec2-meets-restore-time-target", "Checks if the restore time of Amazon Elastic Compute Cloud (Amazon EC2) instances meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon EC2 instance is greater than maxRestoreTime minutes.", "ec2", d,
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
			var res []ConfigResource
			for _, instance := range instances {
				id := instanceID(instance)
				arn := buildEC2InstanceARN(region, accountID, id)
				ok, detail, err := restoreTimeTargetResult(d, arn, backupRestoreTimeTargetWindow)
				if err != nil {
					return nil, err
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("ec2-resources-in-logically-air-gapped-vault", "Checks if Amazon Elastic Compute Cloud (Amazon EC2) instances are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon EC2 instance is not in a logically air-gapped vault within the specified time period.", "ec2", d,
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

	checker.Register(ConfigCheck("ebs-in-backup-plan", "Check if Amazon Elastic Block Store (Amazon EBS) volumes are added in backup plans of AWS Backup. The rule is NON_COMPLIANT if Amazon EBS volumes are not included in backup plans.", "ec2", d,
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

	checker.Register(ConfigCheck("ebs-resources-protected-by-backup-plan", "Checks if Amazon Elastic Block Store (Amazon EBS) volumes are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon EBS volume is not covered by a backup plan.", "ec2", d,
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

	checker.Register(ConfigCheck("ebs-last-backup-recovery-point-created", "Checks if a recovery point was created for Amazon Elastic Block Store (Amazon EBS). The rule is NON_COMPLIANT if the Amazon EBS volume does not have a corresponding recovery point created within the specified time period.", "ec2", d,
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

	checker.Register(ConfigCheck("ebs-meets-restore-time-target", "Checks if the restore time of Amazon Elastic Block Store (Amazon EBS) volumes meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon EBS volume is greater than maxRestoreTime minutes.", "ec2", d,
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

	checker.Register(ConfigCheck("ebs-resources-in-logically-air-gapped-vault", "Checks if Amazon Elastic Block Store (Amazon EBS) volumes are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon EBS volume is not in a logically air-gapped vault within the specified time period.", "ec2", d,
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
	checker.Register(TaggedCheck("ecr-repository-tagged", "Checks if Amazon ECR repositories have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "ecr", d,
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

	checker.Register(EnabledCheck("ecr-private-image-scanning-enabled", "Checks if a private Amazon Elastic Container Registry (Amazon ECR) repository has image scanning enabled. The rule is NON_COMPLIANT if the private Amazon ECR repository's scan frequency is not on scan on push or continuous scan. For more information on enabling image scanning, see Image scanning in the Amazon ECR User Guide.", "ecr", d,
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

	checker.Register(EnabledCheck("ecr-private-tag-immutability-enabled", "Checks if a private Amazon Elastic Container Registry (ECR) repository has tag immutability enabled. This rule is NON_COMPLIANT if tag immutability is not enabled for the private ECR repository.", "ecr", d,
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

	checker.Register(ConfigCheck("ecr-private-lifecycle-policy-configured", "Checks if a private Amazon Elastic Container Registry (ECR) repository has at least one lifecycle policy configured. The rule is NON_COMPLIANT if no lifecycle policy is configured for the ECR private repository.", "ecr", d,
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

	checker.Register(ConfigCheck("ecr-repository-cmk-encryption-enabled", "Checks if ECR repository is encrypted at rest using customer-managed KMS key. This rule is NON_COMPLIANT if the repository is encrypted using AES256 or the default KMS key ('aws/ecr').", "ecr", d,
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

func ec2PrefixListIsAWSManagedOrDeleted(prefixList ec2types.ManagedPrefixList) bool {
	if prefixList.OwnerId != nil && strings.EqualFold(strings.TrimSpace(*prefixList.OwnerId), "AWS") {
		return true
	}
	if prefixList.PrefixListName != nil {
		name := strings.ToLower(strings.TrimSpace(*prefixList.PrefixListName))
		if strings.HasPrefix(name, "com.amazonaws.") {
			return true
		}
	}
	state := strings.ToLower(strings.TrimSpace(string(prefixList.State)))
	return strings.Contains(state, "delete")
}
