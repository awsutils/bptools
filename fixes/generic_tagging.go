package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amp"
	"github.com/aws/aws-sdk-go-v2/service/appflow"
	"github.com/aws/aws-sdk-go-v2/service/appintegrations"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	appmeshtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/evidently"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	globalacceleratortypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/iotevents"
	ioteventstypes "github.com/aws/aws-sdk-go-v2/service/iotevents/types"
	"github.com/aws/aws-sdk-go-v2/service/iotsitewise"
	"github.com/aws/aws-sdk-go-v2/service/iottwinmaker"
	"github.com/aws/aws-sdk-go-v2/service/iotwireless"
	iotwirelesstypes "github.com/aws/aws-sdk-go-v2/service/iotwireless/types"
	"github.com/aws/aws-sdk-go-v2/service/ivs"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

var defaultManagedTags = map[string]string{
	"bptools:managed-by": "bptools",
}

type genericTaggedFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *genericTaggedFix) CheckID() string     { return f.checkID }
func (f *genericTaggedFix) Description() string { return "Tag resource to satisfy tagged policy" }
func (f *genericTaggedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *genericTaggedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *genericTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.checkID, ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing resource ID"
		return base
	}

	// Known non-ARN tagged rule where resource ID is bucket name.
	if f.checkID == "s3-bucket-tagged" {
		out, err := f.clients.S3.GetBucketTagging(fctx.Ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(id)})
		if err == nil && len(out.TagSet) > 0 {
			base.Status = fix.FixSkipped
			base.Message = "resource already tagged"
			return base
		}
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag S3 bucket " + id}
			return base
		}
		_, err = f.clients.S3.PutBucketTagging(fctx.Ctx, &s3.PutBucketTaggingInput{
			Bucket: aws.String(id),
			Tagging: &s3types.Tagging{
				TagSet: []s3types.Tag{
					{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
				},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag S3 bucket: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged S3 bucket " + id}
		return base
	}

	// Generic path for ARN-addressable resources via Resource Groups Tagging API.
	if !strings.HasPrefix(strings.ToLower(id), "arn:") {
		// EC2 tagged checks frequently use raw resource IDs (for example: vpc-..., sg-..., subnet-...).
		if strings.HasPrefix(f.checkID, "ec2-") {
			// ec2-launch-template-tagged emits launch template name, but CreateTags needs lt- ID.
			if f.checkID == "ec2-launch-template-tagged" && !strings.HasPrefix(id, "lt-") {
				out, err := f.clients.EC2.DescribeLaunchTemplates(fctx.Ctx, &ec2.DescribeLaunchTemplatesInput{
					LaunchTemplateNames: []string{id},
				})
				if err != nil || len(out.LaunchTemplates) == 0 || out.LaunchTemplates[0].LaunchTemplateId == nil {
					base.Status = fix.FixFailed
					if err != nil {
						base.Message = "resolve launch template ID: " + err.Error()
					} else {
						base.Message = "resolve launch template ID: not found"
					}
					return base
				}
				id = *out.LaunchTemplates[0].LaunchTemplateId
			}
			if fctx.DryRun {
				base.Status = fix.FixDryRun
				base.Steps = []string{"would tag EC2 resource " + id}
				return base
			}
			_, err := f.clients.EC2.CreateTags(fctx.Ctx, &ec2.CreateTagsInput{
				Resources: []string{id},
				Tags: []ec2types.Tag{
					{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
				},
			})
			if err != nil {
				base.Status = fix.FixFailed
				base.Message = "tag EC2 resource: " + err.Error()
				return base
			}
			base.Status = fix.FixApplied
			base.Steps = []string{"tagged EC2 resource " + id}
			return base
		}

		base.Status = fix.FixFailed
		base.Message = "generic tagged fix supports ARN resources only for this rule"
		return base
	}

	// Prefer service-native tagging for select services.
	if strings.HasPrefix(f.checkID, "evidently-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag Evidently resource " + id}
			return base
		}
		_, err := f.clients.Evidently.TagResource(fctx.Ctx, &evidently.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag Evidently resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged Evidently resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "appintegrations-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag AppIntegrations resource " + id}
			return base
		}
		_, err := f.clients.AppIntegrations.TagResource(fctx.Ctx, &appintegrations.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag AppIntegrations resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged AppIntegrations resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "appsync-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag AppSync resource " + id}
			return base
		}
		_, err := f.clients.AppSync.TagResource(fctx.Ctx, &appsync.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag AppSync resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged AppSync resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "apprunner-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag App Runner resource " + id}
			return base
		}
		_, err := f.clients.AppRunner.TagResource(fctx.Ctx, &apprunner.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags: []apprunnertypes.Tag{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag App Runner resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged App Runner resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "appflow-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag AppFlow resource " + id}
			return base
		}
		_, err := f.clients.AppFlow.TagResource(fctx.Ctx, &appflow.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag AppFlow resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged AppFlow resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "appmesh-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag App Mesh resource " + id}
			return base
		}
		_, err := f.clients.AppMesh.TagResource(fctx.Ctx, &appmesh.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags: []appmeshtypes.TagRef{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag App Mesh resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged App Mesh resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "amp-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag AMP resource " + id}
			return base
		}
		_, err := f.clients.AMP.TagResource(fctx.Ctx, &amp.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag AMP resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged AMP resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "iot-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag IoT resource " + id}
			return base
		}
		_, err := f.clients.IoT.TagResource(fctx.Ctx, &iot.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags: []iottypes.Tag{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag IoT resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged IoT resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "iotevents-") {
		arn := id
		// Some IoT Events checks emit names rather than ARNs.
		if !strings.HasPrefix(strings.ToLower(arn), "arn:") {
			switch f.checkID {
			case "iotevents-alarm-model-tagged":
				desc, err := f.clients.IoTEvents.DescribeAlarmModel(fctx.Ctx, &iotevents.DescribeAlarmModelInput{
					AlarmModelName: aws.String(id),
				})
				if err != nil || desc.AlarmModelArn == nil || strings.TrimSpace(*desc.AlarmModelArn) == "" {
					base.Status = fix.FixFailed
					if err != nil {
						base.Message = "resolve IoT Events alarm model ARN: " + err.Error()
					} else {
						base.Message = "resolve IoT Events alarm model ARN: not found"
					}
					return base
				}
				arn = *desc.AlarmModelArn
			case "iotevents-detector-model-tagged":
				desc, err := f.clients.IoTEvents.DescribeDetectorModel(fctx.Ctx, &iotevents.DescribeDetectorModelInput{
					DetectorModelName: aws.String(id),
				})
				if err != nil ||
					desc.DetectorModel == nil ||
					desc.DetectorModel.DetectorModelConfiguration == nil ||
					desc.DetectorModel.DetectorModelConfiguration.DetectorModelArn == nil ||
					strings.TrimSpace(*desc.DetectorModel.DetectorModelConfiguration.DetectorModelArn) == "" {
					base.Status = fix.FixFailed
					if err != nil {
						base.Message = "resolve IoT Events detector model ARN: " + err.Error()
					} else {
						base.Message = "resolve IoT Events detector model ARN: not found"
					}
					return base
				}
				arn = *desc.DetectorModel.DetectorModelConfiguration.DetectorModelArn
			}
		}
		if !strings.HasPrefix(strings.ToLower(arn), "arn:") {
			base.Status = fix.FixFailed
			base.Message = "unable to resolve IoT Events resource ARN"
			return base
		}
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag IoT Events resource " + arn}
			return base
		}
		_, err := f.clients.IoTEvents.TagResource(fctx.Ctx, &iotevents.TagResourceInput{
			ResourceArn: aws.String(arn),
			Tags: []ioteventstypes.Tag{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag IoT Events resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged IoT Events resource " + arn}
		return base
	}
	if strings.HasPrefix(f.checkID, "iotwireless-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag IoT Wireless resource " + id}
			return base
		}
		_, err := f.clients.IoTWireless.TagResource(fctx.Ctx, &iotwireless.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags: []iotwirelesstypes.Tag{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag IoT Wireless resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged IoT Wireless resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "iotsitewise-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag IoT SiteWise resource " + id}
			return base
		}
		_, err := f.clients.IoTSiteWise.TagResource(fctx.Ctx, &iotsitewise.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag IoT SiteWise resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged IoT SiteWise resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "iottwinmaker-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag IoT TwinMaker resource " + id}
			return base
		}
		_, err := f.clients.IoTTwinMaker.TagResource(fctx.Ctx, &iottwinmaker.TagResourceInput{
			ResourceARN: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag IoT TwinMaker resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged IoT TwinMaker resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "ivs-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag IVS resource " + id}
			return base
		}
		_, err := f.clients.IVS.TagResource(fctx.Ctx, &ivs.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag IVS resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged IVS resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "globalaccelerator-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag Global Accelerator resource " + id}
			return base
		}
		_, err := f.clients.GlobalAccelerator.TagResource(fctx.Ctx, &globalaccelerator.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags: []globalacceleratortypes.Tag{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag Global Accelerator resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged Global Accelerator resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "kafka-") || strings.HasPrefix(f.checkID, "msk-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag MSK resource " + id}
			return base
		}
		_, err := f.clients.Kafka.TagResource(fctx.Ctx, &kafka.TagResourceInput{
			ResourceArn: aws.String(id),
			Tags:        defaultManagedTags,
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag MSK resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged MSK resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "sagemaker-") {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag SageMaker resource " + id}
			return base
		}
		_, err := f.clients.SageMaker.AddTags(fctx.Ctx, &sagemaker.AddTagsInput{
			ResourceArn: aws.String(id),
			Tags: []sagemakertypes.Tag{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag SageMaker resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged SageMaker resource " + id}
		return base
	}
	if strings.HasPrefix(f.checkID, "lightsail-") {
		// Lightsail TagResource uses resource name, not ARN.
		parts := strings.Split(id, "/")
		name := parts[len(parts)-1]
		if name == "" {
			base.Status = fix.FixFailed
			base.Message = "invalid Lightsail resource ID"
			return base
		}
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{"would tag Lightsail resource " + name}
			return base
		}
		_, err := f.clients.Lightsail.TagResource(fctx.Ctx, &lightsail.TagResourceInput{
			ResourceName: aws.String(name),
			Tags: []lightsailtypes.Tag{
				{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
			},
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "tag Lightsail resource: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{"tagged Lightsail resource " + name}
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag resource " + id}
		return base
	}

	out, err := f.clients.ResourceGroupsTagging.TagResources(fctx.Ctx, &resourcegroupstaggingapi.TagResourcesInput{
		ResourceARNList: []string{id},
		Tags:            defaultManagedTags,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag resource: " + err.Error()
		return base
	}
	for arn, fail := range out.FailedResourcesMap {
		msg := "unknown tagging failure"
		if strings.TrimSpace(string(fail.ErrorCode)) != "" || fail.ErrorMessage != nil {
			msg = fmt.Sprintf("%s: %s", string(fail.ErrorCode), aws.ToString(fail.ErrorMessage))
		}
		base.Status = fix.FixFailed
		base.Message = "tag resource " + arn + ": " + msg
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"tagged resource " + id}
	return base
}

func registerGenericTaggedFixes(d *awsdata.Data) {
	for _, c := range checker.All() {
		id := strings.TrimSpace(c.ID())
		if id == "" || !strings.HasSuffix(id, "-tagged") {
			continue
		}
		if fix.Lookup(id) != nil {
			continue
		}
		fix.Register(&genericTaggedFix{checkID: id, clients: d.Clients})
	}
}
