package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	workspacestypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"
)

type kmsKeyTaggedFix struct{ clients *awsdata.Clients }

func (f *kmsKeyTaggedFix) CheckID() string     { return "kms-key-tagged" }
func (f *kmsKeyTaggedFix) Description() string { return "Tag KMS key" }
func (f *kmsKeyTaggedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *kmsKeyTaggedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *kmsKeyTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	keyID := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if keyID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing key ID"
		return base
	}
	tagsOut, err := f.clients.KMS.ListResourceTags(fctx.Ctx, &kms.ListResourceTagsInput{KeyId: aws.String(keyID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list key tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "KMS key already tagged"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag KMS key " + keyID}
		return base
	}
	_, err = f.clients.KMS.TagResource(fctx.Ctx, &kms.TagResourceInput{
		KeyId: aws.String(keyID),
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("bptools:managed-by"), TagValue: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag key: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged KMS key " + keyID}
	return base
}

type cloudWatchMetricStreamTaggedFix struct{ clients *awsdata.Clients }

func (f *cloudWatchMetricStreamTaggedFix) CheckID() string     { return "cloudwatch-metric-stream-tagged" }
func (f *cloudWatchMetricStreamTaggedFix) Description() string { return "Tag CloudWatch metric stream" }
func (f *cloudWatchMetricStreamTaggedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *cloudWatchMetricStreamTaggedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *cloudWatchMetricStreamTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	arn := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing metric stream ARN"
		return base
	}
	tagsOut, err := f.clients.CloudWatch.ListTagsForResource(fctx.Ctx, &cloudwatch.ListTagsForResourceInput{
		ResourceARN: aws.String(arn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list metric stream tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "metric stream already tagged"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag CloudWatch metric stream " + arn}
		return base
	}
	_, err = f.clients.CloudWatch.TagResource(fctx.Ctx, &cloudwatch.TagResourceInput{
		ResourceARN: aws.String(arn),
		Tags: []cloudwatchtypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag metric stream: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged CloudWatch metric stream " + arn}
	return base
}

type stepFunctionsStateMachineTaggedFix struct{ clients *awsdata.Clients }

func (f *stepFunctionsStateMachineTaggedFix) CheckID() string {
	return "stepfunctions-state-machine-tagged"
}
func (f *stepFunctionsStateMachineTaggedFix) Description() string {
	return "Tag Step Functions state machine"
}
func (f *stepFunctionsStateMachineTaggedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *stepFunctionsStateMachineTaggedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *stepFunctionsStateMachineTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	arn := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing state machine ARN"
		return base
	}
	tagsOut, err := f.clients.SFN.ListTagsForResource(fctx.Ctx, &sfn.ListTagsForResourceInput{ResourceArn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list state machine tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "state machine already tagged"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag Step Functions state machine " + arn}
		return base
	}
	_, err = f.clients.SFN.TagResource(fctx.Ctx, &sfn.TagResourceInput{
		ResourceArn: aws.String(arn),
		Tags: []sfntypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag state machine: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged Step Functions state machine " + arn}
	return base
}

type transferTaggedFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *transferTaggedFix) CheckID() string     { return f.checkID }
func (f *transferTaggedFix) Description() string { return "Tag AWS Transfer Family resource" }
func (f *transferTaggedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *transferTaggedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *transferTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	arn := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.checkID, ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing Transfer resource ARN"
		return base
	}
	tagsOut, err := f.clients.Transfer.ListTagsForResource(fctx.Ctx, &transfer.ListTagsForResourceInput{Arn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list transfer tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "resource already tagged"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag Transfer resource " + arn}
		return base
	}
	_, err = f.clients.Transfer.TagResource(fctx.Ctx, &transfer.TagResourceInput{
		Arn: aws.String(arn),
		Tags: []transfertypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag transfer resource: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged Transfer resource " + arn}
	return base
}

type workspacesTaggedFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *workspacesTaggedFix) CheckID() string     { return f.checkID }
func (f *workspacesTaggedFix) Description() string { return "Tag Amazon WorkSpaces resource" }
func (f *workspacesTaggedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *workspacesTaggedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *workspacesTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.checkID, ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing WorkSpaces resource ID"
		return base
	}
	tagsOut, err := f.clients.Workspaces.DescribeTags(fctx.Ctx, &workspaces.DescribeTagsInput{ResourceId: aws.String(id)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe tags: " + err.Error()
		return base
	}
	if len(tagsOut.TagList) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "resource already tagged"
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag WorkSpaces resource " + id}
		return base
	}
	_, err = f.clients.Workspaces.CreateTags(fctx.Ctx, &workspaces.CreateTagsInput{
		ResourceId: aws.String(id),
		Tags: []workspacestypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create tags: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged WorkSpaces resource " + id}
	return base
}
