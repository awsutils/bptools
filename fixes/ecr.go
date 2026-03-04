package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ── ecr-private-image-scanning-enabled ───────────────────────────────────────

type ecrImageScanningFix struct{ clients *awsdata.Clients }

func (f *ecrImageScanningFix) CheckID() string { return "ecr-private-image-scanning-enabled" }
func (f *ecrImageScanningFix) Description() string {
	return "Enable scan-on-push for ECR private repository"
}
func (f *ecrImageScanningFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ecrImageScanningFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ecrImageScanningFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ECR.DescribeRepositories(fctx.Ctx, &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe repository: " + err.Error()
		return base
	}
	if len(out.Repositories) == 0 {
		base.Status = fix.FixFailed
		base.Message = "repository not found"
		return base
	}
	repo := out.Repositories[0]
	if repo.ImageScanningConfiguration != nil && repo.ImageScanningConfiguration.ScanOnPush {
		base.Status = fix.FixSkipped
		base.Message = "scan-on-push already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable scan-on-push for ECR repository %s", resourceID)}
		return base
	}

	_, err = f.clients.ECR.PutImageScanningConfiguration(fctx.Ctx, &ecr.PutImageScanningConfigurationInput{
		RepositoryName: aws.String(resourceID),
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{
			ScanOnPush: true,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put image scanning configuration: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled scan-on-push for ECR repository %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ecr-private-tag-immutability-enabled ─────────────────────────────────────

type ecrTagImmutabilityFix struct{ clients *awsdata.Clients }

func (f *ecrTagImmutabilityFix) CheckID() string { return "ecr-private-tag-immutability-enabled" }
func (f *ecrTagImmutabilityFix) Description() string {
	return "Enable tag immutability on ECR private repository"
}
func (f *ecrTagImmutabilityFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ecrTagImmutabilityFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ecrTagImmutabilityFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ECR.DescribeRepositories(fctx.Ctx, &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe repository: " + err.Error()
		return base
	}
	if len(out.Repositories) == 0 {
		base.Status = fix.FixFailed
		base.Message = "repository not found"
		return base
	}
	repo := out.Repositories[0]
	if repo.ImageTagMutability == ecrtypes.ImageTagMutabilityImmutable {
		base.Status = fix.FixSkipped
		base.Message = "tag immutability already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable tag immutability on ECR repository %s", resourceID)}
		return base
	}

	_, err = f.clients.ECR.PutImageTagMutability(fctx.Ctx, &ecr.PutImageTagMutabilityInput{
		RepositoryName:     aws.String(resourceID),
		ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put image tag mutability: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled tag immutability on ECR repository %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── ecr-private-lifecycle-policy-configured ───────────────────────────────────

const ecrDefaultLifecyclePolicy = `{"rules":[{"rulePriority":1,"description":"bptools: expire untagged images after 30 days","selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":30},"action":{"type":"expire"}}]}`

type ecrLifecyclePolicyFix struct{ clients *awsdata.Clients }

func (f *ecrLifecyclePolicyFix) CheckID() string {
	return "ecr-private-lifecycle-policy-configured"
}
func (f *ecrLifecyclePolicyFix) Description() string {
	return "Configure a default lifecycle policy on ECR private repository"
}
func (f *ecrLifecyclePolicyFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ecrLifecyclePolicyFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ecrLifecyclePolicyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	_, err := f.clients.ECR.GetLifecyclePolicy(fctx.Ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: aws.String(resourceID),
	})
	if err == nil {
		base.Status = fix.FixSkipped
		base.Message = "lifecycle policy already configured"
		return base
	}
	// Only proceed if it's a "not found" error
	if !strings.Contains(err.Error(), "LifecyclePolicyNotFoundException") {
		base.Status = fix.FixFailed
		base.Message = "get lifecycle policy: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would add default lifecycle policy to ECR repository %s", resourceID)}
		return base
	}

	_, err = f.clients.ECR.PutLifecyclePolicy(fctx.Ctx, &ecr.PutLifecyclePolicyInput{
		RepositoryName:      aws.String(resourceID),
		LifecyclePolicyText: aws.String(ecrDefaultLifecyclePolicy),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put lifecycle policy: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("added default lifecycle policy (expire untagged images after 30 days) to ECR repository %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
