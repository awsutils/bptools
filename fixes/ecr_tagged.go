package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type ecrRepositoryTaggedFix struct{ clients *awsdata.Clients }

func (f *ecrRepositoryTaggedFix) CheckID() string             { return "ecr-repository-tagged" }
func (f *ecrRepositoryTaggedFix) Description() string         { return "Tag ECR repository" }
func (f *ecrRepositoryTaggedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ecrRepositoryTaggedFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ecrRepositoryTaggedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	repoName := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if repoName == "" {
		base.Status = fix.FixFailed
		base.Message = "missing repository name"
		return base
	}

	descOut, err := f.clients.ECR.DescribeRepositories(fctx.Ctx, &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{repoName},
	})
	if err != nil || len(descOut.Repositories) == 0 || descOut.Repositories[0].RepositoryArn == nil {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "describe repository: " + err.Error()
		} else {
			base.Message = "repository not found"
		}
		return base
	}
	repoARN := *descOut.Repositories[0].RepositoryArn

	tagsOut, err := f.clients.ECR.ListTagsForResource(fctx.Ctx, &ecr.ListTagsForResourceInput{
		ResourceArn: aws.String(repoARN),
	})
	if err == nil && len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "repository already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag ECR repository " + repoName}
		return base
	}

	_, err = f.clients.ECR.TagResource(fctx.Ctx, &ecr.TagResourceInput{
		ResourceArn: aws.String(repoARN),
		Tags: []ecrtypes.Tag{
			{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag repository: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged ECR repository " + repoName}
	return base
}
