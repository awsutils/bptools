package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	route53resolvertypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
)

var defaultRoute53Tag = route53types.Tag{
	Key:   aws.String("bptools:managed-by"),
	Value: aws.String("bptools"),
}

var defaultRoute53ResolverTag = route53resolvertypes.Tag{
	Key:   aws.String("bptools:managed-by"),
	Value: aws.String("bptools"),
}

type route53TagFix struct {
	checkID      string
	resourceType route53types.TagResourceType
	clients      *awsdata.Clients
}

func (f *route53TagFix) CheckID() string     { return f.checkID }
func (f *route53TagFix) Description() string { return "Tag Route53 resource" }
func (f *route53TagFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *route53TagFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *route53TagFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(strings.TrimPrefix(resourceID, "/hostedzone/"))
	base := fix.FixResult{CheckID: f.checkID, ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing resource ID"
		return base
	}

	out, err := f.clients.Route53.ListTagsForResource(fctx.Ctx, &route53.ListTagsForResourceInput{
		ResourceId:   aws.String(id),
		ResourceType: f.resourceType,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list tags: " + err.Error()
		return base
	}
	if out.ResourceTagSet != nil && len(out.ResourceTagSet.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "resource already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag Route53 resource " + id}
		return base
	}

	_, err = f.clients.Route53.ChangeTagsForResource(fctx.Ctx, &route53.ChangeTagsForResourceInput{
		ResourceId:   aws.String(id),
		ResourceType: f.resourceType,
		AddTags:      []route53types.Tag{defaultRoute53Tag},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "change tags for resource: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged Route53 resource " + id}
	return base
}

type route53ResolverTagFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *route53ResolverTagFix) CheckID() string     { return f.checkID }
func (f *route53ResolverTagFix) Description() string { return "Tag Route53 Resolver resource" }
func (f *route53ResolverTagFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *route53ResolverTagFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *route53ResolverTagFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	arn := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.checkID, ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing resource ARN"
		return base
	}

	out, err := f.clients.Route53Resolver.ListTagsForResource(fctx.Ctx, &route53resolver.ListTagsForResourceInput{
		ResourceArn: aws.String(arn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list tags: " + err.Error()
		return base
	}
	if len(out.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "resource already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag Route53 Resolver resource " + arn}
		return base
	}

	_, err = f.clients.Route53Resolver.TagResource(fctx.Ctx, &route53resolver.TagResourceInput{
		ResourceArn: aws.String(arn),
		Tags:        []route53resolvertypes.Tag{defaultRoute53ResolverTag},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag resource: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged Route53 Resolver resource " + arn}
	return base
}
