package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

type sagemakerDomainInVPCFix struct{ clients *awsdata.Clients }

func (f *sagemakerDomainInVPCFix) CheckID() string { return "sagemaker-domain-in-vpc" }
func (f *sagemakerDomainInVPCFix) Description() string {
	return "Set SageMaker domain app network access to VpcOnly"
}
func (f *sagemakerDomainInVPCFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *sagemakerDomainInVPCFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func sagemakerDomainIDFromResource(resourceID string) string {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return ""
	}
	// ARN format ends with domain/<domain-id>
	if strings.HasPrefix(id, "arn:") {
		parts := strings.Split(id, "/")
		return parts[len(parts)-1]
	}
	return id
}

func (f *sagemakerDomainInVPCFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	domainID := sagemakerDomainIDFromResource(resourceID)
	if domainID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing domain ID"
		return base
	}

	out, err := f.clients.SageMaker.DescribeDomain(fctx.Ctx, &sagemaker.DescribeDomainInput{
		DomainId: aws.String(domainID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe domain: " + err.Error()
		return base
	}
	if out.AppNetworkAccessType == sagemakertypes.AppNetworkAccessTypeVpcOnly {
		base.Status = fix.FixSkipped
		base.Message = "domain already configured with VpcOnly"
		return base
	}
	if out.VpcId == nil || strings.TrimSpace(*out.VpcId) == "" || len(out.SubnetIds) == 0 {
		base.Status = fix.FixFailed
		base.Message = "cannot set VpcOnly: domain has no VPC/subnets configured"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set SageMaker domain app network access to VpcOnly for " + domainID}
		return base
	}

	_, err = f.clients.SageMaker.UpdateDomain(fctx.Ctx, &sagemaker.UpdateDomainInput{
		DomainId:             aws.String(domainID),
		AppNetworkAccessType: sagemakertypes.AppNetworkAccessTypeVpcOnly,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update domain: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set SageMaker domain app network access to VpcOnly for " + domainID}
	return base
}
