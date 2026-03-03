package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// inspector2Fix enables a specific Inspector2 scan type for the account.
type inspector2Fix struct {
	checkID      string
	description  string
	resourceType inspector2types.ResourceScanType
	clients      *awsdata.Clients
}

func (f *inspector2Fix) CheckID() string          { return f.checkID }
func (f *inspector2Fix) Description() string      { return f.description }
func (f *inspector2Fix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *inspector2Fix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *inspector2Fix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	st, err := f.clients.Inspector2.BatchGetAccountStatus(fctx.Ctx, &inspector2.BatchGetAccountStatusInput{})
	if err == nil {
		for _, acct := range st.Accounts {
			if acct.ResourceState == nil {
				continue
			}
			var state *inspector2types.State
			switch f.resourceType {
			case inspector2types.ResourceScanTypeEc2:
				state = acct.ResourceState.Ec2
			case inspector2types.ResourceScanTypeEcr:
				state = acct.ResourceState.Ecr
			case inspector2types.ResourceScanTypeLambda:
				state = acct.ResourceState.Lambda
			case inspector2types.ResourceScanTypeLambdaCode:
				state = acct.ResourceState.LambdaCode
			}
			if state != nil && state.Status == inspector2types.StatusEnabled {
				base.Status = fix.FixSkipped
				base.Message = f.checkID + " already enabled"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable Inspector2 " + string(f.resourceType) + " scanning"}
		return base
	}

	_, err = f.clients.Inspector2.Enable(fctx.Ctx, &inspector2.EnableInput{
		ResourceTypes: []inspector2types.ResourceScanType{f.resourceType},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable Inspector2 scan: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled Inspector2 " + string(f.resourceType) + " scanning"}
	base.Status = fix.FixApplied
	return base
}
