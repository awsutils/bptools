package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

// sagemakerNotebookName extracts the notebook instance name from an ARN or
// returns the value as-is. ARN format:
//
//	arn:aws:sagemaker:region:account:notebook-instance/name
func sagemakerNotebookName(resourceID string) string {
	if strings.HasPrefix(resourceID, "arn:") {
		parts := strings.Split(resourceID, "/")
		return parts[len(parts)-1]
	}
	return resourceID
}

// ── sagemaker-notebook-instance-root-access-check ────────────────────────────

type sagemakerNotebookRootAccessFix struct{ clients *awsdata.Clients }

func (f *sagemakerNotebookRootAccessFix) CheckID() string {
	return "sagemaker-notebook-instance-root-access-check"
}
func (f *sagemakerNotebookRootAccessFix) Description() string {
	return "Disable root access on SageMaker notebook instance"
}
func (f *sagemakerNotebookRootAccessFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *sagemakerNotebookRootAccessFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *sagemakerNotebookRootAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := sagemakerNotebookName(resourceID)

	out, err := f.clients.SageMaker.DescribeNotebookInstance(fctx.Ctx, &sagemaker.DescribeNotebookInstanceInput{
		NotebookInstanceName: aws.String(name),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe notebook instance: " + err.Error()
		return base
	}
	if out.RootAccess == sagemakertypes.RootAccessDisabled {
		base.Status = fix.FixSkipped
		base.Message = "root access already disabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would disable root access on SageMaker notebook instance " + name}
		return base
	}

	_, err = f.clients.SageMaker.UpdateNotebookInstance(fctx.Ctx, &sagemaker.UpdateNotebookInstanceInput{
		NotebookInstanceName: aws.String(name),
		RootAccess:           sagemakertypes.RootAccessDisabled,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update notebook instance: " + err.Error()
		return base
	}
	base.Steps = []string{"disabled root access on SageMaker notebook instance " + name}
	base.Status = fix.FixApplied
	return base
}
