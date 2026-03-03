package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

// ── eks-cluster-logging-enabled / eks-cluster-log-enabled ────────────────────

// eksLoggingFix enables all five EKS control-plane log types.
// Two check IDs map to the same underlying fix.
type eksLoggingFix struct {
	checkID string
	clients *awsdata.Clients
}

var eksAllLogTypes = []ekstypes.LogType{
	ekstypes.LogTypeApi,
	ekstypes.LogTypeAudit,
	ekstypes.LogTypeAuthenticator,
	ekstypes.LogTypeControllerManager,
	ekstypes.LogTypeScheduler,
}

func (f *eksLoggingFix) CheckID() string          { return f.checkID }
func (f *eksLoggingFix) Description() string      { return "Enable all EKS control-plane log types" }
func (f *eksLoggingFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *eksLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *eksLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EKS.DescribeCluster(fctx.Ctx, &eks.DescribeClusterInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster: " + err.Error()
		return base
	}
	if out.Cluster == nil {
		base.Status = fix.FixFailed
		base.Message = "cluster not found"
		return base
	}

	// Check if all required log types are already enabled.
	enabled := make(map[ekstypes.LogType]bool)
	if out.Cluster.Logging != nil {
		for _, setup := range out.Cluster.Logging.ClusterLogging {
			if setup.Enabled != nil && *setup.Enabled {
				for _, t := range setup.Types {
					enabled[t] = true
				}
			}
		}
	}
	allEnabled := true
	for _, t := range eksAllLogTypes {
		if !enabled[t] {
			allEnabled = false
			break
		}
	}
	if allEnabled {
		base.Status = fix.FixSkipped
		base.Message = "all control-plane log types already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable all control-plane log types on EKS cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.EKS.UpdateClusterConfig(fctx.Ctx, &eks.UpdateClusterConfigInput{
		Name: aws.String(resourceID),
		Logging: &ekstypes.Logging{
			ClusterLogging: []ekstypes.LogSetup{
				{Types: eksAllLogTypes, Enabled: aws.Bool(true)},
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update cluster config: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled all control-plane log types on EKS cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── eks-endpoint-no-public-access ────────────────────────────────────────────

type eksEndpointNoPublicAccessFix struct{ clients *awsdata.Clients }

func (f *eksEndpointNoPublicAccessFix) CheckID() string {
	return "eks-endpoint-no-public-access"
}
func (f *eksEndpointNoPublicAccessFix) Description() string {
	return "Disable public endpoint access on EKS cluster"
}
func (f *eksEndpointNoPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *eksEndpointNoPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *eksEndpointNoPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EKS.DescribeCluster(fctx.Ctx, &eks.DescribeClusterInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe EKS cluster: " + err.Error()
		return base
	}
	if out.Cluster == nil || out.Cluster.ResourcesVpcConfig == nil {
		base.Status = fix.FixFailed
		base.Message = "cluster or VPC config not found"
		return base
	}
	if !out.Cluster.ResourcesVpcConfig.EndpointPublicAccess {
		base.Status = fix.FixSkipped
		base.Message = "public endpoint access already disabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable public endpoint access on EKS cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.EKS.UpdateClusterConfig(fctx.Ctx, &eks.UpdateClusterConfigInput{
		Name: aws.String(resourceID),
		ResourcesVpcConfig: &ekstypes.VpcConfigRequest{
			EndpointPublicAccess:  aws.Bool(false),
			EndpointPrivateAccess: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update EKS cluster config: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("disabled public endpoint access (and enabled private) on EKS cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
