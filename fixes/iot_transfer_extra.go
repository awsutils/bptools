package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
)

type iotProvisioningTemplateJITPFix struct{ clients *awsdata.Clients }

func (f *iotProvisioningTemplateJITPFix) CheckID() string { return "iot-provisioning-template-jitp" }
func (f *iotProvisioningTemplateJITPFix) Description() string {
	return "Enable IoT provisioning template (JITP check)"
}
func (f *iotProvisioningTemplateJITPFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *iotProvisioningTemplateJITPFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *iotProvisioningTemplateJITPFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing provisioning template name"
		return base
	}

	out, err := f.clients.IoT.DescribeProvisioningTemplate(fctx.Ctx, &iot.DescribeProvisioningTemplateInput{
		TemplateName: aws.String(name),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe provisioning template: " + err.Error()
		return base
	}
	if out.Enabled != nil && *out.Enabled {
		base.Status = fix.FixSkipped
		base.Message = "provisioning template already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable IoT provisioning template " + name}
		return base
	}

	_, err = f.clients.IoT.UpdateProvisioningTemplate(fctx.Ctx, &iot.UpdateProvisioningTemplateInput{
		TemplateName: aws.String(name),
		Enabled:      aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update provisioning template: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"enabled IoT provisioning template " + name}
	return base
}

type transferConnectorLoggingFix struct{ clients *awsdata.Clients }

func (f *transferConnectorLoggingFix) CheckID() string { return "transfer-connector-logging-enabled" }
func (f *transferConnectorLoggingFix) Description() string {
	return "Set Transfer connector logging role"
}
func (f *transferConnectorLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *transferConnectorLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *transferConnectorLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	connectorID := strings.TrimSpace(resourceID)
	if connectorID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing connector ID"
		return base
	}

	out, err := f.clients.Transfer.DescribeConnector(fctx.Ctx, &transfer.DescribeConnectorInput{
		ConnectorId: aws.String(connectorID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe connector: " + err.Error()
		return base
	}
	if out.Connector == nil {
		base.Status = fix.FixFailed
		base.Message = "connector not found"
		return base
	}
	if out.Connector.LoggingRole != nil && strings.TrimSpace(*out.Connector.LoggingRole) != "" {
		base.Status = fix.FixSkipped
		base.Message = "logging role already configured"
		return base
	}
	if out.Connector.AccessRole == nil || strings.TrimSpace(*out.Connector.AccessRole) == "" {
		base.Status = fix.FixFailed
		base.Message = "cannot auto-configure logging role: connector has no access role"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set Transfer connector logging role to connector access role"}
		return base
	}

	_, err = f.clients.Transfer.UpdateConnector(fctx.Ctx, &transfer.UpdateConnectorInput{
		ConnectorId: aws.String(connectorID),
		LoggingRole: out.Connector.AccessRole,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update connector: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set Transfer connector logging role"}
	return base
}
