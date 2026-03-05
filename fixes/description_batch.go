package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appintegrations"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/evidently"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
)

const defaultAutoDescription = "Managed by bptools auto-remediation"

func evidentlyLaunchProjectFromARN(launchARN string) string {
	// arn:...:project/<project-name>/launch/<launch-name>
	parts := strings.Split(launchARN, "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "project" {
			return parts[i+1]
		}
	}
	return ""
}

type lambdaFunctionDescriptionFix struct{ clients *awsdata.Clients }

func (f *lambdaFunctionDescriptionFix) CheckID() string             { return "lambda-function-description" }
func (f *lambdaFunctionDescriptionFix) Description() string         { return "Set Lambda function description" }
func (f *lambdaFunctionDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *lambdaFunctionDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *lambdaFunctionDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing Lambda function name"
		return base
	}

	out, err := f.clients.Lambda.GetFunctionConfiguration(fctx.Ctx, &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(name),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get function configuration: " + err.Error()
		return base
	}
	if out.Description != nil && strings.TrimSpace(*out.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Lambda function " + name}
		return base
	}

	_, err = f.clients.Lambda.UpdateFunctionConfiguration(fctx.Ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(name),
		Description:  aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update function configuration: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Lambda function " + name}
	return base
}

type appIntegrationsEventDescriptionFix struct{ clients *awsdata.Clients }

func (f *appIntegrationsEventDescriptionFix) CheckID() string {
	return "appintegrations-event-integration-description"
}
func (f *appIntegrationsEventDescriptionFix) Description() string {
	return "Set AppIntegrations event integration description"
}
func (f *appIntegrationsEventDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *appIntegrationsEventDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *appIntegrationsEventDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	id := strings.TrimSpace(resourceID)
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing event integration ID"
		return base
	}

	events, err := f.clients.AppIntegrations.ListEventIntegrations(fctx.Ctx, &appintegrations.ListEventIntegrationsInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list event integrations: " + err.Error()
		return base
	}

	targetName := ""
	alreadySet := false
	for _, e := range events.EventIntegrations {
		if e.EventIntegrationArn != nil && *e.EventIntegrationArn == id && e.Name != nil {
			targetName = aws.ToString(e.Name)
			alreadySet = e.Description != nil && strings.TrimSpace(*e.Description) != ""
			break
		}
	}
	if targetName == "" {
		base.Status = fix.FixFailed
		base.Message = "event integration not found by ARN"
		return base
	}
	if alreadySet {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on AppIntegrations event integration " + targetName}
		return base
	}

	_, err = f.clients.AppIntegrations.UpdateEventIntegration(fctx.Ctx, &appintegrations.UpdateEventIntegrationInput{
		Name:        aws.String(targetName),
		Description: aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update event integration: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on AppIntegrations event integration " + targetName}
	return base
}

type iotProvisioningTemplateDescriptionFix struct{ clients *awsdata.Clients }

func (f *iotProvisioningTemplateDescriptionFix) CheckID() string {
	return "iot-provisioning-template-description"
}
func (f *iotProvisioningTemplateDescriptionFix) Description() string {
	return "Set IoT provisioning template description"
}
func (f *iotProvisioningTemplateDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *iotProvisioningTemplateDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *iotProvisioningTemplateDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing template name"
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
	if out.Description != nil && strings.TrimSpace(*out.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on IoT provisioning template " + name}
		return base
	}

	_, err = f.clients.IoT.UpdateProvisioningTemplate(fctx.Ctx, &iot.UpdateProvisioningTemplateInput{
		TemplateName: aws.String(name),
		Description:  aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update provisioning template: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on IoT provisioning template " + name}
	return base
}

type athenaDataCatalogDescriptionFix struct{ clients *awsdata.Clients }

func (f *athenaDataCatalogDescriptionFix) CheckID() string { return "athena-data-catalog-description" }
func (f *athenaDataCatalogDescriptionFix) Description() string {
	return "Set Athena data catalog description"
}
func (f *athenaDataCatalogDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *athenaDataCatalogDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *athenaDataCatalogDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing data catalog name"
		return base
	}

	out, err := f.clients.Athena.GetDataCatalog(fctx.Ctx, &athena.GetDataCatalogInput{Name: aws.String(name)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get data catalog: " + err.Error()
		return base
	}
	if out.DataCatalog != nil && out.DataCatalog.Description != nil && strings.TrimSpace(*out.DataCatalog.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}
	if out.DataCatalog == nil {
		base.Status = fix.FixFailed
		base.Message = "data catalog not found"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Athena data catalog " + name}
		return base
	}

	_, err = f.clients.Athena.UpdateDataCatalog(fctx.Ctx, &athena.UpdateDataCatalogInput{
		Name:        aws.String(name),
		Type:        out.DataCatalog.Type,
		Parameters:  out.DataCatalog.Parameters,
		Description: aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update data catalog: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Athena data catalog " + name}
	return base
}

type athenaPreparedStatementDescriptionFix struct{ clients *awsdata.Clients }

func (f *athenaPreparedStatementDescriptionFix) CheckID() string {
	return "athena-prepared-statement-description"
}
func (f *athenaPreparedStatementDescriptionFix) Description() string {
	return "Set Athena prepared statement description"
}
func (f *athenaPreparedStatementDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *athenaPreparedStatementDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *athenaPreparedStatementDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	parts := strings.SplitN(strings.TrimSpace(resourceID), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format, expected workgroup:statement"
		return base
	}
	workgroup := parts[0]
	statement := parts[1]

	out, err := f.clients.Athena.GetPreparedStatement(fctx.Ctx, &athena.GetPreparedStatementInput{
		WorkGroup:     aws.String(workgroup),
		StatementName: aws.String(statement),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get prepared statement: " + err.Error()
		return base
	}
	if out.PreparedStatement == nil {
		base.Status = fix.FixFailed
		base.Message = "prepared statement not found"
		return base
	}
	if out.PreparedStatement.Description != nil && strings.TrimSpace(*out.PreparedStatement.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Athena prepared statement " + resourceID}
		return base
	}

	_, err = f.clients.Athena.UpdatePreparedStatement(fctx.Ctx, &athena.UpdatePreparedStatementInput{
		WorkGroup:      aws.String(workgroup),
		StatementName:  aws.String(statement),
		QueryStatement: out.PreparedStatement.QueryStatement,
		Description:    aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update prepared statement: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Athena prepared statement " + resourceID}
	return base
}

type athenaWorkgroupDescriptionFix struct{ clients *awsdata.Clients }

func (f *athenaWorkgroupDescriptionFix) CheckID() string { return "athena-workgroup-description" }
func (f *athenaWorkgroupDescriptionFix) Description() string {
	return "Set Athena workgroup description"
}
func (f *athenaWorkgroupDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *athenaWorkgroupDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *athenaWorkgroupDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing workgroup name"
		return base
	}

	out, err := f.clients.Athena.GetWorkGroup(fctx.Ctx, &athena.GetWorkGroupInput{WorkGroup: aws.String(name)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get workgroup: " + err.Error()
		return base
	}
	if out.WorkGroup != nil && out.WorkGroup.Description != nil && strings.TrimSpace(*out.WorkGroup.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Athena workgroup " + name}
		return base
	}

	_, err = f.clients.Athena.UpdateWorkGroup(fctx.Ctx, &athena.UpdateWorkGroupInput{
		WorkGroup:   aws.String(name),
		Description: aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update workgroup: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Athena workgroup " + name}
	return base
}

type ebApplicationDescriptionFix struct{ clients *awsdata.Clients }

func (f *ebApplicationDescriptionFix) CheckID() string {
	return "elasticbeanstalk-application-description"
}
func (f *ebApplicationDescriptionFix) Description() string {
	return "Set Elastic Beanstalk application description"
}
func (f *ebApplicationDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebApplicationDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ebApplicationDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing application name"
		return base
	}

	out, err := f.clients.ElasticBeanstalk.DescribeApplications(fctx.Ctx, &elasticbeanstalk.DescribeApplicationsInput{
		ApplicationNames: []string{name},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe applications: " + err.Error()
		return base
	}
	if len(out.Applications) > 0 && out.Applications[0].Description != nil && strings.TrimSpace(*out.Applications[0].Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Elastic Beanstalk application " + name}
		return base
	}

	_, err = f.clients.ElasticBeanstalk.UpdateApplication(fctx.Ctx, &elasticbeanstalk.UpdateApplicationInput{
		ApplicationName: aws.String(name),
		Description:     aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update application: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Elastic Beanstalk application " + name}
	return base
}

type ebApplicationVersionDescriptionFix struct{ clients *awsdata.Clients }

func (f *ebApplicationVersionDescriptionFix) CheckID() string {
	return "elasticbeanstalk-application-version-description"
}
func (f *ebApplicationVersionDescriptionFix) Description() string {
	return "Set Elastic Beanstalk application version description"
}
func (f *ebApplicationVersionDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebApplicationVersionDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ebApplicationVersionDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	versions, err := f.clients.ElasticBeanstalk.DescribeApplicationVersions(fctx.Ctx, &elasticbeanstalk.DescribeApplicationVersionsInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe application versions: " + err.Error()
		return base
	}

	var appName, versionLabel string
	for _, v := range versions.ApplicationVersions {
		if v.ApplicationVersionArn != nil && *v.ApplicationVersionArn == resourceID {
			appName = aws.ToString(v.ApplicationName)
			versionLabel = aws.ToString(v.VersionLabel)
			if v.Description != nil && strings.TrimSpace(*v.Description) != "" {
				base.Status = fix.FixSkipped
				base.Message = "description already set"
				return base
			}
			break
		}
	}
	if appName == "" || versionLabel == "" {
		base.Status = fix.FixFailed
		base.Message = "application version not found by ARN"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Elastic Beanstalk application version " + versionLabel}
		return base
	}

	_, err = f.clients.ElasticBeanstalk.UpdateApplicationVersion(fctx.Ctx, &elasticbeanstalk.UpdateApplicationVersionInput{
		ApplicationName: aws.String(appName),
		VersionLabel:    aws.String(versionLabel),
		Description:     aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update application version: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Elastic Beanstalk application version " + versionLabel}
	return base
}

type ebEnvironmentDescriptionFix struct{ clients *awsdata.Clients }

func (f *ebEnvironmentDescriptionFix) CheckID() string {
	return "elasticbeanstalk-environment-description"
}
func (f *ebEnvironmentDescriptionFix) Description() string {
	return "Set Elastic Beanstalk environment description"
}
func (f *ebEnvironmentDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebEnvironmentDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ebEnvironmentDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	envName := ebEnvName(resourceID)
	if strings.TrimSpace(envName) == "" {
		base.Status = fix.FixFailed
		base.Message = "missing environment name"
		return base
	}

	envs, err := f.clients.ElasticBeanstalk.DescribeEnvironments(fctx.Ctx, &elasticbeanstalk.DescribeEnvironmentsInput{
		EnvironmentNames: []string{envName},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe environments: " + err.Error()
		return base
	}
	if len(envs.Environments) > 0 && envs.Environments[0].Description != nil && strings.TrimSpace(*envs.Environments[0].Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Elastic Beanstalk environment " + envName}
		return base
	}

	_, err = f.clients.ElasticBeanstalk.UpdateEnvironment(fctx.Ctx, &elasticbeanstalk.UpdateEnvironmentInput{
		EnvironmentName: aws.String(envName),
		Description:     aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update environment: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Elastic Beanstalk environment " + envName}
	return base
}

type transferAgreementDescriptionFix struct{ clients *awsdata.Clients }

func (f *transferAgreementDescriptionFix) CheckID() string { return "transfer-agreement-description" }
func (f *transferAgreementDescriptionFix) Description() string {
	return "Set Transfer agreement description"
}
func (f *transferAgreementDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *transferAgreementDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *transferAgreementDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	agreementID := strings.TrimSpace(resourceID)
	if agreementID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing agreement ID"
		return base
	}

	agreements, err := f.clients.Transfer.ListAgreements(fctx.Ctx, &transfer.ListAgreementsInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list agreements: " + err.Error()
		return base
	}

	serverID := ""
	for _, a := range agreements.Agreements {
		if a.AgreementId != nil && *a.AgreementId == agreementID && a.ServerId != nil {
			serverID = *a.ServerId
			break
		}
	}
	if serverID == "" {
		base.Status = fix.FixFailed
		base.Message = "agreement not found"
		return base
	}

	out, err := f.clients.Transfer.DescribeAgreement(fctx.Ctx, &transfer.DescribeAgreementInput{
		AgreementId: aws.String(agreementID),
		ServerId:    aws.String(serverID),
	})
	if err == nil && out.Agreement != nil && out.Agreement.Description != nil && strings.TrimSpace(*out.Agreement.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Transfer agreement " + agreementID}
		return base
	}

	_, err = f.clients.Transfer.UpdateAgreement(fctx.Ctx, &transfer.UpdateAgreementInput{
		AgreementId: aws.String(agreementID),
		ServerId:    aws.String(serverID),
		Description: aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update agreement: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Transfer agreement " + agreementID}
	return base
}

type transferCertificateDescriptionFix struct{ clients *awsdata.Clients }

func (f *transferCertificateDescriptionFix) CheckID() string {
	return "transfer-certificate-description"
}
func (f *transferCertificateDescriptionFix) Description() string {
	return "Set Transfer certificate description"
}
func (f *transferCertificateDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *transferCertificateDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *transferCertificateDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	certID := strings.TrimSpace(resourceID)
	if certID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing certificate ID"
		return base
	}

	out, err := f.clients.Transfer.DescribeCertificate(fctx.Ctx, &transfer.DescribeCertificateInput{
		CertificateId: aws.String(certID),
	})
	if err == nil && out.Certificate != nil && out.Certificate.Description != nil && strings.TrimSpace(*out.Certificate.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Transfer certificate " + certID}
		return base
	}

	_, err = f.clients.Transfer.UpdateCertificate(fctx.Ctx, &transfer.UpdateCertificateInput{
		CertificateId: aws.String(certID),
		Description:   aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update certificate: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Transfer certificate " + certID}
	return base
}

type sagemakerImageDescriptionFix struct{ clients *awsdata.Clients }

func (f *sagemakerImageDescriptionFix) CheckID() string             { return "sagemaker-image-description" }
func (f *sagemakerImageDescriptionFix) Description() string         { return "Set SageMaker image description" }
func (f *sagemakerImageDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *sagemakerImageDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *sagemakerImageDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	id := strings.TrimSpace(resourceID)
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing image ID"
		return base
	}

	images, err := f.clients.SageMaker.ListImages(fctx.Ctx, &sagemaker.ListImagesInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list images: " + err.Error()
		return base
	}

	imageName := ""
	for _, img := range images.Images {
		if (img.ImageArn != nil && *img.ImageArn == id) || (img.ImageName != nil && *img.ImageName == id) {
			imageName = aws.ToString(img.ImageName)
			break
		}
	}
	if imageName == "" && strings.HasPrefix(id, "arn:") {
		parts := strings.Split(id, "/")
		imageName = parts[len(parts)-1]
	}
	if imageName == "" {
		base.Status = fix.FixFailed
		base.Message = "SageMaker image not found"
		return base
	}

	desc, err := f.clients.SageMaker.DescribeImage(fctx.Ctx, &sagemaker.DescribeImageInput{
		ImageName: aws.String(imageName),
	})
	if err == nil && desc.Description != nil && strings.TrimSpace(*desc.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on SageMaker image " + imageName}
		return base
	}

	_, err = f.clients.SageMaker.UpdateImage(fctx.Ctx, &sagemaker.UpdateImageInput{
		ImageName:   aws.String(imageName),
		Description: aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = fmt.Sprintf("update SageMaker image %s: %v", imageName, err)
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on SageMaker image " + imageName}
	return base
}

type ec2TrafficMirrorSessionDescriptionFix struct{ clients *awsdata.Clients }

func (f *ec2TrafficMirrorSessionDescriptionFix) CheckID() string {
	return "ec2-traffic-mirror-session-description"
}
func (f *ec2TrafficMirrorSessionDescriptionFix) Description() string {
	return "Set EC2 traffic mirror session description"
}
func (f *ec2TrafficMirrorSessionDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ec2TrafficMirrorSessionDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ec2TrafficMirrorSessionDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	id := strings.TrimSpace(resourceID)
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing traffic mirror session ID"
		return base
	}

	out, err := f.clients.EC2.DescribeTrafficMirrorSessions(fctx.Ctx, &ec2.DescribeTrafficMirrorSessionsInput{
		TrafficMirrorSessionIds: []string{id},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe traffic mirror sessions: " + err.Error()
		return base
	}
	if len(out.TrafficMirrorSessions) == 0 {
		base.Status = fix.FixFailed
		base.Message = "traffic mirror session not found"
		return base
	}
	if out.TrafficMirrorSessions[0].Description != nil && strings.TrimSpace(*out.TrafficMirrorSessions[0].Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on traffic mirror session " + id}
		return base
	}

	_, err = f.clients.EC2.ModifyTrafficMirrorSession(fctx.Ctx, &ec2.ModifyTrafficMirrorSessionInput{
		TrafficMirrorSessionId: aws.String(id),
		Description:            aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify traffic mirror session: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on traffic mirror session " + id}
	return base
}

type evidentlyProjectDescriptionFix struct{ clients *awsdata.Clients }

func (f *evidentlyProjectDescriptionFix) CheckID() string { return "evidently-project-description" }
func (f *evidentlyProjectDescriptionFix) Description() string {
	return "Set Evidently project description"
}
func (f *evidentlyProjectDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *evidentlyProjectDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *evidentlyProjectDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	project := strings.TrimSpace(resourceID)
	if project == "" {
		base.Status = fix.FixFailed
		base.Message = "missing project ID"
		return base
	}

	out, err := f.clients.Evidently.GetProject(fctx.Ctx, &evidently.GetProjectInput{Project: aws.String(project)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get project: " + err.Error()
		return base
	}
	if out.Project != nil && out.Project.Description != nil && strings.TrimSpace(*out.Project.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Evidently project " + project}
		return base
	}

	_, err = f.clients.Evidently.UpdateProject(fctx.Ctx, &evidently.UpdateProjectInput{
		Project:     aws.String(project),
		Description: aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update project: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Evidently project " + project}
	return base
}

type evidentlyLaunchDescriptionFix struct{ clients *awsdata.Clients }

func (f *evidentlyLaunchDescriptionFix) CheckID() string { return "evidently-launch-description" }
func (f *evidentlyLaunchDescriptionFix) Description() string {
	return "Set Evidently launch description"
}
func (f *evidentlyLaunchDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *evidentlyLaunchDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *evidentlyLaunchDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	launch := strings.TrimSpace(resourceID)
	if launch == "" {
		base.Status = fix.FixFailed
		base.Message = "missing launch ID"
		return base
	}
	project := evidentlyLaunchProjectFromARN(launch)
	if project == "" {
		base.Status = fix.FixFailed
		base.Message = "unable to determine project from launch ARN"
		return base
	}

	out, err := f.clients.Evidently.GetLaunch(fctx.Ctx, &evidently.GetLaunchInput{
		Project: aws.String(project),
		Launch:  aws.String(launch),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get launch: " + err.Error()
		return base
	}
	if out.Launch != nil && out.Launch.Description != nil && strings.TrimSpace(*out.Launch.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "description already set"
		return base
	}
	if out.Launch == nil || out.Launch.Name == nil || strings.TrimSpace(*out.Launch.Name) == "" {
		base.Status = fix.FixFailed
		base.Message = "launch not found"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on Evidently launch " + *out.Launch.Name}
		return base
	}

	_, err = f.clients.Evidently.UpdateLaunch(fctx.Ctx, &evidently.UpdateLaunchInput{
		Project:     aws.String(project),
		Launch:      out.Launch.Name,
		Description: aws.String(defaultAutoDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update launch: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on Evidently launch " + *out.Launch.Name}
	return base
}
