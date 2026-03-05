package fixes

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	appstreamtypes "github.com/aws/aws-sdk-go-v2/service/appstream/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	codepipelinetypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/customerprofiles"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/fis"
	fistypes "github.com/aws/aws-sdk-go-v2/service/fis/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	servicecatalog "github.com/aws/aws-sdk-go-v2/service/servicecatalog"
	servicecatalogtypes "github.com/aws/aws-sdk-go-v2/service/servicecatalog/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

func registerMultiBatch01(d *awsdata.Data) {
	fix.Register(&appStreamFleetInVPCFix{clients: d.Clients})
	fix.Register(&customerProfilesObjectTypeAllowProfileCreationFix{clients: d.Clients})
	fix.Register(&fisExperimentTemplateLogConfigurationExistsFix{clients: d.Clients})
	fix.Register(&serviceCatalogSharedWithinOrganizationFix{clients: d.Clients})
	fix.Register(&codePipelineDeploymentCountFix{clients: d.Clients})
	fix.Register(&codePipelineRegionFanoutFix{clients: d.Clients})
	fix.Register(&appRunnerServiceInVPCFix{clients: d.Clients})
	fix.Register(&appRunnerServiceIPAddressTypeFix{clients: d.Clients})
	fix.Register(&appRunnerServiceMaxUnhealthyThresholdFix{clients: d.Clients})
	fix.Register(&appRunnerServiceNoPublicAccessFix{clients: d.Clients})
}

type defaultVPCResources struct {
	VPCID            string
	SubnetIDs        []string
	SecurityGroupIDs []string
}

func resolveDefaultVPCResources(fctx fix.FixContext, clients *awsdata.Clients, minSubnets int) (*defaultVPCResources, error) {
	vpcs, err := clients.EC2.DescribeVpcs(fctx.Ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
	})
	if err != nil {
		return nil, err
	}
	if len(vpcs.Vpcs) == 0 || vpcs.Vpcs[0].VpcId == nil || strings.TrimSpace(*vpcs.Vpcs[0].VpcId) == "" {
		return nil, fmt.Errorf("default VPC not found")
	}
	vpcID := strings.TrimSpace(*vpcs.Vpcs[0].VpcId)

	subnetsOut, err := clients.EC2.DescribeSubnets(fctx.Ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("state"), Values: []string{"available"}},
		},
	})
	if err != nil {
		return nil, err
	}
	type subnetRow struct {
		az string
		id string
	}
	rows := make([]subnetRow, 0, len(subnetsOut.Subnets))
	for _, s := range subnetsOut.Subnets {
		if s.SubnetId == nil || strings.TrimSpace(*s.SubnetId) == "" {
			continue
		}
		rows = append(rows, subnetRow{az: aws.ToString(s.AvailabilityZone), id: *s.SubnetId})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].az == rows[j].az {
			return rows[i].id < rows[j].id
		}
		return rows[i].az < rows[j].az
	})
	seenAZ := make(map[string]bool)
	subnets := make([]string, 0, 3)
	for _, r := range rows {
		if len(subnets) >= 3 {
			break
		}
		if !seenAZ[r.az] {
			subnets = append(subnets, r.id)
			seenAZ[r.az] = true
		}
	}
	if len(subnets) < minSubnets {
		for _, r := range rows {
			if len(subnets) >= minSubnets {
				break
			}
			already := false
			for _, existing := range subnets {
				if existing == r.id {
					already = true
					break
				}
			}
			if !already {
				subnets = append(subnets, r.id)
			}
		}
	}
	if len(subnets) < minSubnets {
		return nil, fmt.Errorf("default VPC has %d usable subnets; need at least %d", len(subnets), minSubnets)
	}

	sgOut, err := clients.EC2.DescribeSecurityGroups(fctx.Ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("group-name"), Values: []string{"default"}},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(sgOut.SecurityGroups) == 0 || sgOut.SecurityGroups[0].GroupId == nil || strings.TrimSpace(*sgOut.SecurityGroups[0].GroupId) == "" {
		return nil, fmt.Errorf("default security group not found in VPC %s", vpcID)
	}

	return &defaultVPCResources{
		VPCID:            vpcID,
		SubnetIDs:        subnets,
		SecurityGroupIDs: []string{*sgOut.SecurityGroups[0].GroupId},
	}, nil
}

func parseAppStreamFleetName(resourceID string) string {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(id), "arn:") {
		return id
	}
	parts := strings.Split(id, "/")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func parseCustomerProfilesObjectTypeID(resourceID string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(resourceID), ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func accountIDFromSTS(fctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	out, err := clients.STS.GetCallerIdentity(fctx.Ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	if out.Account == nil || strings.TrimSpace(*out.Account) == "" {
		return "", fmt.Errorf("missing account ID from STS")
	}
	return strings.TrimSpace(*out.Account), nil
}

func ensureAppRunnerVPCConnector(fctx fix.FixContext, clients *awsdata.Clients) (string, []string, error) {
	listOut, err := clients.AppRunner.ListVpcConnectors(fctx.Ctx, &apprunner.ListVpcConnectorsInput{})
	if err != nil {
		return "", nil, err
	}
	for _, c := range listOut.VpcConnectors {
		if c.VpcConnectorArn != nil && strings.TrimSpace(*c.VpcConnectorArn) != "" && c.Status == apprunnertypes.VpcConnectorStatusActive {
			return strings.TrimSpace(*c.VpcConnectorArn), []string{fmt.Sprintf("reused existing App Runner VPC connector %s", strings.TrimSpace(*c.VpcConnectorArn))}, nil
		}
	}

	vpc, err := resolveDefaultVPCResources(fctx, clients, 1)
	if err != nil {
		return "", nil, err
	}
	name := fmt.Sprintf("bptools-vpc-%d", time.Now().Unix())
	createOut, err := clients.AppRunner.CreateVpcConnector(fctx.Ctx, &apprunner.CreateVpcConnectorInput{
		VpcConnectorName: aws.String(name),
		Subnets:          vpc.SubnetIDs,
		SecurityGroups:   vpc.SecurityGroupIDs,
		Tags:             []apprunnertypes.Tag{{Key: aws.String("bptools:managed-by"), Value: aws.String("bptools")}},
	})
	if err != nil {
		return "", nil, err
	}
	arn := ""
	if createOut.VpcConnector != nil && createOut.VpcConnector.VpcConnectorArn != nil {
		arn = strings.TrimSpace(*createOut.VpcConnector.VpcConnectorArn)
	}
	if arn == "" {
		return "", nil, fmt.Errorf("create VPC connector returned empty ARN")
	}
	return arn, []string{fmt.Sprintf("created App Runner VPC connector %s in default VPC %s", arn, vpc.VPCID)}, nil
}

func getCodePipelineArtifactBucket(p *codepipelinetypes.PipelineDeclaration, homeRegion string) string {
	if p == nil {
		return ""
	}
	if p.ArtifactStore != nil && strings.TrimSpace(aws.ToString(p.ArtifactStore.Location)) != "" {
		return strings.TrimSpace(aws.ToString(p.ArtifactStore.Location))
	}
	if len(p.ArtifactStores) == 0 {
		return ""
	}
	if homeRegion != "" {
		if s, ok := p.ArtifactStores[homeRegion]; ok && strings.TrimSpace(aws.ToString(s.Location)) != "" {
			return strings.TrimSpace(aws.ToString(s.Location))
		}
	}
	for _, s := range p.ArtifactStores {
		if strings.TrimSpace(aws.ToString(s.Location)) != "" {
			return strings.TrimSpace(aws.ToString(s.Location))
		}
	}
	return ""
}

func firstPipelineOutputArtifactName(p *codepipelinetypes.PipelineDeclaration) string {
	if p == nil {
		return ""
	}
	for _, st := range p.Stages {
		for _, act := range st.Actions {
			for _, out := range act.OutputArtifacts {
				if out.Name != nil && strings.TrimSpace(*out.Name) != "" {
					return strings.TrimSpace(*out.Name)
				}
			}
		}
	}
	return ""
}

func uniqueActionName(st *codepipelinetypes.StageDeclaration, base string) string {
	candidate := base
	used := make(map[string]bool)
	for _, a := range st.Actions {
		if a.Name != nil {
			used[strings.TrimSpace(*a.Name)] = true
		}
	}
	if !used[candidate] {
		return candidate
	}
	for i := 2; i < 1000; i++ {
		n := fmt.Sprintf("%s%d", base, i)
		if !used[n] {
			return n
		}
	}
	return fmt.Sprintf("%s%d", base, time.Now().Unix())
}

// 1) appstream-fleet-in-vpc

type appStreamFleetInVPCFix struct{ clients *awsdata.Clients }

func (f *appStreamFleetInVPCFix) CheckID() string { return "appstream-fleet-in-vpc" }
func (f *appStreamFleetInVPCFix) Description() string {
	return "Configure AppStream fleet with VPC subnets"
}
func (f *appStreamFleetInVPCFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appStreamFleetInVPCFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *appStreamFleetInVPCFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	fleetName := parseAppStreamFleetName(resourceID)
	if fleetName == "" {
		base.Status = fix.FixFailed
		base.Message = "missing fleet identifier"
		return base
	}

	descOut, err := f.clients.AppStream.DescribeFleets(fctx.Ctx, &appstream.DescribeFleetsInput{Names: []string{fleetName}})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe fleets: " + err.Error()
		return base
	}
	if len(descOut.Fleets) == 0 {
		base.Status = fix.FixFailed
		base.Message = "fleet not found: " + fleetName
		return base
	}
	fleet := descOut.Fleets[0]
	if fleet.VpcConfig != nil && len(fleet.VpcConfig.SubnetIds) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "fleet already associated with VPC subnets"
		return base
	}
	if fleet.FleetType == appstreamtypes.FleetTypeElastic {
		base.Status = fix.FixSkipped
		base.Message = "elastic fleet networking requirements vary; skip automatic VPC assignment"
		return base
	}

	vpc, err := resolveDefaultVPCResources(fctx, f.clients, 1)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve default VPC resources: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would associate fleet %s with default VPC %s", fleetName, vpc.VPCID),
			fmt.Sprintf("would configure subnets %v and security groups %v", vpc.SubnetIDs, vpc.SecurityGroupIDs),
		}
		return base
	}

	_, err = f.clients.AppStream.UpdateFleet(fctx.Ctx, &appstream.UpdateFleetInput{
		Name: aws.String(fleetName),
		VpcConfig: &appstreamtypes.VpcConfig{
			SubnetIds:        vpc.SubnetIDs,
			SecurityGroupIds: vpc.SecurityGroupIDs,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update fleet: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("associated AppStream fleet %s with default VPC %s", fleetName, vpc.VPCID)}
	return base
}

// 2) customerprofiles-object-type-allow-profile-creation

type customerProfilesObjectTypeAllowProfileCreationFix struct{ clients *awsdata.Clients }

func (f *customerProfilesObjectTypeAllowProfileCreationFix) CheckID() string {
	return "customerprofiles-object-type-allow-profile-creation"
}
func (f *customerProfilesObjectTypeAllowProfileCreationFix) Description() string {
	return "Enable AllowProfileCreation for Customer Profiles object type"
}
func (f *customerProfilesObjectTypeAllowProfileCreationFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *customerProfilesObjectTypeAllowProfileCreationFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *customerProfilesObjectTypeAllowProfileCreationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	domain, objectType, ok := parseCustomerProfilesObjectTypeID(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected domain:objectType)"
		return base
	}

	getOut, err := f.clients.CustomerProfiles.GetProfileObjectType(fctx.Ctx, &customerprofiles.GetProfileObjectTypeInput{
		DomainName:     aws.String(domain),
		ObjectTypeName: aws.String(objectType),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get profile object type: " + err.Error()
		return base
	}
	if getOut.AllowProfileCreation {
		base.Status = fix.FixSkipped
		base.Message = "AllowProfileCreation already enabled"
		return base
	}
	if getOut.TemplateId != nil && strings.TrimSpace(*getOut.TemplateId) != "" {
		base.Status = fix.FixSkipped
		base.Message = "object type is template-managed; cannot safely override allowProfileCreation"
		return base
	}
	if getOut.Description == nil || strings.TrimSpace(*getOut.Description) == "" {
		base.Status = fix.FixSkipped
		base.Message = "object type description is missing; PutProfileObjectType requires description"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set AllowProfileCreation=true for Customer Profiles object type %s", resourceID)}
		return base
	}

	_, err = f.clients.CustomerProfiles.PutProfileObjectType(fctx.Ctx, &customerprofiles.PutProfileObjectTypeInput{
		DomainName:                       aws.String(domain),
		ObjectTypeName:                   aws.String(objectType),
		Description:                      getOut.Description,
		AllowProfileCreation:             true,
		EncryptionKey:                    getOut.EncryptionKey,
		ExpirationDays:                   getOut.ExpirationDays,
		Fields:                           getOut.Fields,
		Keys:                             getOut.Keys,
		MaxProfileObjectCount:            getOut.MaxProfileObjectCount,
		SourceLastUpdatedTimestampFormat: getOut.SourceLastUpdatedTimestampFormat,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put profile object type: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("enabled AllowProfileCreation for Customer Profiles object type %s", resourceID)}
	return base
}

// 3) fis-experiment-template-log-configuration-exists

type fisExperimentTemplateLogConfigurationExistsFix struct{ clients *awsdata.Clients }

func (f *fisExperimentTemplateLogConfigurationExistsFix) CheckID() string {
	return "fis-experiment-template-log-configuration-exists"
}
func (f *fisExperimentTemplateLogConfigurationExistsFix) Description() string {
	return "Enable CloudWatch log configuration for FIS experiment template"
}
func (f *fisExperimentTemplateLogConfigurationExistsFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *fisExperimentTemplateLogConfigurationExistsFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *fisExperimentTemplateLogConfigurationExistsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	id := strings.TrimSpace(resourceID)
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing experiment template ID"
		return base
	}

	getOut, err := f.clients.FIS.GetExperimentTemplate(fctx.Ctx, &fis.GetExperimentTemplateInput{Id: aws.String(id)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get experiment template: " + err.Error()
		return base
	}
	if getOut.ExperimentTemplate == nil {
		base.Status = fix.FixFailed
		base.Message = "experiment template not found"
		return base
	}
	t := getOut.ExperimentTemplate
	if t.LogConfiguration != nil && (t.LogConfiguration.CloudWatchLogsConfiguration != nil || t.LogConfiguration.S3Configuration != nil) {
		base.Status = fix.FixSkipped
		base.Message = "log configuration already exists"
		return base
	}

	accountID, err := accountIDFromSTS(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve account ID: " + err.Error()
		return base
	}
	region := strings.TrimSpace(f.clients.FIS.Options().Region)
	logGroupName := fmt.Sprintf("/aws/fis/experiment-template/%s", id)
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", region, accountID, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would ensure CloudWatch log group %s exists", logGroupName),
			fmt.Sprintf("would set FIS template %s log configuration to %s", id, logGroupArn),
		}
		return base
	}

	_, err = f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{LogGroupName: aws.String(logGroupName)})
	if err != nil {
		var apiErr smithy.APIError
		if !strings.Contains(strings.ToLower(err.Error()), "already exists") && (!errors.As(err, &apiErr) || apiErr.ErrorCode() != "ResourceAlreadyExistsException") {
			base.Status = fix.FixFailed
			base.Message = "create log group: " + err.Error()
			return base
		}
	}

	_, err = f.clients.FIS.UpdateExperimentTemplate(fctx.Ctx, &fis.UpdateExperimentTemplateInput{
		Id: aws.String(id),
		LogConfiguration: &fistypes.UpdateExperimentTemplateLogConfigurationInput{
			LogSchemaVersion: aws.Int32(1),
			CloudWatchLogsConfiguration: &fistypes.ExperimentTemplateCloudWatchLogsLogConfigurationInput{
				LogGroupArn: aws.String(logGroupArn),
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update experiment template: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{
		fmt.Sprintf("ensured CloudWatch log group %s", logGroupName),
		fmt.Sprintf("enabled FIS experiment logging for template %s", id),
	}
	return base
}

// 4) service-catalog-shared-within-organization

type serviceCatalogSharedWithinOrganizationFix struct{ clients *awsdata.Clients }

func (f *serviceCatalogSharedWithinOrganizationFix) CheckID() string {
	return "service-catalog-shared-within-organization"
}
func (f *serviceCatalogSharedWithinOrganizationFix) Description() string {
	return "Share Service Catalog portfolio with the AWS Organization"
}
func (f *serviceCatalogSharedWithinOrganizationFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *serviceCatalogSharedWithinOrganizationFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *serviceCatalogSharedWithinOrganizationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	portfolioID := strings.TrimSpace(resourceID)
	if portfolioID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing portfolio ID"
		return base
	}

	accessOut, err := f.clients.ServiceCatalog.ListPortfolioAccess(fctx.Ctx, &servicecatalog.ListPortfolioAccessInput{PortfolioId: aws.String(portfolioID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list portfolio access: " + err.Error()
		return base
	}
	if len(accessOut.AccountIds) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "portfolio already shared with one or more accounts"
		return base
	}

	orgOut, err := f.clients.Organizations.DescribeOrganization(fctx.Ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe organization: " + err.Error()
		return base
	}
	if orgOut.Organization == nil || orgOut.Organization.Id == nil || strings.TrimSpace(*orgOut.Organization.Id) == "" {
		base.Status = fix.FixFailed
		base.Message = "organization ID unavailable"
		return base
	}
	orgID := strings.TrimSpace(*orgOut.Organization.Id)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would share portfolio %s with organization %s", portfolioID, orgID)}
		return base
	}

	_, err = f.clients.ServiceCatalog.CreatePortfolioShare(fctx.Ctx, &servicecatalog.CreatePortfolioShareInput{
		PortfolioId: aws.String(portfolioID),
		OrganizationNode: &servicecatalogtypes.OrganizationNode{
			Type:  servicecatalogtypes.OrganizationNodeTypeOrganization,
			Value: aws.String(orgID),
		},
		ShareTagOptions: true,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create portfolio share: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("shared portfolio %s with organization %s", portfolioID, orgID)}
	return base
}

// 5) codepipeline-deployment-count-check

type codePipelineDeploymentCountFix struct{ clients *awsdata.Clients }

func (f *codePipelineDeploymentCountFix) CheckID() string {
	return "codepipeline-deployment-count-check"
}
func (f *codePipelineDeploymentCountFix) Description() string {
	return "Ensure pipeline has at least one deploy action"
}
func (f *codePipelineDeploymentCountFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *codePipelineDeploymentCountFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *codePipelineDeploymentCountFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing pipeline name"
		return base
	}

	getOut, err := f.clients.CodePipeline.GetPipeline(fctx.Ctx, &codepipeline.GetPipelineInput{Name: aws.String(name)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get pipeline: " + err.Error()
		return base
	}
	if getOut.Pipeline == nil {
		base.Status = fix.FixFailed
		base.Message = "pipeline not found"
		return base
	}
	p := *getOut.Pipeline
	deployCount := 0
	for _, st := range p.Stages {
		for _, a := range st.Actions {
			if a.ActionTypeId != nil && a.ActionTypeId.Category == codepipelinetypes.ActionCategoryDeploy {
				deployCount++
			}
		}
	}
	if deployCount > 0 {
		base.Status = fix.FixSkipped
		base.Message = "pipeline already has deploy actions"
		return base
	}
	if len(p.Stages) == 0 {
		base.Status = fix.FixFailed
		base.Message = "pipeline has no stages"
		return base
	}

	artifactName := firstPipelineOutputArtifactName(&p)
	if artifactName == "" {
		base.Status = fix.FixSkipped
		base.Message = "no output artifact found; cannot auto-add S3 deploy action safely"
		return base
	}
	artifactBucket := getCodePipelineArtifactBucket(&p, strings.TrimSpace(f.clients.CodePipeline.Options().Region))
	if artifactBucket == "" {
		base.Status = fix.FixSkipped
		base.Message = "pipeline artifact bucket unavailable; cannot auto-add S3 deploy action safely"
		return base
	}

	last := len(p.Stages) - 1
	maxRunOrder := int32(0)
	for _, a := range p.Stages[last].Actions {
		if a.RunOrder != nil && *a.RunOrder > maxRunOrder {
			maxRunOrder = *a.RunOrder
		}
	}
	if maxRunOrder == 0 {
		maxRunOrder = 1
	}
	actionName := uniqueActionName(&p.Stages[last], "AutoDeployS3")
	newAction := codepipelinetypes.ActionDeclaration{
		Name: aws.String(actionName),
		ActionTypeId: &codepipelinetypes.ActionTypeId{
			Category: codepipelinetypes.ActionCategoryDeploy,
			Owner:    codepipelinetypes.ActionOwnerAws,
			Provider: aws.String("S3"),
			Version:  aws.String("1"),
		},
		Configuration: map[string]string{
			"BucketName": artifactBucket,
			"Extract":    "true",
		},
		InputArtifacts: []codepipelinetypes.InputArtifact{{Name: aws.String(artifactName)}},
		RunOrder:       aws.Int32(maxRunOrder + 1),
	}
	p.Stages[last].Actions = append(p.Stages[last].Actions, newAction)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would add Deploy(S3) action %s to pipeline %s", actionName, name),
			fmt.Sprintf("would deploy artifact %s to bucket %s", artifactName, artifactBucket),
		}
		return base
	}

	_, err = f.clients.CodePipeline.UpdatePipeline(fctx.Ctx, &codepipeline.UpdatePipelineInput{Pipeline: &p})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update pipeline: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("added Deploy(S3) action %s to pipeline %s", actionName, name)}
	return base
}

// 6) codepipeline-region-fanout-check

type codePipelineRegionFanoutFix struct{ clients *awsdata.Clients }

func (f *codePipelineRegionFanoutFix) CheckID() string {
	return "codepipeline-region-fanout-check"
}
func (f *codePipelineRegionFanoutFix) Description() string {
	return "Ensure pipeline actions target more than one region where safe"
}
func (f *codePipelineRegionFanoutFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *codePipelineRegionFanoutFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *codePipelineRegionFanoutFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing pipeline name"
		return base
	}

	getOut, err := f.clients.CodePipeline.GetPipeline(fctx.Ctx, &codepipeline.GetPipelineInput{Name: aws.String(name)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get pipeline: " + err.Error()
		return base
	}
	if getOut.Pipeline == nil {
		base.Status = fix.FixFailed
		base.Message = "pipeline not found"
		return base
	}
	p := *getOut.Pipeline

	regions := make(map[string]bool)
	for _, st := range p.Stages {
		for _, a := range st.Actions {
			if a.Region != nil && strings.TrimSpace(*a.Region) != "" {
				regions[strings.TrimSpace(*a.Region)] = true
			}
		}
	}
	if len(regions) > 1 {
		base.Status = fix.FixSkipped
		base.Message = "pipeline already deploys across multiple regions"
		return base
	}
	if len(p.ArtifactStores) < 2 {
		base.Status = fix.FixSkipped
		base.Message = "cross-region artifact stores are not configured; skipping automatic fanout mutation"
		return base
	}

	homeRegion := strings.TrimSpace(f.clients.CodePipeline.Options().Region)
	secondaryRegion := ""
	for r := range p.ArtifactStores {
		if strings.TrimSpace(r) != "" && strings.TrimSpace(r) != homeRegion {
			secondaryRegion = strings.TrimSpace(r)
			break
		}
	}
	if secondaryRegion == "" {
		base.Status = fix.FixSkipped
		base.Message = "no secondary artifact store region available"
		return base
	}

	updated := false
	for si := range p.Stages {
		for ai := range p.Stages[si].Actions {
			a := &p.Stages[si].Actions[ai]
			if a.ActionTypeId == nil {
				continue
			}
			if a.ActionTypeId.Category != codepipelinetypes.ActionCategoryDeploy {
				continue
			}
			if a.Region != nil && strings.TrimSpace(*a.Region) == secondaryRegion {
				updated = true
				break
			}
			a.Region = aws.String(secondaryRegion)
			updated = true
			break
		}
		if updated {
			break
		}
	}
	if !updated {
		base.Status = fix.FixSkipped
		base.Message = "no deploy action found to move to a secondary region"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set one deploy action region to %s for pipeline %s", secondaryRegion, name)}
		return base
	}

	_, err = f.clients.CodePipeline.UpdatePipeline(fctx.Ctx, &codepipeline.UpdatePipelineInput{Pipeline: &p})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update pipeline: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("updated one deploy action region to %s for pipeline %s", secondaryRegion, name)}
	return base
}

// 7) apprunner-service-in-vpc

type appRunnerServiceInVPCFix struct{ clients *awsdata.Clients }

func (f *appRunnerServiceInVPCFix) CheckID() string { return "apprunner-service-in-vpc" }
func (f *appRunnerServiceInVPCFix) Description() string {
	return "Configure App Runner service egress through a VPC connector"
}
func (f *appRunnerServiceInVPCFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appRunnerServiceInVPCFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *appRunnerServiceInVPCFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	arn := strings.TrimSpace(resourceID)
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing service ARN"
		return base
	}

	descOut, err := f.clients.AppRunner.DescribeService(fctx.Ctx, &apprunner.DescribeServiceInput{ServiceArn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe service: " + err.Error()
		return base
	}
	if descOut.Service == nil {
		base.Status = fix.FixFailed
		base.Message = "service not found"
		return base
	}
	svc := descOut.Service
	if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.EgressConfiguration != nil &&
		svc.NetworkConfiguration.EgressConfiguration.EgressType == apprunnertypes.EgressTypeVpc &&
		svc.NetworkConfiguration.EgressConfiguration.VpcConnectorArn != nil &&
		strings.TrimSpace(*svc.NetworkConfiguration.EgressConfiguration.VpcConnectorArn) != "" {
		base.Status = fix.FixSkipped
		base.Message = "service already configured for VPC egress"
		return base
	}

	connectorArn := ""
	steps := []string{}
	if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.EgressConfiguration != nil && svc.NetworkConfiguration.EgressConfiguration.VpcConnectorArn != nil {
		connectorArn = strings.TrimSpace(*svc.NetworkConfiguration.EgressConfiguration.VpcConnectorArn)
	}
	if connectorArn == "" {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{
				"would create or reuse an active App Runner VPC connector",
				fmt.Sprintf("would update service %s to use VPC egress", arn),
			}
			return base
		}
		var connSteps []string
		connectorArn, connSteps, err = ensureAppRunnerVPCConnector(fctx, f.clients)
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "ensure VPC connector: " + err.Error()
			return base
		}
		steps = append(steps, connSteps...)
	}

	network := &apprunnertypes.NetworkConfiguration{}
	if svc.NetworkConfiguration != nil {
		*network = *svc.NetworkConfiguration
	}
	network.EgressConfiguration = &apprunnertypes.EgressConfiguration{
		EgressType:      apprunnertypes.EgressTypeVpc,
		VpcConnectorArn: aws.String(connectorArn),
	}

	_, err = f.clients.AppRunner.UpdateService(fctx.Ctx, &apprunner.UpdateServiceInput{
		ServiceArn:           aws.String(arn),
		NetworkConfiguration: network,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update service: " + err.Error()
		return base
	}

	steps = append(steps, fmt.Sprintf("set App Runner service %s egress type to VPC", arn))
	base.Status = fix.FixApplied
	base.Steps = steps
	return base
}

// 8) apprunner-service-ip-address-type-check

type appRunnerServiceIPAddressTypeFix struct{ clients *awsdata.Clients }

func (f *appRunnerServiceIPAddressTypeFix) CheckID() string {
	return "apprunner-service-ip-address-type-check"
}
func (f *appRunnerServiceIPAddressTypeFix) Description() string {
	return "Set App Runner service IP address type"
}
func (f *appRunnerServiceIPAddressTypeFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *appRunnerServiceIPAddressTypeFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *appRunnerServiceIPAddressTypeFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	arn := strings.TrimSpace(resourceID)
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing service ARN"
		return base
	}

	descOut, err := f.clients.AppRunner.DescribeService(fctx.Ctx, &apprunner.DescribeServiceInput{ServiceArn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe service: " + err.Error()
		return base
	}
	if descOut.Service == nil {
		base.Status = fix.FixFailed
		base.Message = "service not found"
		return base
	}
	svc := descOut.Service
	if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.IpAddressType != "" {
		base.Status = fix.FixSkipped
		base.Message = "IP address type already set"
		return base
	}

	network := &apprunnertypes.NetworkConfiguration{}
	if svc.NetworkConfiguration != nil {
		*network = *svc.NetworkConfiguration
	}
	network.IpAddressType = apprunnertypes.IpAddressTypeIpv4

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set App Runner service %s IpAddressType to IPV4", arn)}
		return base
	}

	_, err = f.clients.AppRunner.UpdateService(fctx.Ctx, &apprunner.UpdateServiceInput{
		ServiceArn:           aws.String(arn),
		NetworkConfiguration: network,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update service: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set App Runner service %s IpAddressType to IPV4", arn)}
	return base
}

// 9) apprunner-service-max-unhealthy-threshold

type appRunnerServiceMaxUnhealthyThresholdFix struct{ clients *awsdata.Clients }

func (f *appRunnerServiceMaxUnhealthyThresholdFix) CheckID() string {
	return "apprunner-service-max-unhealthy-threshold"
}
func (f *appRunnerServiceMaxUnhealthyThresholdFix) Description() string {
	return "Set App Runner unhealthy threshold to 5 or lower"
}
func (f *appRunnerServiceMaxUnhealthyThresholdFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *appRunnerServiceMaxUnhealthyThresholdFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *appRunnerServiceMaxUnhealthyThresholdFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	arn := strings.TrimSpace(resourceID)
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing service ARN"
		return base
	}

	descOut, err := f.clients.AppRunner.DescribeService(fctx.Ctx, &apprunner.DescribeServiceInput{ServiceArn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe service: " + err.Error()
		return base
	}
	if descOut.Service == nil {
		base.Status = fix.FixFailed
		base.Message = "service not found"
		return base
	}
	svc := descOut.Service

	current := int32(0)
	if svc.HealthCheckConfiguration != nil && svc.HealthCheckConfiguration.UnhealthyThreshold != nil {
		current = *svc.HealthCheckConfiguration.UnhealthyThreshold
	}
	if current > 0 && current <= 5 {
		base.Status = fix.FixSkipped
		base.Message = "unhealthy threshold already compliant"
		return base
	}

	hc := &apprunnertypes.HealthCheckConfiguration{}
	if svc.HealthCheckConfiguration != nil {
		*hc = *svc.HealthCheckConfiguration
	}
	hc.UnhealthyThreshold = aws.Int32(5)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set App Runner service %s unhealthy threshold to 5", arn)}
		return base
	}

	_, err = f.clients.AppRunner.UpdateService(fctx.Ctx, &apprunner.UpdateServiceInput{
		ServiceArn:               aws.String(arn),
		HealthCheckConfiguration: hc,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update service: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set App Runner service %s unhealthy threshold to 5", arn)}
	return base
}

// 10) apprunner-service-no-public-access

type appRunnerServiceNoPublicAccessFix struct{ clients *awsdata.Clients }

func (f *appRunnerServiceNoPublicAccessFix) CheckID() string {
	return "apprunner-service-no-public-access"
}
func (f *appRunnerServiceNoPublicAccessFix) Description() string {
	return "Disable public ingress for App Runner service"
}
func (f *appRunnerServiceNoPublicAccessFix) Impact() fix.ImpactType {
	return fix.ImpactDegradation
}
func (f *appRunnerServiceNoPublicAccessFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *appRunnerServiceNoPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	arn := strings.TrimSpace(resourceID)
	if arn == "" {
		base.Status = fix.FixFailed
		base.Message = "missing service ARN"
		return base
	}

	descOut, err := f.clients.AppRunner.DescribeService(fctx.Ctx, &apprunner.DescribeServiceInput{ServiceArn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe service: " + err.Error()
		return base
	}
	if descOut.Service == nil {
		base.Status = fix.FixFailed
		base.Message = "service not found"
		return base
	}
	svc := descOut.Service

	if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.IngressConfiguration != nil && !svc.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible {
		base.Status = fix.FixSkipped
		base.Message = "public access already disabled"
		return base
	}

	network := &apprunnertypes.NetworkConfiguration{}
	if svc.NetworkConfiguration != nil {
		*network = *svc.NetworkConfiguration
	}
	network.IngressConfiguration = &apprunnertypes.IngressConfiguration{IsPubliclyAccessible: false}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable public ingress for App Runner service %s", arn)}
		return base
	}

	_, err = f.clients.AppRunner.UpdateService(fctx.Ctx, &apprunner.UpdateServiceInput{
		ServiceArn:           aws.String(arn),
		NetworkConfiguration: network,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update service: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("disabled public ingress for App Runner service %s", arn)}
	return base
}
