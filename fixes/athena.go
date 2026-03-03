package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
)

// athenaWorkgroupFix applies a WorkGroupConfigurationUpdates change.
type athenaWorkgroupFix struct {
	checkID      string
	description  string
	severity     fix.SeverityLevel
	alreadyOK    func(cfg *athenatypes.WorkGroupConfiguration) bool
	buildUpdates func() *athenatypes.WorkGroupConfigurationUpdates
	clients      *awsdata.Clients
}

func (f *athenaWorkgroupFix) CheckID() string          { return f.checkID }
func (f *athenaWorkgroupFix) Description() string      { return f.description }
func (f *athenaWorkgroupFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *athenaWorkgroupFix) Severity() fix.SeverityLevel { return f.severity }

func (f *athenaWorkgroupFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Athena.GetWorkGroup(fctx.Ctx, &athena.GetWorkGroupInput{
		WorkGroup: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get workgroup: " + err.Error()
		return base
	}
	var cfg *athenatypes.WorkGroupConfiguration
	if out.WorkGroup != nil {
		cfg = out.WorkGroup.Configuration
	}
	if f.alreadyOK(cfg) {
		base.Status = fix.FixSkipped
		base.Message = f.checkID + " already satisfied"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would apply " + f.checkID + " fix on Athena workgroup " + resourceID}
		return base
	}

	_, err = f.clients.Athena.UpdateWorkGroup(fctx.Ctx, &athena.UpdateWorkGroupInput{
		WorkGroup:            aws.String(resourceID),
		ConfigurationUpdates: f.buildUpdates(),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update workgroup: " + err.Error()
		return base
	}
	base.Steps = []string{"applied " + f.checkID + " fix on Athena workgroup " + resourceID}
	base.Status = fix.FixApplied
	return base
}

func newAthenaEncryptionAtRestFix(clients *awsdata.Clients) *athenaWorkgroupFix {
	return &athenaWorkgroupFix{
		checkID:     "athena-workgroup-encrypted-at-rest",
		description: "Enable encryption at rest for Athena workgroup",
		severity:    fix.SeverityHigh,
		alreadyOK: func(cfg *athenatypes.WorkGroupConfiguration) bool {
			return cfg != nil && cfg.ResultConfiguration != nil && cfg.ResultConfiguration.EncryptionConfiguration != nil
		},
		buildUpdates: func() *athenatypes.WorkGroupConfigurationUpdates {
			return &athenatypes.WorkGroupConfigurationUpdates{
				ResultConfigurationUpdates: &athenatypes.ResultConfigurationUpdates{
					EncryptionConfiguration: &athenatypes.EncryptionConfiguration{
						EncryptionOption: athenatypes.EncryptionOptionSseS3,
					},
				},
			}
		},
		clients: clients,
	}
}

func newAthenaEnforceWorkgroupConfigFix(clients *awsdata.Clients) *athenaWorkgroupFix {
	return &athenaWorkgroupFix{
		checkID:     "athena-workgroup-enforce-workgroup-configuration",
		description: "Enforce workgroup configuration in Athena workgroup",
		severity:    fix.SeverityMedium,
		alreadyOK: func(cfg *athenatypes.WorkGroupConfiguration) bool {
			return cfg != nil && cfg.EnforceWorkGroupConfiguration != nil && *cfg.EnforceWorkGroupConfiguration
		},
		buildUpdates: func() *athenatypes.WorkGroupConfigurationUpdates {
			return &athenatypes.WorkGroupConfigurationUpdates{
				EnforceWorkGroupConfiguration: aws.Bool(true),
			}
		},
		clients: clients,
	}
}

func newAthenaEngineAutoUpgradeFix(clients *awsdata.Clients) *athenaWorkgroupFix {
	return &athenaWorkgroupFix{
		checkID:     "athena-workgroup-engine-version-auto-upgrade",
		description: "Enable auto engine version upgrade for Athena workgroup",
		severity:    fix.SeverityLow,
		alreadyOK: func(cfg *athenatypes.WorkGroupConfiguration) bool {
			return cfg != nil && cfg.EngineVersion != nil && cfg.EngineVersion.SelectedEngineVersion != nil && *cfg.EngineVersion.SelectedEngineVersion == "AUTO"
		},
		buildUpdates: func() *athenatypes.WorkGroupConfigurationUpdates {
			return &athenatypes.WorkGroupConfigurationUpdates{
				EngineVersion: &athenatypes.EngineVersion{
					SelectedEngineVersion: aws.String("AUTO"),
				},
			}
		},
		clients: clients,
	}
}

func newAthenaCloudWatchMetricsFix(clients *awsdata.Clients) *athenaWorkgroupFix {
	return &athenaWorkgroupFix{
		checkID:     "athena-workgroup-logging-enabled",
		description: "Enable CloudWatch metrics for Athena workgroup",
		severity:    fix.SeverityMedium,
		alreadyOK: func(cfg *athenatypes.WorkGroupConfiguration) bool {
			return cfg != nil && cfg.PublishCloudWatchMetricsEnabled != nil && *cfg.PublishCloudWatchMetricsEnabled
		},
		buildUpdates: func() *athenatypes.WorkGroupConfigurationUpdates {
			return &athenatypes.WorkGroupConfigurationUpdates{
				PublishCloudWatchMetricsEnabled: aws.Bool(true),
			}
		},
		clients: clients,
	}
}
