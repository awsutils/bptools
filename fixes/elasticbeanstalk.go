package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
)

// ebEnvName extracts the environment name from an ARN or returns the value as-is
// if it is already a plain name. ARN format:
//   arn:aws:elasticbeanstalk:region:account:environment/app-name/env-name
func ebEnvName(resourceID string) string {
	if strings.HasPrefix(resourceID, "arn:") {
		parts := strings.Split(resourceID, "/")
		return parts[len(parts)-1]
	}
	return resourceID
}

// ebOptionSetting is a convenience constructor for OptionSettings.
func ebOptionSetting(namespace, name, value string) ebtypes.ConfigurationOptionSetting {
	return ebtypes.ConfigurationOptionSetting{
		Namespace:  aws.String(namespace),
		OptionName: aws.String(name),
		Value:      aws.String(value),
	}
}

// ── elastic-beanstalk-logs-to-cloudwatch ─────────────────────────────────────

type ebLogsToCloudWatchFix struct{ clients *awsdata.Clients }

func (f *ebLogsToCloudWatchFix) CheckID() string {
	return "elastic-beanstalk-logs-to-cloudwatch"
}
func (f *ebLogsToCloudWatchFix) Description() string {
	return "Enable CloudWatch log streaming on Elastic Beanstalk environment"
}
func (f *ebLogsToCloudWatchFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebLogsToCloudWatchFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ebLogsToCloudWatchFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	envName := ebEnvName(resourceID)

	// Idempotency check
	out, err := f.clients.ElasticBeanstalk.DescribeConfigurationSettings(fctx.Ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		EnvironmentName: aws.String(envName),
		ApplicationName: aws.String(""), // optional; SDK will use env name alone
	})
	if err == nil && len(out.ConfigurationSettings) > 0 {
		for _, opt := range out.ConfigurationSettings[0].OptionSettings {
			if opt.Namespace != nil && *opt.Namespace == "aws:elasticbeanstalk:cloudwatch:logs" &&
				opt.OptionName != nil && *opt.OptionName == "StreamLogs" &&
				opt.Value != nil && strings.EqualFold(*opt.Value, "true") {
				base.Status = fix.FixSkipped
				base.Message = "CloudWatch log streaming already enabled"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable CloudWatch log streaming on Elastic Beanstalk environment " + envName}
		return base
	}

	_, err = f.clients.ElasticBeanstalk.UpdateEnvironment(fctx.Ctx, &elasticbeanstalk.UpdateEnvironmentInput{
		EnvironmentName: aws.String(envName),
		OptionSettings: []ebtypes.ConfigurationOptionSetting{
			ebOptionSetting("aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs", "true"),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update environment: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled CloudWatch log streaming on Elastic Beanstalk environment " + envName}
	base.Status = fix.FixApplied
	return base
}

// ── elastic-beanstalk-managed-updates-enabled ─────────────────────────────────

type ebManagedUpdatesFix struct{ clients *awsdata.Clients }

func (f *ebManagedUpdatesFix) CheckID() string {
	return "elastic-beanstalk-managed-updates-enabled"
}
func (f *ebManagedUpdatesFix) Description() string {
	return "Enable managed platform updates on Elastic Beanstalk environment"
}
func (f *ebManagedUpdatesFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebManagedUpdatesFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ebManagedUpdatesFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	envName := ebEnvName(resourceID)

	// Idempotency check
	out, err := f.clients.ElasticBeanstalk.DescribeConfigurationSettings(fctx.Ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		EnvironmentName: aws.String(envName),
		ApplicationName: aws.String(""),
	})
	if err == nil && len(out.ConfigurationSettings) > 0 {
		for _, opt := range out.ConfigurationSettings[0].OptionSettings {
			if opt.Namespace != nil && *opt.Namespace == "aws:elasticbeanstalk:managedactions" &&
				opt.OptionName != nil && *opt.OptionName == "ManagedActionsEnabled" &&
				opt.Value != nil && strings.EqualFold(*opt.Value, "true") {
				base.Status = fix.FixSkipped
				base.Message = "managed updates already enabled"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable managed updates on Elastic Beanstalk environment " + envName}
		return base
	}

	_, err = f.clients.ElasticBeanstalk.UpdateEnvironment(fctx.Ctx, &elasticbeanstalk.UpdateEnvironmentInput{
		EnvironmentName: aws.String(envName),
		OptionSettings: []ebtypes.ConfigurationOptionSetting{
			ebOptionSetting("aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled", "true"),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update environment: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled managed updates on Elastic Beanstalk environment " + envName}
	base.Status = fix.FixApplied
	return base
}

// ── beanstalk-enhanced-health-reporting-enabled ───────────────────────────────

type ebEnhancedHealthFix struct{ clients *awsdata.Clients }

func (f *ebEnhancedHealthFix) CheckID() string {
	return "beanstalk-enhanced-health-reporting-enabled"
}
func (f *ebEnhancedHealthFix) Description() string {
	return "Enable enhanced health reporting on Elastic Beanstalk environment"
}
func (f *ebEnhancedHealthFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ebEnhancedHealthFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ebEnhancedHealthFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	envName := ebEnvName(resourceID)

	// Idempotency check
	out, err := f.clients.ElasticBeanstalk.DescribeConfigurationSettings(fctx.Ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		EnvironmentName: aws.String(envName),
		ApplicationName: aws.String(""),
	})
	if err == nil && len(out.ConfigurationSettings) > 0 {
		for _, opt := range out.ConfigurationSettings[0].OptionSettings {
			if opt.Namespace != nil && *opt.Namespace == "aws:elasticbeanstalk:healthreporting:system" &&
				opt.OptionName != nil && *opt.OptionName == "HealthReportingSystem" &&
				opt.Value != nil && strings.EqualFold(*opt.Value, "enhanced") {
				base.Status = fix.FixSkipped
				base.Message = "enhanced health reporting already enabled"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable enhanced health reporting on Elastic Beanstalk environment " + envName}
		return base
	}

	_, err = f.clients.ElasticBeanstalk.UpdateEnvironment(fctx.Ctx, &elasticbeanstalk.UpdateEnvironmentInput{
		EnvironmentName: aws.String(envName),
		OptionSettings: []ebtypes.ConfigurationOptionSetting{
			ebOptionSetting("aws:elasticbeanstalk:healthreporting:system", "HealthReportingSystem", "enhanced"),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update environment: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled enhanced health reporting on Elastic Beanstalk environment " + envName}
	base.Status = fix.FixApplied
	return base
}
