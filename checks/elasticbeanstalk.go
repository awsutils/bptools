package checks

import (
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	ebtypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
)

// RegisterElasticBeanstalkChecks registers Elastic Beanstalk checks.
func RegisterElasticBeanstalkChecks(d *awsdata.Data) {
	checker.Register(DescriptionCheck(
		"elasticbeanstalk-application-description",
		"Checks if AWS Elastic Beanstalk applications have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.",
		"elasticbeanstalk",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			apps, err := d.ElasticBeanstalkApps.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, a := range apps {
				id := "unknown"
				if a.ApplicationName != nil {
					id = *a.ApplicationName
				}
				has := a.Description != nil && *a.Description != ""
				res = append(res, DescriptionResource{ID: id, HasDescription: has})
			}
			return res, nil
		},
	))

	checker.Register(DescriptionCheck(
		"elasticbeanstalk-application-version-description",
		"Checks if AWS Elastic Beanstalk application versions have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.",
		"elasticbeanstalk",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			vers, err := d.ElasticBeanstalkAppVersions.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, v := range vers {
				id := "unknown"
				if v.ApplicationVersionArn != nil {
					id = *v.ApplicationVersionArn
				} else if v.VersionLabel != nil {
					id = *v.VersionLabel
				}
				has := v.Description != nil && *v.Description != ""
				res = append(res, DescriptionResource{ID: id, HasDescription: has})
			}
			return res, nil
		},
	))

	checker.Register(DescriptionCheck(
		"elasticbeanstalk-environment-description",
		"Checks if AWS Elastic Beanstalk environments have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.",
		"elasticbeanstalk",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			envs, err := d.ElasticBeanstalkEnvs.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, e := range envs {
				id := envID(e)
				has := e.Description != nil && *e.Description != ""
				res = append(res, DescriptionResource{ID: id, HasDescription: has})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"elastic-beanstalk-logs-to-cloudwatch",
		"Checks if AWS Elastic Beanstalk environments are configured to send logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if the value of `StreamLogs` is false.",
		"elasticbeanstalk",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			envs, err := d.ElasticBeanstalkEnvs.Get()
			if err != nil {
				return nil, err
			}
			settings, err := d.ElasticBeanstalkEnvSettings.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, e := range envs {
				id := envID(e)
				opts := settings[envName(e)]
				logging := optionEnabled(opts, "aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs")
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"elastic-beanstalk-managed-updates-enabled",
		"Checks if managed platform updates in an AWS Elastic Beanstalk environment is enabled. The rule is COMPLIANT if the value for ManagedActionsEnabled is set to true. The rule is NON_COMPLIANT if the value for ManagedActionsEnabled is set to false, or if a parameter is provided and its value does not match the existing configurations.",
		"elasticbeanstalk",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			envs, err := d.ElasticBeanstalkEnvs.Get()
			if err != nil {
				return nil, err
			}
			settings, err := d.ElasticBeanstalkEnvSettings.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, e := range envs {
				id := envID(e)
				opts := settings[envName(e)]
				enabled := optionEnabled(opts, "aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled")
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"beanstalk-enhanced-health-reporting-enabled",
		"Checks if an AWS Elastic Beanstalk environment is configured for enhanced health reporting. The rule is COMPLIANT if the environment is configured for enhanced health reporting. The rule is NON_COMPLIANT if the environment is configured for basic health reporting.",
		"elasticbeanstalk",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			envs, err := d.ElasticBeanstalkEnvs.Get()
			if err != nil {
				return nil, err
			}
			settings, err := d.ElasticBeanstalkEnvSettings.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, e := range envs {
				id := envID(e)
				opts := settings[envName(e)]
				value := optionValue(opts, "aws:elasticbeanstalk:healthreporting:system", "HealthReportingSystem")
				enabled := strings.EqualFold(value, "enhanced")
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))
}

func envID(e ebtypes.EnvironmentDescription) string {
	if e.EnvironmentArn != nil {
		return *e.EnvironmentArn
	}
	if e.EnvironmentName != nil {
		return *e.EnvironmentName
	}
	return "unknown"
}

func envName(e ebtypes.EnvironmentDescription) string {
	if e.EnvironmentName != nil {
		return *e.EnvironmentName
	}
	return ""
}

func optionEnabled(opts []ebtypes.ConfigurationOptionSetting, namespace, name string) bool {
	value := optionValue(opts, namespace, name)
	return strings.EqualFold(value, "true") || strings.EqualFold(value, "enabled")
}

func optionValue(opts []ebtypes.ConfigurationOptionSetting, namespace, name string) string {
	for _, o := range opts {
		if o.Namespace != nil && o.OptionName != nil && *o.Namespace == namespace && *o.OptionName == name {
			if o.Value != nil {
				return *o.Value
			}
		}
	}
	return ""
}
