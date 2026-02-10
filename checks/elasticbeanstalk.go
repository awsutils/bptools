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
		"This rule checks elastic beanstalk application description.",
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
		"This rule checks elastic beanstalk application version description.",
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
		"This rule checks elastic beanstalk environment description.",
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
		"This rule checks elastic beanstalk logs to CloudWatch.",
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
		"This rule checks enabled state for elastic beanstalk managed updates.",
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
		"This rule checks enabled state for elastic beanstalk enhanced health reporting.",
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
