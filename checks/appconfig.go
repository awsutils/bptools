package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/appconfig"
)

func appconfigListTags(d *awsdata.Data, arn string) map[string]string {
	out, err := d.Clients.AppConfig.ListTagsForResource(d.Ctx, &appconfig.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil || out == nil {
		return nil
	}
	return out.Tags
}

func appconfigResourceARN(d *awsdata.Data, resourcePath string) string {
	region := d.Clients.AppConfig.Options().Region
	acct, _ := d.AccountID.Get()
	return fmt.Sprintf("arn:aws:appconfig:%s:%s:%s", region, acct, resourcePath)
}

func RegisterAppConfigChecks(d *awsdata.Data) {
	// appconfig-application-description
	checker.Register(DescriptionCheck(
		"appconfig-application-description",
		"Checks if AWS AppConfig applications have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			apps, err := d.AppConfigApplications.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, app := range apps {
				id := "unknown"
				if app.Id != nil {
					id = *app.Id
				}
				res = append(res, DescriptionResource{ID: id, Description: app.Description})
			}
			return res, nil
		},
	))

	// appconfig-application-tagged
	checker.Register(TaggedCheck(
		"appconfig-application-tagged",
		"Checks if AWS AppConfig applications have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			apps, err := d.AppConfigApplications.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, app := range apps {
				id := "unknown"
				if app.Id != nil {
					id = *app.Id
				}
				arn := appconfigResourceARN(d, "application/"+id)
				res = append(res, TaggedResource{ID: id, Tags: appconfigListTags(d, arn)})
			}
			return res, nil
		},
	))

	// appconfig-environment-description
	checker.Register(DescriptionCheck(
		"appconfig-environment-description",
		"Checks if AWS AppConfig environments have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			envsByApp, err := d.AppConfigEnvironments.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for appID, envs := range envsByApp {
				for _, env := range envs {
					id := appID
					if env.Id != nil {
						id = appID + ":" + *env.Id
					}
					res = append(res, DescriptionResource{ID: id, Description: env.Description})
				}
			}
			return res, nil
		},
	))

	// appconfig-environment-tagged
	checker.Register(TaggedCheck(
		"appconfig-environment-tagged",
		"Checks if AWS AppConfig environments have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			envsByApp, err := d.AppConfigEnvironments.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for appID, envs := range envsByApp {
				for _, env := range envs {
					id := appID
					envID := appID
					if env.Id != nil {
						envID = *env.Id
						id = appID + ":" + envID
					}
					arn := appconfigResourceARN(d, "application/"+appID+"/environment/"+envID)
					res = append(res, TaggedResource{ID: id, Tags: appconfigListTags(d, arn)})
				}
			}
			return res, nil
		},
	))

	// appconfig-configuration-profile-tagged
	checker.Register(TaggedCheck(
		"appconfig-configuration-profile-tagged",
		"Checks if AWS AppConfig configuration profiles have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			profiles, err := d.AppConfigProfiles.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for appID, profs := range profiles {
				for _, p := range profs {
					id := appID
					profID := appID
					if p.Id != nil {
						profID = *p.Id
						id = appID + ":" + profID
					}
					arn := appconfigResourceARN(d, "application/"+appID+"/configurationprofile/"+profID)
					res = append(res, TaggedResource{ID: id, Tags: appconfigListTags(d, arn)})
				}
			}
			return res, nil
		},
	))

	// appconfig-configuration-profile-validators-not-empty
	checker.Register(ConfigCheck(
		"appconfig-configuration-profile-validators-not-empty",
		"Checks if an AWS AppConfig configuration profile includes at least one validator for syntactic or semantic check to ensure the configuration deploy functions as intended. The rule is NON_COMPLIANT if the Validators property is an empty array.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			profiles, err := d.AppConfigProfiles.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for appID, profs := range profiles {
				for _, p := range profs {
					id := appID
					if p.Id != nil {
						id = appID + ":" + *p.Id
					}
					ok := len(p.ValidatorTypes) > 0
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Validators: %d", len(p.ValidatorTypes))})
				}
			}
			return res, nil
		},
	))

	// appconfig-deployment-strategy-description
	checker.Register(DescriptionCheck(
		"appconfig-deployment-strategy-description",
		"Checks if AWS AppConfig deployment strategies have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			strategies, err := d.AppConfigDeploymentStrategies.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, s := range strategies {
				id := "unknown"
				if s.Id != nil {
					id = *s.Id
				}
				if appconfigIsAWSManagedDeploymentStrategyID(id) {
					continue
				}
				res = append(res, DescriptionResource{ID: id, Description: s.Description})
			}
			return res, nil
		},
	))

	// appconfig-deployment-strategy-minimum-final-bake-time
	checker.Register(ConfigCheck(
		"appconfig-deployment-strategy-minimum-final-bake-time",
		"Checks if an AWS AppConfig deployment strategy requires the specified minimum bake time. The rule is NON_COMPLIANT if the deployment strategy has a final bake time less than value specified in the rule parameter. The default value is 30 minutes.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			strategies, err := d.AppConfigDeploymentStrategies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range strategies {
				id := "unknown"
				if s.Id != nil {
					id = *s.Id
				}
				if appconfigIsAWSManagedDeploymentStrategyID(id) {
					continue
				}
				ok := s.FinalBakeTimeInMinutes >= 30
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("FinalBakeTimeInMinutes: %v", s.FinalBakeTimeInMinutes)})
			}
			return res, nil
		},
	))

	// appconfig-deployment-strategy-replicate-to-ssm
	checker.Register(ConfigCheck(
		"appconfig-deployment-strategy-replicate-to-ssm",
		"Checks if AWS AppConfig deployment strategies save the deployment strategy to an AWS Systems Manager (SSM) document. The rule is NON_COMPLIANT if configuration.ReplicateTo is not 'SSM_DOCUMENT'.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			strategies, err := d.AppConfigDeploymentStrategies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range strategies {
				id := "unknown"
				if s.Id != nil {
					id = *s.Id
				}
				if appconfigIsAWSManagedDeploymentStrategyID(id) {
					continue
				}
				ok := s.ReplicateTo == "SSM_DOCUMENT"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("ReplicateTo: %s", s.ReplicateTo)})
			}
			return res, nil
		},
	))

	// appconfig-deployment-strategy-tagged
	checker.Register(TaggedCheck(
		"appconfig-deployment-strategy-tagged",
		"Checks if AWS AppConfig deployment strategies have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			strategies, err := d.AppConfigDeploymentStrategies.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, s := range strategies {
				id := "unknown"
				if s.Id != nil {
					id = *s.Id
				}
				if appconfigIsAWSManagedDeploymentStrategyID(id) {
					continue
				}
				arn := appconfigResourceARN(d, "deploymentstrategy/"+id)
				res = append(res, TaggedResource{ID: id, Tags: appconfigListTags(d, arn)})
			}
			return res, nil
		},
	))

	// appconfig-extension-association-tagged
	checker.Register(TaggedCheck(
		"appconfig-extension-association-tagged",
		"Checks if AWS AppConfig extension associations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			assocs, err := d.AppConfigExtensionAssociations.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range assocs {
				id := "unknown"
				if a.Id != nil {
					id = *a.Id
				}
				arn := appconfigResourceARN(d, "extensionassociation/"+id)
				res = append(res, TaggedResource{ID: id, Tags: appconfigListTags(d, arn)})
			}
			return res, nil
		},
	))

	// appconfig-freeform-profile-config-storage
	checker.Register(ConfigCheck(
		"appconfig-freeform-profile-config-storage",
		"Checks if freeform configuration profiles for AWS AppConfig store their configuration data in AWS Secrets Manager or AWS AppConfig hosted configuration store. The rule is NON_COMPLIANT if configuration.LocationUri is not secretsmanager or hosted.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			profiles, err := d.AppConfigProfiles.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for appID, profs := range profiles {
				for _, p := range profs {
					id := appID
					if p.Id != nil {
						id = appID + ":" + *p.Id
					}
					profileType := ""
					if p.Type != nil {
						profileType = *p.Type
					}
					location := ""
					if p.LocationUri != nil {
						location = strings.TrimSpace(*p.LocationUri)
					}
					isFreeform := strings.Contains(strings.ToLower(strings.TrimSpace(profileType)), "freeform")
					locLower := strings.ToLower(location)
					ok := !isFreeform ||
						strings.HasPrefix(locLower, "secretsmanager") ||
						strings.HasPrefix(locLower, "hosted")
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Type: %s, LocationUri: %v", profileType, p.LocationUri)})
				}
			}
			return res, nil
		},
	))

	// appconfig-hosted-configuration-version-description
	checker.Register(DescriptionCheck(
		"appconfig-hosted-configuration-version-description",
		"Checks if AWS AppConfig hosted configuration versions have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
		"appconfig",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			versions, err := d.AppConfigHostedConfigVersions.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for key, items := range versions {
				for _, v := range items {
					id := key
					if v.VersionNumber != 0 {
						id = fmt.Sprintf("%s:%d", key, v.VersionNumber)
					}
					res = append(res, DescriptionResource{ID: id, Description: v.Description})
				}
			}
			return res, nil
		},
	))
}

func appconfigIsAWSManagedDeploymentStrategyID(id string) bool {
	value := strings.ToLower(strings.TrimSpace(id))
	return strings.HasPrefix(value, "appconfig.")
}
