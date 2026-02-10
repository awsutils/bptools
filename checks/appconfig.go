package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

func RegisterAppConfigChecks(d *awsdata.Data) {
	// appconfig-application-description
	checker.Register(DescriptionCheck(
		"appconfig-application-description",
		"This rule checks descriptions for AppConfig application exist.",
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
		"This rule checks tagging for AppConfig application exist.",
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
				res = append(res, TaggedResource{ID: id, Tags: nil})
			}
			return res, nil
		},
	))

	// appconfig-environment-description
	checker.Register(DescriptionCheck(
		"appconfig-environment-description",
		"This rule checks descriptions for AppConfig environment exist.",
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
		"This rule checks tagging for AppConfig environment exist.",
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
					if env.Id != nil {
						id = appID + ":" + *env.Id
					}
					res = append(res, TaggedResource{ID: id, Tags: nil})
				}
			}
			return res, nil
		},
	))

	// appconfig-configuration-profile-tagged
	checker.Register(TaggedCheck(
		"appconfig-configuration-profile-tagged",
		"This rule checks tagging for AppConfig configuration profile exist.",
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
					if p.Id != nil {
						id = appID + ":" + *p.Id
					}
					res = append(res, TaggedResource{ID: id, Tags: nil})
				}
			}
			return res, nil
		},
	))

	// appconfig-configuration-profile-validators-not-empty
	checker.Register(ConfigCheck(
		"appconfig-configuration-profile-validators-not-empty",
		"This rule checks AppConfig configuration profile validators not empty.",
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
		"This rule checks descriptions for AppConfig deployment strategy exist.",
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
				res = append(res, DescriptionResource{ID: id, Description: s.Description})
			}
			return res, nil
		},
	))

	// appconfig-deployment-strategy-minimum-final-bake-time
	checker.Register(ConfigCheck(
		"appconfig-deployment-strategy-minimum-final-bake-time",
		"This rule checks AppConfig deployment strategy minimum final bake time.",
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
				ok := s.FinalBakeTimeInMinutes > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("FinalBakeTimeInMinutes: %v", s.FinalBakeTimeInMinutes)})
			}
			return res, nil
		},
	))

	// appconfig-deployment-strategy-replicate-to-ssm
	checker.Register(ConfigCheck(
		"appconfig-deployment-strategy-replicate-to-ssm",
		"This rule checks AppConfig deployment strategy replicate to SSM.",
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
				ok := s.ReplicateTo == "SSM_DOCUMENT"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("ReplicateTo: %s", s.ReplicateTo)})
			}
			return res, nil
		},
	))

	// appconfig-deployment-strategy-tagged
	checker.Register(TaggedCheck(
		"appconfig-deployment-strategy-tagged",
		"This rule checks tagging for AppConfig deployment strategy exist.",
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
				res = append(res, TaggedResource{ID: id, Tags: nil})
			}
			return res, nil
		},
	))

	// appconfig-extension-association-tagged
	checker.Register(TaggedCheck(
		"appconfig-extension-association-tagged",
		"This rule checks tagging for AppConfig extension association exist.",
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
				res = append(res, TaggedResource{ID: id, Tags: nil})
			}
			return res, nil
		},
	))

	// appconfig-freeform-profile-config-storage
	checker.Register(ConfigCheck(
		"appconfig-freeform-profile-config-storage",
		"This rule checks AppConfig freeform profile config storage.",
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
					ok := (p.Type == nil || *p.Type != "Freeform") || (p.LocationUri != nil && *p.LocationUri != "")
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Type: %s, LocationUri: %v", p.Type, p.LocationUri)})
				}
			}
			return res, nil
		},
	))

	// appconfig-hosted-configuration-version-description
	checker.Register(DescriptionCheck(
		"appconfig-hosted-configuration-version-description",
		"This rule checks descriptions for AppConfig hosted configuration version exist.",
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
