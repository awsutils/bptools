package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

func appID(appArn, appId, appName *string) string {
	if appId != nil {
		return *appId
	}
	if appName != nil {
		return *appName
	}
	if appArn != nil {
		return *appArn
	}
	return "unknown"
}

func branchID(branchArn, branchName *string) string {
	if branchName != nil {
		return *branchName
	}
	if branchArn != nil {
		return *branchArn
	}
	return "unknown"
}

// RegisterAmplifyChecks registers Amplify-related checks.
func RegisterAmplifyChecks(d *awsdata.Data) {
	// amplify-app-description
	checker.Register(DescriptionCheck(
		"amplify-app-description",
		"Checks if AWS Amplify apps have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
		"amplify",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			apps, err := d.AmplifyApps.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, app := range apps {
				res = append(res, DescriptionResource{ID: appID(app.AppArn, app.AppId, app.Name), Description: app.Description})
			}
			return res, nil
		},
	))

	// amplify-app-no-environment-variables
	checker.Register(ConfigCheck(
		"amplify-app-no-environment-variables",
		"Checks that AWS Amplify apps do not contain environment variables. The rule is NON_COMPLIANT if configuration.EnvironmentVariables is not an empty list.",
		"amplify",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			apps, err := d.AmplifyApps.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, app := range apps {
				count := 0
				if app.EnvironmentVariables != nil {
					count = len(app.EnvironmentVariables)
				}
				res = append(res, ConfigResource{ID: appID(app.AppArn, app.AppId, app.Name), Passing: count == 0, Detail: "Environment variables must be empty"})
			}
			return res, nil
		},
	))

	// amplify-app-branch-auto-deletion-enabled
	checker.Register(EnabledCheck(
		"amplify-app-branch-auto-deletion-enabled",
		"Checks if AWS Amplify apps automatically disconnect a branch in Amplify Hosting when you delete a branch from your Git repository. The rule is NON_COMPLIANT if configuration.EnableBranchAutoDeletion is false.",
		"amplify",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			apps, err := d.AmplifyApps.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, app := range apps {
				enabled := app.EnableBranchAutoDeletion != nil && *app.EnableBranchAutoDeletion
				res = append(res, EnabledResource{ID: appID(app.AppArn, app.AppId, app.Name), Enabled: enabled})
			}
			return res, nil
		},
	))

	// amplify-app-tagged
	checker.Register(TaggedCheck(
		"amplify-app-tagged",
		"Checks if AWS Amplify apps have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"amplify",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			apps, err := d.AmplifyApps.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AmplifyAppTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, app := range apps {
				if app.AppArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: appID(app.AppArn, app.AppId, app.Name), Tags: tags[*app.AppArn]})
			}
			return res, nil
		},
	))

	// amplify-branch-description
	checker.Register(DescriptionCheck(
		"amplify-branch-description",
		"Checks if AWS Amplify branches have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
		"amplify",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			branchesByApp, err := d.AmplifyBranches.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, branches := range branchesByApp {
				for _, b := range branches {
					res = append(res, DescriptionResource{ID: branchID(b.BranchArn, b.BranchName), Description: b.Description})
				}
			}
			return res, nil
		},
	))

	// amplify-branch-performance-mode-enabled
	checker.Register(EnabledCheck(
		"amplify-branch-performance-mode-enabled",
		"Checks if AWS Amplify branches have performance mode enabled. The rule is NON_COMPLIANT if configuration.EnablePerformanceMode is false.",
		"amplify",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			branchesByApp, err := d.AmplifyBranches.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, branches := range branchesByApp {
				for _, b := range branches {
					enabled := b.EnablePerformanceMode != nil && *b.EnablePerformanceMode
					res = append(res, EnabledResource{ID: branchID(b.BranchArn, b.BranchName), Enabled: enabled})
				}
			}
			return res, nil
		},
	))

	// amplify-branch-tagged
	checker.Register(TaggedCheck(
		"amplify-branch-tagged",
		"Checks if AWS Amplify branches have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"amplify",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			branchesByApp, err := d.AmplifyBranches.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AmplifyBranchTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, branches := range branchesByApp {
				for _, b := range branches {
					if b.BranchArn == nil {
						continue
					}
					res = append(res, TaggedResource{ID: branchID(b.BranchArn, b.BranchName), Tags: tags[*b.BranchArn]})
				}
			}
			return res, nil
		},
	))
}
