package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
	amplifytypes "github.com/aws/aws-sdk-go-v2/service/amplify/types"
)

const amplifyDefaultDescription = "Managed by bptools auto-remediation"

var amplifyDefaultTags = map[string]string{
	"bptools:managed-by": "bptools",
}

type amplifyBranchRef struct {
	AppID      string
	AppARN     string
	BranchName string
	BranchARN  string
}

func listAllAmplifyApps(ctx fix.FixContext, clients *awsdata.Clients) ([]amplifytypes.App, error) {
	var out []amplifytypes.App
	var next *string
	for {
		resp, err := clients.Amplify.ListApps(ctx.Ctx, &amplify.ListAppsInput{NextToken: next})
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Apps...)
		if resp.NextToken == nil || strings.TrimSpace(*resp.NextToken) == "" {
			break
		}
		next = resp.NextToken
	}
	return out, nil
}

func listAmplifyBranches(ctx fix.FixContext, clients *awsdata.Clients, appID string) ([]amplifytypes.Branch, error) {
	var out []amplifytypes.Branch
	var next *string
	for {
		resp, err := clients.Amplify.ListBranches(ctx.Ctx, &amplify.ListBranchesInput{
			AppId:     aws.String(appID),
			NextToken: next,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Branches...)
		if resp.NextToken == nil || strings.TrimSpace(*resp.NextToken) == "" {
			break
		}
		next = resp.NextToken
	}
	return out, nil
}

func resolveAmplifyApp(ctx fix.FixContext, clients *awsdata.Clients, resourceID string) (string, string, error) {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return "", "", fmt.Errorf("missing app identifier")
	}

	// Fast path: resourceID is already the app ID.
	getOut, err := clients.Amplify.GetApp(ctx.Ctx, &amplify.GetAppInput{AppId: aws.String(id)})
	if err == nil && getOut.App != nil && getOut.App.AppId != nil {
		arn := ""
		if getOut.App.AppArn != nil {
			arn = *getOut.App.AppArn
		}
		return *getOut.App.AppId, arn, nil
	}

	apps, err := listAllAmplifyApps(ctx, clients)
	if err != nil {
		return "", "", err
	}

	var matches []amplifytypes.App
	for _, app := range apps {
		if app.AppId != nil && *app.AppId == id {
			matches = append(matches, app)
			continue
		}
		if app.AppArn != nil && *app.AppArn == id {
			matches = append(matches, app)
			continue
		}
		if app.Name != nil && *app.Name == id {
			matches = append(matches, app)
		}
	}

	if len(matches) == 0 {
		return "", "", fmt.Errorf("no Amplify app matched identifier %q", id)
	}
	if len(matches) > 1 {
		return "", "", fmt.Errorf("ambiguous Amplify app identifier %q matched %d apps", id, len(matches))
	}

	app := matches[0]
	if app.AppId == nil {
		return "", "", fmt.Errorf("matched app is missing app ID")
	}
	arn := ""
	if app.AppArn != nil {
		arn = *app.AppArn
	}
	return *app.AppId, arn, nil
}

func resolveAmplifyBranch(ctx fix.FixContext, clients *awsdata.Clients, resourceID string) (*amplifyBranchRef, error) {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return nil, fmt.Errorf("missing branch identifier")
	}

	apps, err := listAllAmplifyApps(ctx, clients)
	if err != nil {
		return nil, err
	}

	var matches []amplifyBranchRef
	for _, app := range apps {
		if app.AppId == nil {
			continue
		}
		appID := *app.AppId
		appARN := ""
		if app.AppArn != nil {
			appARN = *app.AppArn
		}
		branches, err := listAmplifyBranches(ctx, clients, appID)
		if err != nil {
			return nil, err
		}
		for _, b := range branches {
			branchName := ""
			if b.BranchName != nil {
				branchName = *b.BranchName
			}
			branchARN := ""
			if b.BranchArn != nil {
				branchARN = *b.BranchArn
			}
			if id == branchName || id == branchARN || id == appID+":"+branchName {
				matches = append(matches, amplifyBranchRef{
					AppID:      appID,
					AppARN:     appARN,
					BranchName: branchName,
					BranchARN:  branchARN,
				})
			}
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no Amplify branch matched identifier %q", id)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous Amplify branch identifier %q matched %d branches", id, len(matches))
	}
	if matches[0].BranchName == "" {
		return nil, fmt.Errorf("matched branch is missing branch name")
	}
	return &matches[0], nil
}

type amplifyAppDescriptionFix struct{ clients *awsdata.Clients }

func (f *amplifyAppDescriptionFix) CheckID() string     { return "amplify-app-description" }
func (f *amplifyAppDescriptionFix) Description() string { return "Set Amplify app description" }
func (f *amplifyAppDescriptionFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *amplifyAppDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *amplifyAppDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	appID, _, err := resolveAmplifyApp(fctx, f.clients, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve app: " + err.Error()
		return base
	}

	out, err := f.clients.Amplify.GetApp(fctx.Ctx, &amplify.GetAppInput{AppId: aws.String(appID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get app: " + err.Error()
		return base
	}
	if out.App != nil && out.App.Description != nil && strings.TrimSpace(*out.App.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "app description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set description on Amplify app %s", appID)}
		return base
	}

	_, err = f.clients.Amplify.UpdateApp(fctx.Ctx, &amplify.UpdateAppInput{
		AppId:       aws.String(appID),
		Description: aws.String(amplifyDefaultDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update app description: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set description on Amplify app %s", appID)}
	return base
}

type amplifyBranchAutoDeletionFix struct{ clients *awsdata.Clients }

func (f *amplifyBranchAutoDeletionFix) CheckID() string {
	return "amplify-app-branch-auto-deletion-enabled"
}
func (f *amplifyBranchAutoDeletionFix) Description() string {
	return "Enable Amplify app branch auto-deletion"
}
func (f *amplifyBranchAutoDeletionFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *amplifyBranchAutoDeletionFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *amplifyBranchAutoDeletionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	appID, _, err := resolveAmplifyApp(fctx, f.clients, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve app: " + err.Error()
		return base
	}

	out, err := f.clients.Amplify.GetApp(fctx.Ctx, &amplify.GetAppInput{AppId: aws.String(appID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get app: " + err.Error()
		return base
	}
	if out.App != nil && out.App.EnableBranchAutoDeletion != nil && *out.App.EnableBranchAutoDeletion {
		base.Status = fix.FixSkipped
		base.Message = "branch auto deletion already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable branch auto deletion for Amplify app %s", appID)}
		return base
	}

	_, err = f.clients.Amplify.UpdateApp(fctx.Ctx, &amplify.UpdateAppInput{
		AppId:                    aws.String(appID),
		EnableBranchAutoDeletion: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable branch auto deletion: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("enabled branch auto deletion for Amplify app %s", appID)}
	return base
}

type amplifyAppTagFix struct{ clients *awsdata.Clients }

func (f *amplifyAppTagFix) CheckID() string     { return "amplify-app-tagged" }
func (f *amplifyAppTagFix) Description() string { return "Tag Amplify app" }
func (f *amplifyAppTagFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *amplifyAppTagFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *amplifyAppTagFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	appID, appARN, err := resolveAmplifyApp(fctx, f.clients, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve app: " + err.Error()
		return base
	}
	if strings.TrimSpace(appARN) == "" {
		base.Status = fix.FixFailed
		base.Message = "resolved app is missing ARN"
		return base
	}

	tagsOut, err := f.clients.Amplify.ListTagsForResource(fctx.Ctx, &amplify.ListTagsForResourceInput{
		ResourceArn: aws.String(appARN),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list app tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "app already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would tag Amplify app %s", appID)}
		return base
	}

	_, err = f.clients.Amplify.TagResource(fctx.Ctx, &amplify.TagResourceInput{
		ResourceArn: aws.String(appARN),
		Tags:        amplifyDefaultTags,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag app: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("tagged Amplify app %s", appID)}
	return base
}

type amplifyAppNoEnvVarsFix struct{ clients *awsdata.Clients }

func (f *amplifyAppNoEnvVarsFix) CheckID() string {
	return "amplify-app-no-environment-variables"
}
func (f *amplifyAppNoEnvVarsFix) Description() string {
	return "Clear Amplify app environment variables"
}
func (f *amplifyAppNoEnvVarsFix) Impact() fix.ImpactType { return fix.ImpactDegradation }
func (f *amplifyAppNoEnvVarsFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *amplifyAppNoEnvVarsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	appID, _, err := resolveAmplifyApp(fctx, f.clients, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve app: " + err.Error()
		return base
	}

	out, err := f.clients.Amplify.GetApp(fctx.Ctx, &amplify.GetAppInput{AppId: aws.String(appID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get app: " + err.Error()
		return base
	}
	if out.App == nil || len(out.App.EnvironmentVariables) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "app already has no environment variables"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would clear %d environment variables from Amplify app %s", len(out.App.EnvironmentVariables), appID)}
		return base
	}

	_, err = f.clients.Amplify.UpdateApp(fctx.Ctx, &amplify.UpdateAppInput{
		AppId:                aws.String(appID),
		EnvironmentVariables: map[string]string{},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "clear app environment variables: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("cleared environment variables from Amplify app %s", appID)}
	return base
}

type amplifyBranchDescriptionFix struct{ clients *awsdata.Clients }

func (f *amplifyBranchDescriptionFix) CheckID() string { return "amplify-branch-description" }
func (f *amplifyBranchDescriptionFix) Description() string {
	return "Set Amplify branch description"
}
func (f *amplifyBranchDescriptionFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *amplifyBranchDescriptionFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *amplifyBranchDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	branchRef, err := resolveAmplifyBranch(fctx, f.clients, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve branch: " + err.Error()
		return base
	}

	out, err := f.clients.Amplify.GetBranch(fctx.Ctx, &amplify.GetBranchInput{
		AppId:      aws.String(branchRef.AppID),
		BranchName: aws.String(branchRef.BranchName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get branch: " + err.Error()
		return base
	}
	if out.Branch != nil && out.Branch.Description != nil && strings.TrimSpace(*out.Branch.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "branch description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set description on Amplify branch %s", branchRef.BranchName)}
		return base
	}

	_, err = f.clients.Amplify.UpdateBranch(fctx.Ctx, &amplify.UpdateBranchInput{
		AppId:       aws.String(branchRef.AppID),
		BranchName:  aws.String(branchRef.BranchName),
		Description: aws.String(amplifyDefaultDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update branch description: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set description on Amplify branch %s", branchRef.BranchName)}
	return base
}

type amplifyBranchPerformanceModeFix struct{ clients *awsdata.Clients }

func (f *amplifyBranchPerformanceModeFix) CheckID() string {
	return "amplify-branch-performance-mode-enabled"
}
func (f *amplifyBranchPerformanceModeFix) Description() string {
	return "Enable Amplify branch performance mode"
}
func (f *amplifyBranchPerformanceModeFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *amplifyBranchPerformanceModeFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *amplifyBranchPerformanceModeFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	branchRef, err := resolveAmplifyBranch(fctx, f.clients, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve branch: " + err.Error()
		return base
	}

	out, err := f.clients.Amplify.GetBranch(fctx.Ctx, &amplify.GetBranchInput{
		AppId:      aws.String(branchRef.AppID),
		BranchName: aws.String(branchRef.BranchName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get branch: " + err.Error()
		return base
	}
	if out.Branch != nil && out.Branch.EnablePerformanceMode != nil && *out.Branch.EnablePerformanceMode {
		base.Status = fix.FixSkipped
		base.Message = "branch performance mode already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable performance mode on Amplify branch %s", branchRef.BranchName)}
		return base
	}

	_, err = f.clients.Amplify.UpdateBranch(fctx.Ctx, &amplify.UpdateBranchInput{
		AppId:                 aws.String(branchRef.AppID),
		BranchName:            aws.String(branchRef.BranchName),
		EnablePerformanceMode: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable branch performance mode: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("enabled performance mode on Amplify branch %s", branchRef.BranchName)}
	return base
}

type amplifyBranchTagFix struct{ clients *awsdata.Clients }

func (f *amplifyBranchTagFix) CheckID() string     { return "amplify-branch-tagged" }
func (f *amplifyBranchTagFix) Description() string { return "Tag Amplify branch" }
func (f *amplifyBranchTagFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *amplifyBranchTagFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *amplifyBranchTagFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	branchRef, err := resolveAmplifyBranch(fctx, f.clients, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve branch: " + err.Error()
		return base
	}
	if strings.TrimSpace(branchRef.BranchARN) == "" {
		base.Status = fix.FixFailed
		base.Message = "resolved branch is missing ARN"
		return base
	}

	tagsOut, err := f.clients.Amplify.ListTagsForResource(fctx.Ctx, &amplify.ListTagsForResourceInput{
		ResourceArn: aws.String(branchRef.BranchARN),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list branch tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "branch already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would tag Amplify branch %s", branchRef.BranchName)}
		return base
	}

	_, err = f.clients.Amplify.TagResource(fctx.Ctx, &amplify.TagResourceInput{
		ResourceArn: aws.String(branchRef.BranchARN),
		Tags:        amplifyDefaultTags,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag branch: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("tagged Amplify branch %s", branchRef.BranchName)}
	return base
}
