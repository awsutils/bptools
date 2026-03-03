package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

type guardDutyFix struct{ clients *awsdata.Clients }

func (f *guardDutyFix) CheckID() string          { return "guardduty-enabled-centralized" }
func (f *guardDutyFix) Description() string      { return "Enable GuardDuty detector" }
func (f *guardDutyFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *guardDutyFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *guardDutyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.CheckID(),
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}

	// Idempotency: re-fetch detector status.
	det, err := f.clients.GuardDuty.GetDetector(fctx.Ctx, &guardduty.GetDetectorInput{
		DetectorId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get detector: " + err.Error()
		return base
	}
	if det.Status == guarddutytypes.DetectorStatusEnabled {
		base.Status = fix.FixSkipped
		base.Message = "detector already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable GuardDuty detector %s", resourceID)}
		return base
	}

	_, err = f.clients.GuardDuty.UpdateDetector(fctx.Ctx, &guardduty.UpdateDetectorInput{
		DetectorId: aws.String(resourceID),
		Enable:     aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update detector: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled GuardDuty detector %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── guardduty feature fixes ───────────────────────────────────────────────────

// guardDutyFeatureFix enables a single GuardDuty protection feature on a detector.
// checkID → featureName mapping mirrors the check registrations in checks/guardduty.go.
type guardDutyFeatureFix struct {
	checkID     string
	featureName string
	clients     *awsdata.Clients
}

func (f *guardDutyFeatureFix) CheckID() string          { return f.checkID }
func (f *guardDutyFeatureFix) Description() string      { return "Enable GuardDuty feature " + f.featureName }
func (f *guardDutyFeatureFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *guardDutyFeatureFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *guardDutyFeatureFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	det, err := f.clients.GuardDuty.GetDetector(fctx.Ctx, &guardduty.GetDetectorInput{
		DetectorId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get detector: " + err.Error()
		return base
	}
	if det.Status != guarddutytypes.DetectorStatusEnabled {
		base.Status = fix.FixSkipped
		base.Message = "detector is not enabled; enable it first"
		return base
	}
	for _, ft := range det.Features {
		if strings.EqualFold(string(ft.Name), f.featureName) && ft.Status == guarddutytypes.FeatureStatusEnabled {
			base.Status = fix.FixSkipped
			base.Message = fmt.Sprintf("feature %s already enabled", f.featureName)
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable GuardDuty feature %s on detector %s", f.featureName, resourceID)}
		return base
	}

	_, err = f.clients.GuardDuty.UpdateDetector(fctx.Ctx, &guardduty.UpdateDetectorInput{
		DetectorId: aws.String(resourceID),
		Features: []guarddutytypes.DetectorFeatureConfiguration{
			{
				Name:   guarddutytypes.DetectorFeature(f.featureName),
				Status: guarddutytypes.FeatureStatusEnabled,
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = fmt.Sprintf("update detector feature %s: %s", f.featureName, err.Error())
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled GuardDuty feature %s on detector %s", f.featureName, resourceID)}
	base.Status = fix.FixApplied
	return base
}
