package fix

import "context"

// ImpactType classifies the operational impact of applying a fix.
type ImpactType string

// SeverityLevel classifies the security severity of the underlying finding.
type SeverityLevel string

// FixStatus is the outcome of a single fix attempt.
type FixStatus string

const (
	ImpactNone        ImpactType = "NO_IMPACT"
	ImpactDegradation ImpactType = "DEGRADATION"
	ImpactDown        ImpactType = "DOWN"

	SeverityLow    SeverityLevel = "LOW"
	SeverityMedium SeverityLevel = "MEDIUM"
	SeverityHigh   SeverityLevel = "HIGH"

	FixApplied FixStatus = "APPLIED"
	FixSkipped FixStatus = "SKIPPED"
	FixFailed  FixStatus = "FAILED"
	FixDryRun  FixStatus = "DRY_RUN"
)

// FixResult records the outcome of one fix attempt on a single resource.
type FixResult struct {
	CheckID    string
	ResourceID string
	Status     FixStatus
	Impact     ImpactType
	Severity   SeverityLevel
	Message    string
	Steps      []string // ordered actions taken (or planned in dry-run)
}

// FixContext carries per-run options into each Apply call.
type FixContext struct {
	Ctx    context.Context
	DryRun bool
}

// FixAction is the interface every fix implementation must satisfy.
type FixAction interface {
	CheckID() string
	Description() string
	Impact() ImpactType
	Severity() SeverityLevel
	Apply(fctx FixContext, resourceID string) FixResult
}
