package fixes

import (
	"bptools/fix"
)

// aliasFix delegates execution to another registered concrete fix.
// Used for semantically equivalent rule IDs.
type aliasFix struct {
	checkID string
	target  string
}

func (f *aliasFix) CheckID() string     { return f.checkID }
func (f *aliasFix) Description() string { return "Alias fix for " + f.target }
func (f *aliasFix) Impact() fix.ImpactType {
	if a := fix.Lookup(f.target); a != nil {
		return a.Impact()
	}
	return fix.ImpactNone
}
func (f *aliasFix) Severity() fix.SeverityLevel {
	if a := fix.Lookup(f.target); a != nil {
		return a.Severity()
	}
	return fix.SeverityLow
}
func (f *aliasFix) Apply(ctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.checkID,
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}
	target := fix.Lookup(f.target)
	if target == nil {
		base.Status = fix.FixFailed
		base.Message = "alias target fix not registered: " + f.target
		return base
	}
	out := target.Apply(ctx, resourceID)
	out.CheckID = f.checkID
	if out.Impact == "" {
		out.Impact = base.Impact
	}
	if out.Severity == "" {
		out.Severity = base.Severity
	}
	return out
}

// unsupportedFix is an explicit, check-specific safe fixer for rules that are
// not safely automatable in-place.
type unsupportedFix struct {
	checkID string
	reason  string
}

func (f *unsupportedFix) CheckID() string     { return f.checkID }
func (f *unsupportedFix) Description() string { return "Manual remediation required" }
func (f *unsupportedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *unsupportedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}
func (f *unsupportedFix) Apply(_ fix.FixContext, resourceID string) fix.FixResult {
	return fix.FixResult{
		CheckID:    f.checkID,
		ResourceID: resourceID,
		Status:     fix.FixSkipped,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
		Message:    f.reason,
	}
}
