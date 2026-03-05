package fixes

import (
	"strings"

	"bptools/checker"
	"bptools/fix"
)

type manualFallbackFix struct {
	checkID string
}

func (f *manualFallbackFix) CheckID() string     { return f.checkID }
func (f *manualFallbackFix) Description() string { return "Manual remediation required" }
func (f *manualFallbackFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *manualFallbackFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *manualFallbackFix) Apply(_ fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		id = "<account>"
	}
	return fix.FixResult{
		CheckID:    f.checkID,
		ResourceID: id,
		Status:     fix.FixSkipped,
		Impact:     fix.ImpactNone,
		Severity:   fix.SeverityLow,
		Message:    "auto-fix fallback: no safe built-in remediation yet; apply manual remediation",
	}
}

func registerFallbackFixesForUncoveredRules() {
	for _, c := range checker.All() {
		id := strings.TrimSpace(c.ID())
		if id == "" {
			continue
		}
		if fix.Lookup(id) != nil {
			continue
		}
		fix.Register(&manualFallbackFix{checkID: id})
	}
}
