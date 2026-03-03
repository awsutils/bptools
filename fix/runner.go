package fix

import (
	"context"

	"bptools/checker"
)

// RunOpts controls which fixes are executed.
type RunOpts struct {
	DryRun         bool
	ImpactFilter   map[ImpactType]bool   // nil = all impacts
	SeverityFilter map[SeverityLevel]bool // nil = all severities
}

// RunHooks provides optional callbacks for fix execution progress.
type RunHooks struct {
	OnStart    func(total int)
	OnComplete func(checkID, resourceID string, r FixResult)
	OnDone     func(total, applied, failed int)
}

// RunFixes runs fixes sequentially for all FAIL results that have a registered
// FixAction. Sequential execution prevents races on shared resource creation
// (e.g., two fixes simultaneously creating the same S3 bucket).
func RunFixes(ctx context.Context, results []checker.Result, opts RunOpts, hooks RunHooks) []FixResult {
	type job struct {
		checkID    string
		resourceID string
		action     FixAction
	}

	// Deduplicate by (checkID, resourceID) keeping first occurrence.
	seen := make(map[string]bool)
	var jobs []job
	for _, r := range results {
		if r.Status != checker.StatusFail {
			continue
		}
		action := Lookup(r.CheckID)
		if action == nil {
			continue
		}
		if opts.ImpactFilter != nil && !opts.ImpactFilter[action.Impact()] {
			continue
		}
		if opts.SeverityFilter != nil && !opts.SeverityFilter[action.Severity()] {
			continue
		}
		key := r.CheckID + "\x00" + r.ResourceID
		if seen[key] {
			continue
		}
		seen[key] = true
		jobs = append(jobs, job{checkID: r.CheckID, resourceID: r.ResourceID, action: action})
	}

	if hooks.OnStart != nil {
		hooks.OnStart(len(jobs))
	}

	fctx := FixContext{Ctx: ctx, DryRun: opts.DryRun}
	var fixResults []FixResult
	applied, failed := 0, 0
	for _, j := range jobs {
		r := j.action.Apply(fctx, j.resourceID)
		fixResults = append(fixResults, r)
		if hooks.OnComplete != nil {
			hooks.OnComplete(j.checkID, j.resourceID, r)
		}
		switch r.Status {
		case FixApplied, FixDryRun:
			applied++
		case FixFailed:
			failed++
		}
	}

	if hooks.OnDone != nil {
		hooks.OnDone(len(jobs), applied, failed)
	}
	return fixResults
}
