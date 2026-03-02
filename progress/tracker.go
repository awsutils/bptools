package progress

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"bptools/awsdata"
	"bptools/checker"
)

// Action represents a user-triggered action.
type Action string

const (
	ActionRecheckFailedErrored Action = "recheck_failed_errored"
)

// Tracker coordinates progress output between prefetch and rule runs.
type Tracker struct {
	out   io.Writer
	mu    sync.Mutex
	actCh chan Action
}

// New creates a Tracker that writes progress to out (typically os.Stderr).
func New(out io.Writer) *Tracker {
	if out == nil {
		out = os.Stderr
	}
	actCh := make(chan Action)
	close(actCh) // no interactive UI; recheck loop exits immediately
	return &Tracker{
		out:   out,
		actCh: actCh,
	}
}

func (t *Tracker) logf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.out, format+"\n", args...)
}

// Wait is a no-op without a TUI program to wait for.
func (t *Tracker) Wait() {}

// Actions returns a closed channel; no interactive actions are possible.
func (t *Tracker) Actions() <-chan Action {
	return t.actCh
}

// Close is a no-op without a TUI program to stop.
func (t *Tracker) Close() {}

// ShowResults prints results to stdout in plain text.
// Checks where every result is an error (e.g. EoL / unreachable service) are
// omitted entirely — only checks with at least one FAIL finding are shown.
func (t *Tracker) ShowResults(results []checker.Result, descriptions map[string]string) {
	grouped := make(map[string][]checker.Result)
	for _, r := range results {
		if r.Status != checker.StatusFail && r.Status != checker.StatusError {
			continue
		}
		grouped[r.CheckID] = append(grouped[r.CheckID], r)
	}

	// Build sorted list of check IDs that have at least one FAIL.
	type checkSummary struct {
		id        string
		items     []checker.Result
		failCount int
		errCount  int
	}
	var checks []checkSummary
	for id, items := range grouped {
		failCount := 0
		errCount := 0
		for _, item := range items {
			if item.Status == checker.StatusError {
				errCount++
			} else {
				failCount++
			}
		}
		if failCount == 0 {
			continue // all errors → EoL / unreachable service, skip
		}
		checks = append(checks, checkSummary{id: id, items: items, failCount: failCount, errCount: errCount})
	}

	if len(checks) == 0 {
		fmt.Fprintln(os.Stdout, "No non-compliant resources found.")
		return
	}

	sort.Slice(checks, func(i, j int) bool { return checks[i].id < checks[j].id })

	totalFindings := 0
	for _, c := range checks {
		totalFindings += c.failCount
	}
	fmt.Fprintf(os.Stdout, "rules_with_issues=%d findings=%d\n", len(checks), totalFindings)

	for _, c := range checks {
		sort.Slice(c.items, func(i, j int) bool {
			if c.items[i].ResourceID != c.items[j].ResourceID {
				return c.items[i].ResourceID < c.items[j].ResourceID
			}
			return c.items[i].Message < c.items[j].Message
		})

		fmt.Fprintf(os.Stdout, "\n%s (fail=%d)\n", c.id, c.failCount)
		if desc := strings.TrimSpace(descriptions[c.id]); desc != "" {
			fmt.Fprintf(os.Stdout, "  description: %s\n", desc)
		}
		fmt.Fprintf(os.Stdout, "  docs: https://docs.aws.amazon.com/config/latest/developerguide/%s.html\n", c.id)

		for _, item := range c.items {
			if item.Status == checker.StatusError {
				continue
			}
			resource := strings.TrimSpace(item.ResourceID)
			if resource == "" {
				resource = "<account>"
			}
			msg := strings.TrimSpace(item.Message)
			if msg == "" {
				msg = "-"
			}
			msg = strings.Join(strings.Fields(msg), " ")
			fmt.Fprintf(os.Stdout, "  [FAIL] %s — %s\n", resource, msg)
		}
	}
}

// PrefetchHooks returns hooks that log prefetch progress to stderr.
func (t *Tracker) PrefetchHooks() awsdata.PrefetchHooks {
	return awsdata.PrefetchHooks{
		OnStart: func(total int) {
			t.logf("prefetch: starting (%d caches)", total)
		},
		OnComplete: func(name string, err error) {},
		OnDone: func(total int, failures int) {
			if failures > 0 {
				t.logf("prefetch: done with %d/%d failures", failures, total)
			} else {
				t.logf("prefetch: done (%d/%d)", total, total)
			}
		},
	}
}

// RunHooks returns hooks that log rule-check progress to stderr.
func (t *Tracker) RunHooks() checker.RunHooks {
	return checker.RunHooks{
		OnStart: func(total int) {
			t.logf("checks: starting (%d)", total)
		},
		OnComplete: func(id string, count int, errCount int) {
			if errCount > 0 {
				t.logf("checks: %s (findings=%d errors=%d)", id, count, errCount)
			}
		},
		OnDone: func(total int, findings int, errors int) {
			t.logf("checks: done (checks=%d findings=%d errors=%d)", total, findings, errors)
		},
	}
}
