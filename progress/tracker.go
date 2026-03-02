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
func (t *Tracker) ShowResults(results []checker.Result, descriptions map[string]string) {
	grouped := make(map[string][]checker.Result)
	for _, r := range results {
		if r.Status != checker.StatusFail && r.Status != checker.StatusError {
			continue
		}
		grouped[r.CheckID] = append(grouped[r.CheckID], r)
	}

	if len(grouped) == 0 {
		fmt.Fprintln(os.Stdout, "No non-compliant resources found.")
		return
	}

	checkIDs := make([]string, 0, len(grouped))
	for id := range grouped {
		checkIDs = append(checkIDs, id)
	}
	sort.Strings(checkIDs)

	totalItems := 0
	totalErrors := 0
	for _, items := range grouped {
		for _, item := range items {
			totalItems++
			if item.Status == checker.StatusError {
				totalErrors++
			}
		}
	}

	summary := fmt.Sprintf("rules_with_issues=%d findings=%d", len(checkIDs), totalItems)
	if totalErrors > 0 {
		summary += fmt.Sprintf(" errors=%d", totalErrors)
	}
	fmt.Fprintln(os.Stdout, summary)

	for _, checkID := range checkIDs {
		items := grouped[checkID]
		sort.Slice(items, func(i, j int) bool {
			if items[i].Status != items[j].Status {
				return items[i].Status < items[j].Status
			}
			if items[i].ResourceID != items[j].ResourceID {
				return items[i].ResourceID < items[j].ResourceID
			}
			return items[i].Message < items[j].Message
		})

		failCount := 0
		errCount := 0
		for _, item := range items {
			if item.Status == checker.StatusError {
				errCount++
			} else {
				failCount++
			}
		}

		fmt.Fprintf(os.Stdout, "\n%s (fail=%d error=%d)\n", checkID, failCount, errCount)
		if desc := strings.TrimSpace(descriptions[checkID]); desc != "" {
			fmt.Fprintf(os.Stdout, "  description: %s\n", desc)
		}
		fmt.Fprintf(os.Stdout, "  docs: https://docs.aws.amazon.com/config/latest/developerguide/%s.html\n", checkID)

		for _, item := range items {
			resource := strings.TrimSpace(item.ResourceID)
			if resource == "" {
				resource = "<account>"
			}
			msg := strings.TrimSpace(item.Message)
			if msg == "" {
				msg = "-"
			}
			msg = strings.Join(strings.Fields(msg), " ")
			status := "FAIL"
			if item.Status == checker.StatusError {
				status = "ERR"
			}
			fmt.Fprintf(os.Stdout, "  [%s] %s — %s\n", status, resource, msg)
		}
	}
}

// PrefetchHooks returns hooks that log prefetch progress to stderr.
func (t *Tracker) PrefetchHooks() awsdata.PrefetchHooks {
	return awsdata.PrefetchHooks{
		OnStart: func(total int) {
			t.logf("prefetch: starting (%d caches)", total)
		},
		OnComplete: func(name string, err error) {
			if err != nil {
				t.logf("prefetch: error: %s: %v", name, err)
			}
		},
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
