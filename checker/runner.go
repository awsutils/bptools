package checker

import (
	"os"
	"strings"
	"sync"
)

// RunHooks provides optional callbacks for check execution progress.
type RunHooks struct {
	OnStart    func(total int)
	OnComplete func(id string, count int, errCount int)
	OnDone     func(total int, findings int, errors int)
}

// RunAll executes checks concurrently with bounded parallelism.
func RunAll(checks []Check, concurrency int) []Result {
	return RunAllWithHooks(checks, concurrency, RunHooks{})
}

// RunAllWithHooks executes checks concurrently with bounded parallelism and callbacks.
func RunAllWithHooks(checks []Check, concurrency int, hooks RunHooks) []Result {
	if concurrency < 1 {
		concurrency = 20
	}
	if hooks.OnStart != nil {
		hooks.OnStart(len(checks))
	}

	var (
		mu       sync.Mutex
		results  []Result
		wg       sync.WaitGroup
		sem      = make(chan struct{}, concurrency)
		totalErr int
	)
	for _, c := range checks {
		wg.Add(1)
		sem <- struct{}{}
		go func(c Check) {
			defer wg.Done()
			defer func() { <-sem }()
			r := filterIgnoredResults(c.Run())
			errCount := 0
			for _, rr := range r {
				if rr.Status == StatusError {
					errCount++
				}
			}
			mu.Lock()
			results = append(results, r...)
			totalErr += errCount
			mu.Unlock()

			if hooks.OnComplete != nil {
				hooks.OnComplete(c.ID(), len(r), errCount)
			}
		}(c)
	}
	wg.Wait()

	if hooks.OnDone != nil {
		hooks.OnDone(len(checks), len(results), totalErr)
	}
	return results
}

func filterIgnoredResults(in []Result) []Result {
	if len(in) == 0 {
		return in
	}
	out := make([]Result, 0, len(in))
	for _, r := range in {
		if shouldIgnoreDeletedResult(r) {
			continue
		}
		if shouldIgnoreDefaultTaggingResult(r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func shouldIgnoreDeletedResult(r Result) bool {
	if !boolEnvDefaultTrue("BPTOOLS_IGNORE_DELETED_RESOURCES") {
		return false
	}
	return isDeletedLikeResourceID(r.ResourceID)
}

func shouldIgnoreDefaultTaggingResult(r Result) bool {
	if !boolEnvDefaultTrue("BPTOOLS_IGNORE_DEFAULT_RESOURCES_IN_TAG_CHECKS") {
		return false
	}
	if !isTaggingCheckID(r.CheckID) {
		return false
	}
	return isAWSDefaultLikeResourceID(r.ResourceID)
}

func isTaggingCheckID(checkID string) bool {
	id := strings.ToLower(strings.TrimSpace(checkID))
	return strings.Contains(id, "tag")
}

func isDeletedLikeResourceID(id string) bool {
	v := strings.ToLower(strings.TrimSpace(id))
	if v == "" {
		return false
	}
	return strings.Contains(v, "deleted") ||
		strings.Contains(v, "deleting") ||
		strings.Contains(v, "terminated") ||
		strings.Contains(v, "terminating")
}

func isAWSDefaultLikeResourceID(id string) bool {
	v := strings.ToLower(strings.TrimSpace(id))
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "aws-") {
		return true
	}
	if strings.Contains(v, ":default:") || strings.HasSuffix(v, ":default") {
		return true
	}
	if strings.Contains(v, "/default/") || strings.HasSuffix(v, "/default") {
		return true
	}
	if strings.Contains(v, "alias/aws/") {
		return true
	}
	return false
}

func boolEnvDefaultTrue(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch v {
	case "", "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		return true
	}
}

// Filter returns checks matching the given IDs or services.
func Filter(checks []Check, ids map[string]bool, services map[string]bool) []Check {
	if len(ids) == 0 && len(services) == 0 {
		return checks
	}
	var out []Check
	for _, c := range checks {
		if len(ids) > 0 && ids[c.ID()] {
			out = append(out, c)
		} else if len(services) > 0 && services[c.Service()] {
			out = append(out, c)
		}
	}
	return out
}
