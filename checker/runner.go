package checker

import (
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
			r := c.Run()
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
