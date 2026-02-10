package checker

import (
	"log/slog"
	"sync"
	"time"
)

// RunAll executes checks concurrently with bounded parallelism.
func RunAll(checks []Check, concurrency int) []Result {
	if concurrency < 1 {
		concurrency = 20
	}
	slog.Info("RunAll start", "checks", len(checks), "concurrency", concurrency)
	start := time.Now()
	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, concurrency)
	)
	for _, c := range checks {
		wg.Add(1)
		sem <- struct{}{}
		go func(c Check) {
			defer wg.Done()
			defer func() { <-sem }()
			slog.Debug("check start", "id", c.ID(), "service", c.Service())
			cstart := time.Now()
			r := c.Run()
			slog.Info("check done", "id", c.ID(), "service", c.Service(), "results", len(r), "duration", time.Since(cstart))
			mu.Lock()
			results = append(results, r...)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	slog.Info("RunAll done", "results", len(results), "duration", time.Since(start))
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
