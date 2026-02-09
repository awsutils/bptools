package checker

import "sync"

// RunAll executes checks concurrently with bounded parallelism.
func RunAll(checks []Check, concurrency int) []Result {
	if concurrency < 1 {
		concurrency = 20
	}
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
			r := c.Run()
			mu.Lock()
			results = append(results, r...)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
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
