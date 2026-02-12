package awsdata

import (
	"reflect"
	"strings"
	"sync"
)

type memoJob struct {
	name  string
	field reflect.Value
}

// PrefetchHooks provides optional callbacks for prefetch lifecycle events.
type PrefetchHooks struct {
	OnStart    func(total int)
	OnComplete func(name string, err error)
	OnDone     func(total int, failures int)
}

// PrefetchAll loads all cache.Memo fields concurrently.
// It ignores nil fields and continues on errors.
func (d *Data) PrefetchAll(concurrency int) {
	d.PrefetchFiltered(nil, concurrency)
}

// PrefetchAllWithHooks loads all cache.Memo fields concurrently with callbacks.
func (d *Data) PrefetchAllWithHooks(concurrency int, hooks PrefetchHooks) {
	d.PrefetchFilteredWithHooks(nil, concurrency, hooks)
}

// PrefetchFiltered loads cache.Memo fields concurrently, optionally filtered by service names.
// Filtering is based on substring match against Memo.Name().
func (d *Data) PrefetchFiltered(services map[string]bool, concurrency int) {
	d.PrefetchFilteredWithHooks(services, concurrency, PrefetchHooks{})
}

// PrefetchFilteredWithHooks loads cache.Memo fields concurrently, optionally filtered by service names.
// Filtering is based on substring match against Memo.Name().
func (d *Data) PrefetchFilteredWithHooks(services map[string]bool, concurrency int, hooks PrefetchHooks) {
	if d == nil {
		return
	}
	if concurrency < 1 {
		concurrency = 20
	}

	selected := d.selectMemoJobs(func(name string) bool {
		if len(services) == 0 {
			return true
		}
		return serviceMatch(name, services)
	})

	if hooks.OnStart != nil {
		hooks.OnStart(len(selected))
	}

	jobs := make(chan memoJob)
	var wg sync.WaitGroup
	var failures int
	var failuresMu sync.Mutex

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			field := j.field
			if !field.IsValid() || field.IsNil() {
				continue
			}

			m := field.MethodByName("Get")
			if !m.IsValid() {
				continue
			}

			var callErr error
			out := m.Call(nil)
			if len(out) > 0 {
				last := out[len(out)-1]
				if last.IsValid() && !last.IsNil() {
					if err, ok := last.Interface().(error); ok {
						callErr = err
					}
				}
			}

			if callErr != nil {
				failuresMu.Lock()
				failures++
				failuresMu.Unlock()
			}

			if hooks.OnComplete != nil {
				hooks.OnComplete(j.name, callErr)
			}
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	for _, j := range selected {
		jobs <- j
	}

	close(jobs)
	wg.Wait()

	if hooks.OnDone != nil {
		hooks.OnDone(len(selected), failures)
	}
}

// ClearFilteredCaches clears memoized cache fields, optionally filtered by service names.
// Filtering is based on substring match against Memo.Name().
func (d *Data) ClearFilteredCaches(services map[string]bool) {
	if len(services) == 0 {
		d.ClearMemoNames(nil)
		return
	}
	d.ClearMemoNames(d.memoNamesByService(services))
}

// PrefetchMemoNamesWithHooks loads only memo names in the provided set.
func (d *Data) PrefetchMemoNamesWithHooks(memoNames map[string]bool, concurrency int, hooks PrefetchHooks) {
	if len(memoNames) == 0 {
		return
	}
	if d == nil {
		return
	}
	if concurrency < 1 {
		concurrency = 20
	}

	selected := d.selectMemoJobs(func(name string) bool {
		return memoNames[name]
	})

	if hooks.OnStart != nil {
		hooks.OnStart(len(selected))
	}

	jobs := make(chan memoJob)
	var wg sync.WaitGroup
	var failures int
	var failuresMu sync.Mutex

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			field := j.field
			if !field.IsValid() || field.IsNil() {
				continue
			}
			get := field.MethodByName("Get")
			if !get.IsValid() {
				continue
			}
			var callErr error
			out := get.Call(nil)
			if len(out) > 0 {
				last := out[len(out)-1]
				if last.IsValid() && !last.IsNil() {
					if err, ok := last.Interface().(error); ok {
						callErr = err
					}
				}
			}
			if callErr != nil {
				failuresMu.Lock()
				failures++
				failuresMu.Unlock()
			}
			if hooks.OnComplete != nil {
				hooks.OnComplete(j.name, callErr)
			}
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	for _, j := range selected {
		jobs <- j
	}
	close(jobs)
	wg.Wait()

	if hooks.OnDone != nil {
		hooks.OnDone(len(selected), failures)
	}
}

// ClearMemoNames clears memoized cache fields by exact memo name.
// If memoNames is nil or empty, all memo fields are cleared.
func (d *Data) ClearMemoNames(memoNames map[string]bool) {
	if d == nil {
		return
	}
	selected := d.selectMemoJobs(func(name string) bool {
		if len(memoNames) == 0 {
			return true
		}
		return memoNames[name]
	})
	for _, j := range selected {
		reset := j.field.MethodByName("Reset")
		if reset.IsValid() {
			reset.Call(nil)
		}
	}
}

func (d *Data) memoNamesByService(services map[string]bool) map[string]bool {
	out := make(map[string]bool)
	selected := d.selectMemoJobs(func(name string) bool {
		return serviceMatch(name, services)
	})
	for _, job := range selected {
		out[job.name] = true
	}
	return out
}

func (d *Data) selectMemoJobs(nameFilter func(name string) bool) []memoJob {
	v := reflect.ValueOf(d).Elem()
	var selected []memoJob
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() != reflect.Pointer || field.IsNil() {
			continue
		}
		get := field.MethodByName("Get")
		if !get.IsValid() {
			continue
		}
		name := memoFieldName(field)
		if nameFilter != nil && !nameFilter(name) {
			continue
		}
		selected = append(selected, memoJob{name: name, field: field})
	}
	return selected
}

func memoFieldName(field reflect.Value) string {
	name := "unknown"
	if nameMethod := field.MethodByName("Name"); nameMethod.IsValid() {
		out := nameMethod.Call(nil)
		if len(out) == 1 {
			if s, ok := out[0].Interface().(string); ok && s != "" {
				name = s
			}
		}
	}
	return name
}

func serviceMatch(name string, services map[string]bool) bool {
	upper := strings.ToUpper(name)
	for svc := range services {
		if strings.Contains(upper, strings.ToUpper(svc)) {
			return true
		}
	}
	return false
}
