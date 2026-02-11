package awsdata

import (
	"reflect"
	"strings"
	"sync"
)

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

	v := reflect.ValueOf(d).Elem()
	type job struct {
		name  string
		field reflect.Value
	}
	var selected []job

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() != reflect.Pointer || field.IsNil() {
			continue
		}
		get := field.MethodByName("Get")
		if !get.IsValid() {
			continue
		}

		name := "unknown"
		if nameMethod := field.MethodByName("Name"); nameMethod.IsValid() {
			out := nameMethod.Call(nil)
			if len(out) == 1 {
				if s, ok := out[0].Interface().(string); ok && s != "" {
					name = s
				}
			}
		}

		if len(services) > 0 && !serviceMatch(name, services) {
			continue
		}

		selected = append(selected, job{name: name, field: field})
	}

	if hooks.OnStart != nil {
		hooks.OnStart(len(selected))
	}

	jobs := make(chan job)
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

func serviceMatch(name string, services map[string]bool) bool {
	upper := strings.ToUpper(name)
	for svc := range services {
		if strings.Contains(upper, strings.ToUpper(svc)) {
			return true
		}
	}
	return false
}
