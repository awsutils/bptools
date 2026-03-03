package fix

import "sync"

var (
	rmu      sync.Mutex
	registry = make(map[string]FixAction)
)

// Register adds a FixAction to the global registry. Panics on duplicate CheckID.
func Register(a FixAction) {
	rmu.Lock()
	defer rmu.Unlock()
	id := a.CheckID()
	if _, ok := registry[id]; ok {
		panic("fix: duplicate registration for check ID: " + id)
	}
	registry[id] = a
}

// Lookup returns the registered FixAction for checkID, or nil if not registered.
func Lookup(checkID string) FixAction {
	rmu.Lock()
	defer rmu.Unlock()
	return registry[checkID]
}

// All returns every registered FixAction.
func All() []FixAction {
	rmu.Lock()
	defer rmu.Unlock()
	out := make([]FixAction, 0, len(registry))
	for _, a := range registry {
		out = append(out, a)
	}
	return out
}
