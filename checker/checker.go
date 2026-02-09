package checker

import "sync"

// Status represents the outcome of a check.
type Status string

const (
	StatusPass  Status = "PASS"
	StatusFail  Status = "FAIL"
	StatusError Status = "ERROR"
	StatusSkip  Status = "SKIP"
)

// Result is one finding from a check.
type Result struct {
	CheckID    string `json:"check_id"`
	ResourceID string `json:"resource_id"`
	Status     Status `json:"status"`
	Message    string `json:"message"`
}

// Check is the interface every best-practice check implements.
type Check interface {
	ID() string
	Description() string
	Service() string
	Run() []Result
}

// Registry holds all registered checks.
var (
	mu       sync.Mutex
	registry []Check
)

// Register adds a check to the global registry.
func Register(c Check) {
	mu.Lock()
	registry = append(registry, c)
	mu.Unlock()
}

// All returns every registered check.
func All() []Check {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Check, len(registry))
	copy(out, registry)
	return out
}
