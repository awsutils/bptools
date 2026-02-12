package cache

import (
	"sync"

	"bptools/runstate"
)

// Memo is a lazy, thread-safe, exactly-once wrapper around an API call.
type Memo[T any] struct {
	mu     sync.Mutex
	loaded bool
	val    T
	err    error
	fetch  func() (T, error)
	name   string
}

// New creates a Memo that will call fetch at most once.
func New[T any](name string, fetch func() (T, error)) *Memo[T] {
	return &Memo[T]{name: name, fetch: fetch}
}

// Name returns the memo identifier.
func (m *Memo[T]) Name() string {
	return m.name
}

// Get returns the cached value, calling fetch on the first invocation.
func (m *Memo[T]) Get() (T, error) {
	runstate.RecordMemoAccess(m.name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		m.val, m.err = m.fetch()
		m.loaded = true
	}
	return m.val, m.err
}

// Reset clears the cached value so the next Get performs a fresh fetch.
func (m *Memo[T]) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var zero T
	m.val = zero
	m.err = nil
	m.loaded = false
}
