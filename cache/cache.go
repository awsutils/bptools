package cache

import "sync"

// Memo is a lazy, thread-safe, exactly-once wrapper around an API call.
type Memo[T any] struct {
	once  sync.Once
	val   T
	err   error
	fetch func() (T, error)
}

// New creates a Memo that will call fetch at most once.
func New[T any](fetch func() (T, error)) *Memo[T] {
	return &Memo[T]{fetch: fetch}
}

// Get returns the cached value, calling fetch on the first invocation.
func (m *Memo[T]) Get() (T, error) {
	m.once.Do(func() { m.val, m.err = m.fetch() })
	return m.val, m.err
}
