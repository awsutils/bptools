package cache

import (
	"log/slog"
	"sync"
	"time"
)

// Memo is a lazy, thread-safe, exactly-once wrapper around an API call.
type Memo[T any] struct {
	once    sync.Once
	val     T
	err     error
	fetch   func() (T, error)
	name    string
	fetched bool
}

// New creates a Memo that will call fetch at most once.
func New[T any](name string, fetch func() (T, error)) *Memo[T] {
	return &Memo[T]{name: name, fetch: fetch}
}

// Get returns the cached value, calling fetch on the first invocation.
func (m *Memo[T]) Get() (T, error) {
	hit := m.fetched
	m.once.Do(func() {
		start := time.Now()
		m.val, m.err = m.fetch()
		m.fetched = true
		dur := time.Since(start)
		if m.err != nil {
			slog.Warn("cache fetch error", "name", m.name, "duration", dur, "error", m.err)
		} else {
			slog.Info("cache fetch", "name", m.name, "duration", dur)
		}
	})
	if hit {
		slog.Debug("cache hit", "name", m.name)
	}
	return m.val, m.err
}
