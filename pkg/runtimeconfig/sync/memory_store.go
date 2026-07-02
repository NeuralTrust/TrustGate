package configsync

import "sync/atomic"

type MemoryStore[T any] struct {
	ptr atomic.Pointer[Versioned[T]]
}

func NewMemoryStore[T any]() *MemoryStore[T] {
	return &MemoryStore[T]{}
}

func (s *MemoryStore[T]) Load() (*Versioned[T], bool) {
	v := s.ptr.Load()
	return v, v != nil
}

func (s *MemoryStore[T]) Swap(v *Versioned[T]) {
	s.ptr.Store(v)
}

func (s *MemoryStore[T]) Version() string {
	v := s.ptr.Load()
	if v == nil {
		return ""
	}
	return v.Version
}
