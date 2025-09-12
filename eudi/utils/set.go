package utils

import "iter"

type Set[T comparable] struct {
	m map[T]bool
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{
		m: make(map[T]bool),
	}
}

func (s *Set[T]) Add(val T) {
	s.m[val] = true
}

func (s *Set[T]) Delete(val T) {
	delete(s.m, val)
}

func (s *Set[T]) Contains(val T) bool {
	exists := s.m[val]
	return exists
}

func (s *Set[T]) Len() int {
	return len(s.m)
}

func (s *Set[T]) Values() iter.Seq[T] {
	return func(yield func(T) bool) {
		for item := range s.m {
			if !yield(item) {
				break
			}
		}
	}
}
