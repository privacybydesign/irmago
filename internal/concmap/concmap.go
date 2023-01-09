package concmap

import "sync"

// ConcMap is a generic map safe for concurrent use. It uses a sync.RWMutex, so
// the map may be accessed by an arbitrary number of readers or a single writer.
type ConcMap[K comparable, V any] struct {
	m map[K]V
	*sync.RWMutex
}

func New[K comparable, V any]() ConcMap[K, V] {
	return ConcMap[K, V]{
		m:       map[K]V{},
		RWMutex: &sync.RWMutex{},
	}
}

func (cm ConcMap[K, V]) IsSet(key K) bool {
	cm.RLock()
	defer cm.RUnlock()
	_, set := cm.m[key]
	return set
}

func (cm ConcMap[K, V]) Delete(key K) {
	cm.Lock()
	defer cm.Unlock()
	delete(cm.m, key)
}

// DeleteIf iterates over all map entries, and deletes them if the specified function returns true.
func (cm ConcMap[K, V]) DeleteIf(cond func(K, V) bool) {
	cm.Lock()
	defer cm.Unlock()
	for key, val := range cm.m {
		if cond(key, val) {
			delete(cm.m, key)
		}
	}
}

func (cm ConcMap[K, V]) Get(key K) V {
	cm.RLock()
	defer cm.RUnlock()
	return cm.m[key]
}

func (cm ConcMap[K, V]) Set(key K, val V) {
	cm.Lock()
	defer cm.Unlock()
	cm.m[key] = val
}

// Iterate through all elements in the map. Note that the map is locked during iteration, so
// invoking other methods will deadlock. To delete elements based on a condition, use
// DeleteIf.
func (cm ConcMap[K, V]) Iterate(f func(K, V)) {
	cm.RLock()
	defer cm.RUnlock()
	for key, val := range cm.m {
		f(key, val)
	}
}
