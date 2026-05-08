package parallel

import "sync"

// Exec runs f on each element of items concurrently and returns the results in
// the same order. If f returns an error for any element, the first such error
// is returned alongside whatever results were collected.
func Exec[T, R any](items []T, f func(T) (R, error)) ([]R, error) {
	results := make([]R, len(items))
	errs := make([]error, len(items))

	var wg sync.WaitGroup
	wg.Add(len(items))
	for i, item := range items {
		go func(i int, item T) {
			defer wg.Done()
			results[i], errs[i] = f(item)
		}(i, item)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

// ExecRange calls f(i) for each i in [0, n) concurrently and returns the
// results in order. If f returns an error for any index, the first such error
// is returned alongside whatever results were collected.
func ExecRange[R any](n uint, f func(uint) (R, error)) ([]R, error) {
	results := make([]R, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(int(n))
	for i := range n {
		go func(i uint) {
			defer wg.Done()
			results[i], errs[i] = f(i)
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return results, err
		}
	}
	return results, nil
}
