package parallel

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestExec_returnsResultsInOrder(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	results, err := Exec(input, func(n int) (string, error) {
		return strconv.Itoa(n * 2), nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"2", "4", "6", "8", "10"}
	for i, v := range expected {
		if results[i] != v {
			t.Errorf("index %d: got %q, want %q", i, results[i], v)
		}
	}
}

func TestExec_emptySlice(t *testing.T) {
	results, err := Exec([]int{}, func(n int) (int, error) {
		return n, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results, got %v", results)
	}
}

func TestExec_propagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	_, err := Exec([]int{1, 2, 3}, func(n int) (int, error) {
		if n == 2 {
			return 0, sentinel
		}
		return n, nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestExec_allErrors_returnsOne(t *testing.T) {
	_, err := Exec([]int{1, 2, 3}, func(n int) (int, error) {
		return 0, errors.New("fail")
	})
	if err == nil {
		t.Error("expected an error, got nil")
	}
}

func TestExec_noError_nilErr(t *testing.T) {
	_, err := Exec([]string{"a", "b"}, func(s string) (string, error) {
		return s + s, nil
	})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestExecRange_returnsResultsInOrder(t *testing.T) {
	results, err := ExecRange(5, func(i uint) (uint, error) {
		return i * 2, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []uint{0, 2, 4, 6, 8}
	for i, v := range expected {
		if results[i] != v {
			t.Errorf("index %d: got %d, want %d", i, results[i], v)
		}
	}
}

func TestExecRange_zero(t *testing.T) {
	results, err := ExecRange(0, func(i uint) (uint, error) {
		return i, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results, got %v", results)
	}
}

func TestExecRange_propagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	_, err := ExecRange(3, func(i uint) (uint, error) {
		if i == 1 {
			return 0, sentinel
		}
		return i, nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestExecRange_waitsForSlowElement(t *testing.T) {
	results, err := ExecRange(3, func(i uint) (uint, error) {
		if i == 1 {
			time.Sleep(10 * time.Millisecond)
		}
		return i * 10, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []uint{0, 10, 20}
	for i, v := range expected {
		if results[i] != v {
			t.Errorf("index %d: got %d, want %d", i, results[i], v)
		}
	}
}

func TestExec_waitsForSlowElement(t *testing.T) {
	// Element 2 sleeps 10ms; its result must still appear in the output.
	results, err := Exec([]int{1, 2, 3}, func(n int) (int, error) {
		if n == 2 {
			time.Sleep(10 * time.Millisecond)
		}
		return n * 10, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{10, 20, 30}
	for i, v := range expected {
		if results[i] != v {
			t.Errorf("index %d: got %d, want %d", i, results[i], v)
		}
	}
}
