package usage

import (
	"testing"
	"time"
)

// SetMinInterval lowers the minimum interval for the duration of a test.
func SetMinInterval(t testing.TB, d time.Duration) {
	old := minInterval
	minInterval = d
	t.Cleanup(func() { minInterval = old })
}

// SetHeartbeat lowers the heartbeat for the duration of a test.
func SetHeartbeat(t testing.TB, d time.Duration) {
	old := defaultHeartbeat
	defaultHeartbeat = d
	t.Cleanup(func() { defaultHeartbeat = old })
}
