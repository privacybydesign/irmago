package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestRetryableRedisError(t *testing.T) {
	// Error replies reach us as their bare text; go-redis's own error type is internal.
	readonly := errors.New("READONLY You can't write against a read only replica.")
	noreplicas := errors.New("NOREPLICAS Not enough good replicas to write.")
	execabort := errors.New("EXECABORT Transaction discarded because of previous errors.")

	retryable := []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		net.ErrClosed,
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
		readonly,
		noreplicas,
		execabort,
		// As wrapped by go-redis for a transaction connection it gave up on.
		fmt.Errorf("redis: Conn is in a bad state: %w", readonly),
		fmt.Errorf("redis: Conn is in a bad state: %w", &net.OpError{Op: "write", Net: "tcp", Err: net.ErrClosed}),
	}
	for _, err := range retryable {
		require.True(t, retryableRedisError(err), "%v should be retryable", err)
	}

	notRetryable := []error{
		nil,
		context.Canceled,
		context.DeadlineExceeded,
		fmt.Errorf("redis: Conn is in a bad state: %w", context.Canceled),
		redis.Nil,
		redis.TxFailedErr,
		errors.New("NOPERM this user has no permissions to run the 'set' command"),
		errors.New("WRONGTYPE Operation against a key holding the wrong kind of value"),
		errors.New("session ttl is in the past"),
	}
	for _, err := range notRetryable {
		require.False(t, retryableRedisError(err), "%v should not be retryable", err)
	}
}

func TestRetryOnBrokenConnRetriesFailoverErrors(t *testing.T) {
	client := &RedisClient{}
	failures := []error{
		errors.New("READONLY You can't write against a read only replica."),
		errors.New("EXECABORT Transaction discarded because of previous errors."),
		errors.New("NOREPLICAS Not enough good replicas to write."),
	}

	calls := 0
	err := client.RetryOnBrokenConn(context.Background(), func() error {
		calls++
		if calls <= len(failures) {
			return failures[calls-1]
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, len(failures)+1, calls, "every failover error should have been retried once")
}

func TestRetryOnBrokenConnGivesUpOnPermanentError(t *testing.T) {
	client := &RedisClient{}
	permanent := errors.New("NOPERM this user has no permissions to run the 'set' command")

	calls := 0
	err := client.RetryOnBrokenConn(context.Background(), func() error {
		calls++
		return permanent
	})
	require.ErrorIs(t, err, permanent)
	require.Equal(t, 1, calls)
}

func TestRetryOnBrokenConnHonoursNegativeBudget(t *testing.T) {
	client := &RedisClient{RetryBudget: -1}

	calls := 0
	err := client.RetryOnBrokenConn(context.Background(), func() error {
		calls++
		return io.EOF
	})
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 1, calls, "a negative budget should not retry at all")
}

func TestRedisLoggerRoutesThroughLogrus(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.Out = &buf
	logger.Formatter = &logrus.JSONFormatter{}

	redisLogger{logger}.Printf(context.Background(), "sentinel: new master=%q addr=%q", "yivi-master", "redis-1:6379")

	out := buf.String()
	require.Contains(t, out, `"level":"warning"`)
	require.Contains(t, out, `"component":"go-redis"`)
	require.Contains(t, out, `sentinel: new master=\"yivi-master\" addr=\"redis-1:6379\"`)
}
