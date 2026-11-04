package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	// DefaultRedisRetryBudget is the RedisSettings.RetryBudget used when none is configured.
	DefaultRedisRetryBudget = 3 * time.Second

	// minRedisRetryTime and maxRedisRetryTime bound the backoff between attempts.
	minRedisRetryTime = 50 * time.Millisecond
	maxRedisRetryTime = 500 * time.Millisecond
)

// RedisTx is the transaction passed to the function given to RedisClient.WatchWithRetry.
// Next to being a redis.Tx, it carries what the next attempt should run.
type RedisTx struct {
	*redis.Tx
	retry func(tx *RedisTx) error
}

// NoRetry marks the transaction as no longer retryable. Call it just before doing anything
// whose effect is visible outside of Redis, such as invoking a handler that writes an HTTP
// response or consumes the request body, since a next attempt would repeat that effect.
// RetryWith makes the transaction retryable again.
func (tx *RedisTx) NoRetry() {
	tx.retry = nil
}

// RetryWith makes a transaction that NoRetry closed off retryable again, by a function that
// replaces the one given to WatchWithRetry on every further attempt. Use it once the part
// that must not be repeated is done and its outcome is captured in a value the replacement
// can write by itself: the replacement runs in a fresh transaction watching the same keys,
// and is responsible for checking that redoing the write is still correct.
func (tx *RedisTx) RetryWith(fn func(tx *RedisTx) error) {
	tx.retry = fn
}

// WatchWithRetry runs fn in a Redis transaction watching the given keys, like redis.Client.Watch
// does, and retries the whole transaction on a fresh connection when it fails on a connection
// that went away. A further attempt runs fn again, unless fn called NoRetry or RetryWith.
//
// go-redis runs a transaction on a single connection that it cannot swap out halfway. When Redis
// Sentinel promotes a new master, go-redis closes every connection to the old one, including the
// ones that are in use at that moment, and marks the transaction's connection pool as bad. It does
// not retry that by itself: the resulting error ("Conn is in a bad state") is not in the set of
// errors go-redis considers retryable, so without this wrapper a Redis failover fails every
// session request that happens to be in flight.
//
// A transaction is idle between its read and its commit, for however long the caller takes to
// decide what to write, and a connection that broke during that window only surfaces at the
// commit. Retrying that is what RetryWith is for.
func (c *RedisClient) WatchWithRetry(ctx context.Context, keys []string, fn func(tx *RedisTx) error) error {
	next := fn
	return c.retry(ctx, func() error {
		attemptFn := next
		tx := &RedisTx{retry: attemptFn}
		err := c.Watch(ctx, func(redisTx *redis.Tx) error {
			tx.Tx = redisTx
			return attemptFn(tx)
		}, keys...)
		if err != nil && tx.retry == nil {
			return noRetryError{err}
		}
		next = tx.retry
		return err
	})
}

// RetryOnBrokenConn runs fn, and retries it while it fails on a connection that went away.
// Use it for a command that is safe to run twice, such as a write that does not depend on
// what Redis currently holds; for a read-modify-write, use WatchWithRetry.
//
// It is needed even though go-redis retries commands by itself, because that retrying has
// gaps: a pipeline, which is what every MULTI/EXEC block is, gives up on the first attempt
// when the failure was in connecting rather than in the command.
func (c *RedisClient) RetryOnBrokenConn(ctx context.Context, fn func() error) error {
	return c.retry(ctx, fn)
}

// retry runs fn until it succeeds, until it fails with something other than a broken
// connection, or until the retry budget is spent.
func (c *RedisClient) retry(ctx context.Context, fn func() error) error {
	budget := c.RetryBudget
	if budget == 0 {
		budget = DefaultRedisRetryBudget
	}
	deadline := time.Now().Add(budget)

	for attempt := 0; ; attempt++ {
		err := fn()
		if noRetry, ok := errors.AsType[noRetryError](err); ok {
			return noRetry.err
		}
		if err == nil || !retryableRedisError(err) {
			return err
		}
		backoff := redisRetryBackoff(attempt)
		if time.Now().Add(backoff).After(deadline) {
			return err
		}
		if sleepErr := sleepContext(ctx, backoff); sleepErr != nil {
			return err
		}
	}
}

// noRetryError wraps an error that must be returned as it is, without further attempts,
// however retryable it looks.
type noRetryError struct {
	err error
}

func (e noRetryError) Error() string { return e.err.Error() }
func (e noRetryError) Unwrap() error { return e.err }

// retryableRedisError reports whether err means that another attempt stands a chance of
// succeeding: the connection the command ran on went away or could not be established, or
// Redis refused the write because a failover is in progress. Other errors Redis returned are
// not retryable here, redis.TxFailedErr in particular: it means the watched key changed, so
// whatever the caller decided to write is based on a stale read.
func retryableRedisError(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return false
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, net.ErrClosed):
		return true
	case redisErrorHasPrefix(err, "READONLY "), redisErrorHasPrefix(err, "NOREPLICAS "):
		// The node this connection points at was demoted while we were connected to it, or
		// it was just promoted and its replicas have not caught up yet (min-replicas-to-write).
		// Both pass within a failover; the connection is dropped by go-redis or by Sentinel's
		// client kill, and the next dial asks Sentinel for the current master.
		return true
	case redisErrorHasPrefix(err, "EXECABORT "):
		// The transaction was discarded because Redis rejected one of its queued commands,
		// so nothing was executed. Inside MULTI, READONLY and NOREPLICAS surface exactly like
		// this, and go-redis does not pass on the reason, so the cause cannot be told apart
		// from a permanent one such as a denied command. Retrying a permanent one merely
		// delays the same error by the retry budget, on a deployment that is broken anyway.
		return true
	}
	// go-redis wraps the underlying network error, both when a connection broke during the
	// command and when no connection to the master could be established at all.
	_, ok := errors.AsType[net.Error](err)
	return ok
}

// redisErrorHasPrefix reports whether err, or an error it wraps, is a Redis error reply that
// starts with prefix. Error replies reach us as their bare text, and possibly wrapped in the
// error go-redis returns for a transaction connection it gave up on.
func redisErrorHasPrefix(err error, prefix string) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if strings.HasPrefix(err.Error(), prefix) {
			return true
		}
	}
	return false
}

func redisRetryBackoff(attempt int) time.Duration {
	if attempt > 16 {
		return maxRedisRetryTime
	}
	return min(minRedisRetryTime<<attempt, maxRedisRetryTime)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
