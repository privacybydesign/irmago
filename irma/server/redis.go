package server

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	// redisTxAttempts is how often WatchWithRetry attempts a transaction before giving up.
	redisTxAttempts = 3
	// minRedisTxRetryTime and maxRedisTxRetryTime bound the backoff between those attempts.
	minRedisTxRetryTime = 50 * time.Millisecond
	maxRedisTxRetryTime = 500 * time.Millisecond
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
// does, and retries the whole transaction on a fresh connection when it fails on a broken
// connection. A further attempt runs fn again, unless fn called NoRetry or RetryWith.
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
	var err error
	next := fn
	for attempt := range redisTxAttempts {
		if attempt > 0 {
			if err := sleepContext(ctx, redisTxRetryBackoff(attempt-1)); err != nil {
				return err
			}
		}
		attemptFn := next
		tx := &RedisTx{retry: attemptFn}
		err = c.Watch(ctx, func(redisTx *redis.Tx) error {
			tx.Tx = redisTx
			return attemptFn(tx)
		}, keys...)
		if err == nil || tx.retry == nil || !retryableRedisError(err) {
			return err
		}
		next = tx.retry
	}
	return err
}

// retryableRedisError reports whether err means the connection the transaction ran on went
// away, such that another attempt on a new connection stands a chance of succeeding. Errors
// Redis itself returned are not retryable here, redis.TxFailedErr in particular: it means the
// watched key changed, so whatever the caller decided to write is based on a stale read.
func retryableRedisError(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return false
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, net.ErrClosed):
		return true
	}
	// go-redis wraps the underlying network error, both when a connection broke during the
	// transaction and when no connection to the master could be established at all.
	_, ok := errors.AsType[net.Error](err)
	return ok
}

func redisTxRetryBackoff(attempt int) time.Duration {
	return min(minRedisTxRetryTime<<attempt, maxRedisTxRetryTime)
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
