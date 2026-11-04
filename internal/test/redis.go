package test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/go-redis/redis/v8"
)

// flakyConn closes itself right before the first write made after broken is set, which is
// what an in-flight Redis connection looks like when go-redis drops every connection to the
// old master after Redis Sentinel promoted a new one.
type flakyConn struct {
	net.Conn
	broken *atomic.Bool
}

func (c *flakyConn) Write(b []byte) (int, error) {
	if c.broken.CompareAndSwap(true, false) {
		_ = c.Conn.Close()
	}
	return c.Conn.Write(b)
}

// FlakyRedisClient returns a Redis client for addr, and a flag that breaks the connection a
// command is about to be written to. The flag is consumed by the break, so setting it takes
// out one command; the connection the client dials to replace the broken one is healthy.
func FlakyRedisClient(t *testing.T, addr string) (*redis.Client, *atomic.Bool) {
	broken := &atomic.Bool{}
	client := redis.NewClient(&redis.Options{
		Addr: addr,
		Dialer: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &flakyConn{Conn: conn, broken: broken}, nil
		},
	})
	t.Cleanup(func() { _ = client.Close() })
	return client, broken
}
