package cache

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is optional for availability: the cache falls back to the database and the session
// store lets logins through. What that must not cost is time. Without a breaker every Redis
// call of every request waits for its own dial timeout, so an outage turns a 100 ms request
// into several seconds. After a network failure the breaker fails every command at once for
// breakerCooldown, then lets the next one through as a probe.
const breakerCooldown = 5 * time.Second

var errCircuitOpen = errors.New("redis unavailable (circuit open)")

type breaker struct {
	openUntil atomic.Int64 // unix nanoseconds; 0 = closed
	now       func() time.Time
}

func newBreaker() *breaker { return &breaker{now: time.Now} }

func (b *breaker) open() bool {
	until := b.openUntil.Load()
	return until != 0 && b.now().UnixNano() < until
}

// observe trips the breaker on a transport failure. A reply from the server (including an
// error reply or a missing key) proves Redis is up, and a cancelled caller says nothing about it.
func (b *breaker) observe(err error) {
	if err == nil {
		b.openUntil.Store(0)
		return
	}
	var reply redis.Error
	if errors.As(err, &reply) || errors.Is(err, redis.Nil) || errors.Is(err, context.Canceled) {
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) || isConnClosed(err) {
		b.openUntil.Store(b.now().Add(breakerCooldown).UnixNano())
	}
}

func isConnClosed(err error) bool {
	s := err.Error()
	return errors.Is(err, net.ErrClosed) || s == "EOF" || s == "redis: client is closed"
}

// Hook methods make *breaker a redis.Hook.

func (b *breaker) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := next(ctx, network, addr)
		b.observe(err)
		return conn, err
	}
}

func (b *breaker) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if b.open() {
			return errCircuitOpen
		}
		err := next(ctx, cmd)
		b.observe(err)
		return err
	}
}

func (b *breaker) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if b.open() {
			return errCircuitOpen
		}
		err := next(ctx, cmds)
		b.observe(err)
		return err
	}
}
