package cache

import (
	"context"
	"testing"
	"time"

	"github.com/efangly/smtrack-authentication/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With nothing listening, the first call pays for the failed connection and the rest fail at
// once instead of each waiting for their own timeout.
func TestRedisDown_FailsFastAfterFirstError(t *testing.T) {
	c, store := NewRedisAdapter(&config.Config{RedisURL: "redis://127.0.0.1:1/0"})
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 50; i++ {
		_, err := store.LoginFailures(ctx, "alice")
		require.Error(t, err)
		_, err = c.Get(ctx, "user:1", &struct{}{})
		require.Error(t, err)
		require.Error(t, c.Set(ctx, "user:1", 1, time.Minute))
		require.Error(t, c.Del(ctx, "user"))
	}
	assert.Less(t, time.Since(start), 3*time.Second, "200 calls against a dead Redis must not each wait")
}

func TestBreaker_ClosesAfterCooldownAndIgnoresServerReplies(t *testing.T) {
	now := time.Now()
	b := &breaker{now: func() time.Time { return now }}

	b.observe(context.DeadlineExceeded)
	assert.True(t, b.open())
	now = now.Add(breakerCooldown + time.Millisecond)
	assert.False(t, b.open(), "the next call after the cooldown is the probe")

	b.observe(nil)
	assert.False(t, b.open())
	b.observe(context.Canceled)
	assert.False(t, b.open(), "a cancelled caller says nothing about Redis")
}
