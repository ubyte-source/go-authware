package authware

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/flight"
	"github.com/ubyte-source/go-authware/v2/internal/retry"
)

// staleAge is the oldest value served while refetches fail.
const staleAge = 24 * time.Hour

var errRetryBackoff = errors.New("waiting after a failed fetch")

type snapshot[T any] struct {
	fetched time.Time
	value   T
}

// youngerAt reports whether snap exists and is younger than age at now.
func (snap *snapshot[T]) youngerAt(now time.Time, age time.Duration) bool {
	return snap != nil && now.Before(snap.fetched.Add(age))
}

type fetcher[T any] func(ctx context.Context, now time.Time) (T, error)

// cache holds the value fetch returns, refetched once older than ttl through
// one shared fetch at a time. A failed fetch makes the next ones fail fast
// for retry.After, while stale serves the last value.
type cache[T any] struct {
	fetch fetcher[T]

	ttl     time.Duration
	timeout time.Duration

	group   flight.Group[T]
	backoff retry.Backoff
	snap    atomic.Pointer[snapshot[T]]
}

// get returns the value at now, refetching an expired one; while refetching
// fails, stale decides whether the last value is served.
func (c *cache[T]) get(ctx context.Context, now time.Time) (T, error) {
	snap := c.snap.Load()
	if snap.youngerAt(now, c.ttl) {
		return snap.value, nil
	}
	v, err := c.update(ctx, now)
	if err != nil {
		return stale(snap, now, err)
	}
	return v, nil
}

// update refetches the value through one shared fetch unless a failure is
// backing off.
func (c *cache[T]) update(ctx context.Context, now time.Time) (T, error) {
	if c.backoff.Waiting(now) {
		var zero T
		return zero, errRetryBackoff
	}
	return c.group.Do(ctx, c.timeout, func(ctx context.Context) (T, error) {
		return c.refetch(ctx, now)
	})
}

// refetch fetches the value as it stands at now, unless a fetch that ended
// after the caller looked stored a value fresh at now, or failed and backs off.
func (c *cache[T]) refetch(ctx context.Context, now time.Time) (T, error) {
	if snap := c.snap.Load(); snap.youngerAt(now, c.ttl) {
		return snap.value, nil
	}
	if c.backoff.Waiting(now) {
		var zero T
		return zero, errRetryBackoff
	}
	return c.refresh(ctx, now)
}

// force returns the value of the fetch in flight or, with none, of a fetch it
// starts when no failure is backing off and gap grants the claim. With no
// fetch, it fails while a failure backs off, else returns the value get does.
func (c *cache[T]) force(ctx context.Context, now time.Time, gap *retry.Backoff) (T, error) {
	v, ok, err := c.forced(ctx, now, gap)
	switch {
	case ok:
		return v, err
	case c.backoff.Waiting(now):
		return v, errRetryBackoff
	}
	return c.get(ctx, now)
}

// forced joins the fetch in flight or, when no pause runs at now, one it
// starts; ok is false when there is none. While a pause runs, it takes no
// lock.
func (c *cache[T]) forced(ctx context.Context, now time.Time, gap *retry.Backoff) (v T, ok bool, err error) {
	if c.paused(now, gap) {
		return c.group.Wait(ctx)
	}
	return c.group.Join(ctx, c.timeout, c.forcedFetch(now, gap), now, &c.backoff, gap)
}

// paused reports whether a failure backs off or gap pauses the refetches
// forced at now.
func (c *cache[T]) paused(now time.Time, gap *retry.Backoff) bool {
	return c.backoff.Waiting(now) || gap.Waiting(now)
}

// forcedFetch returns the refetch forced at now. It claims gap once the group
// publishes it, so a caller that sees the pause finds the refetch in flight or
// the value it stored.
func (c *cache[T]) forcedFetch(now time.Time, gap *retry.Backoff) flight.Func[T] {
	return func(ctx context.Context) (T, error) {
		gap.Claim(now)
		return c.refresh(ctx, now)
	}
}

// refresh fetches the value and records the outcome observed at now.
func (c *cache[T]) refresh(ctx context.Context, now time.Time) (T, error) {
	v, err := c.fetch(ctx, now)
	if err != nil {
		c.backoff.Fail(now)
		var zero T
		return zero, err
	}
	c.snap.Store(&snapshot[T]{fetched: now, value: v})
	c.backoff.Reset()
	return v, nil
}

// stale serves snap while younger than staleAge at now; else it fails with
// cause.
func stale[T any](snap *snapshot[T], now time.Time, cause error) (T, error) {
	if snap.youngerAt(now, staleAge) {
		return snap.value, nil
	}
	var zero T
	return zero, cause
}
