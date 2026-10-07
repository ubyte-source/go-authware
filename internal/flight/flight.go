package flight

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/retry"
)

// ErrAbandoned reports a caller that stopped waiting for the shared call.
var ErrAbandoned = errors.New("shared call abandoned")

// Func is a call that a Group shares.
type Func[T any] func(ctx context.Context) (T, error)

// call is one shared run, whose result is readable once done is closed.
type call[T any] struct {
	done chan struct{}
	val  T
	err  error
}

// wait returns the result of c, or the abandonment of the caller of ctx when
// that comes first.
func (c *call[T]) wait(ctx context.Context) (T, error) {
	select {
	case <-c.done:
		return c.val, c.err
	case <-ctx.Done():
		var zero T
		return zero, abandoned(ctx)
	}
}

// Group shares one in-flight call among concurrent callers. It is safe for concurrent
// use, its zero value is ready, and it must not be copied after first use.
type Group[T any] struct {
	mu      sync.Mutex
	current atomic.Pointer[call[T]]
}

// Do returns the value and error of the call in flight, or of fn, not nil, started
// under a context that keeps the values of ctx, ignores its cancellation and expires
// after timeout; a caller whose ctx ends first gets ErrAbandoned, any call running on.
func (g *Group[T]) Do(ctx context.Context, timeout time.Duration, fn Func[T]) (T, error) {
	v, _, err := g.Join(ctx, timeout, fn, time.Time{})
	return v, err
}

// Join is Do that starts fn only while no pause of pauses waits at now, checked
// under the lock that orders the calls; ok is false when a pause kept fn from
// starting. Joining a call in flight takes no lock and checks no pause.
func (g *Group[T]) Join(ctx context.Context, timeout time.Duration, fn Func[T], now time.Time,
	pauses ...*retry.Backoff) (v T, ok bool, err error) {
	if ctx.Err() != nil {
		return v, true, abandoned(ctx)
	}
	c := g.current.Load()
	if c == nil {
		if c = g.enter(ctx, timeout, fn, now, pauses); c == nil {
			return v, false, nil
		}
	}
	v, err = c.wait(ctx)
	return v, true, err
}

// Wait returns the result of the call in flight without starting one, or
// ErrAbandoned when ctx ends first; ok is false when none is in flight.
func (g *Group[T]) Wait(ctx context.Context) (v T, ok bool, err error) {
	c := g.current.Load()
	if c == nil {
		return v, false, nil
	}
	v, err = c.wait(ctx)
	return v, true, err
}

// enter returns the call in flight or, with none, a new call of fn unless a pause
// of pauses waits at now; nil when one waits.
func (g *Group[T]) enter(ctx context.Context, timeout time.Duration, fn Func[T], now time.Time,
	pauses []*retry.Backoff) *call[T] {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.current.Load()
	if c != nil || slices.ContainsFunc(pauses, func(p *retry.Backoff) bool { return p.Waiting(now) }) {
		return c
	}
	c = &call[T]{done: make(chan struct{})}
	g.current.Store(c)
	go g.run(ctx, timeout, c, fn)
	return c
}

// run executes fn and clears the group before waking the callers; only the
// call in flight clears it, so no lock orders the clearing.
func (g *Group[T]) run(ctx context.Context, timeout time.Duration, c *call[T], fn Func[T]) {
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	c.val, c.err = fn(callCtx)
	g.current.Store(nil)
	close(c.done)
}

// abandoned reports why the caller of ctx stopped waiting.
func abandoned(ctx context.Context) error {
	return fmt.Errorf("%w: %w", ErrAbandoned, ctx.Err())
}
