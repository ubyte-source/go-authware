package flight

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/retry"
)

// errCall is the failure of a shared call.
var errCall = errors.New("test: call failed")

type ctxKey struct{}

type result struct {
	value int
	err   error
}

// The rounds of a repeated call and the values the calls return.
const (
	rounds      = 3
	sharedValue = 7
	failedValue = 5
)

// unstarted returns a Func that fails t once a Group starts it.
func unstarted(t *testing.T) Func[int] {
	t.Helper()
	return func(context.Context) (int, error) {
		t.Error("Func started, want it refused or the call in flight joined")
		return 0, nil
	}
}

func TestGroupDoShares(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		var calls atomic.Int32
		release := make(chan struct{})
		fn := func(ctx context.Context) (int, error) {
			calls.Add(1)
			<-release
			return 42, ctx.Err()
		}
		results := make(chan result, 8)
		for range 8 {
			go func() {
				v, err := g.Do(t.Context(), time.Minute, fn)
				results <- result{value: v, err: err}
			}()
		}
		synctest.Wait()
		close(release)
		for range 8 {
			if r := <-results; r.err != nil || r.value != 42 {
				t.Fatalf("Do = %d, %v, want 42, nil", r.value, r.err)
			}
		}
		if n := calls.Load(); n != 1 {
			t.Fatalf("fn ran %d times, want 1", n)
		}
	})
}

func TestGroupDoRunsAgainAfterCompletion(t *testing.T) {
	t.Parallel()
	var g Group[int]
	var calls atomic.Int32
	fn := func(context.Context) (int, error) { return int(calls.Add(1)), nil }
	for want := 1; want <= rounds; want++ {
		v, err := g.Do(t.Context(), time.Minute, fn)
		if err != nil || v != want {
			t.Fatalf("Do = %d, %v; want %d", v, err, want)
		}
	}
}

func TestGroupDoLeaderCancel(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[string]
		release := make(chan struct{})
		fn := func(ctx context.Context) (string, error) {
			<-release
			return "token", ctx.Err()
		}
		leaderCtx, cancelLeader := context.WithCancel(t.Context())
		leader := make(chan result, 1)
		go func() {
			_, err := g.Do(leaderCtx, time.Minute, fn)
			leader <- result{err: err}
		}()
		synctest.Wait()
		follower := make(chan string, 1)
		go func() {
			v, err := g.Do(t.Context(), time.Minute, fn)
			if err != nil {
				v = err.Error()
			}
			follower <- v
		}()
		synctest.Wait()

		cancelLeader()
		synctest.Wait()
		select {
		case r := <-leader:
			if !errors.Is(r.err, ErrAbandoned) || !errors.Is(r.err, context.Canceled) {
				t.Fatalf("leader err = %v, want ErrAbandoned wrapping context.Canceled", r.err)
			}
		default:
			t.Fatal("canceled leader = still waiting, want context.Canceled at once")
		}
		close(release)
		if v := <-follower; v != "token" {
			t.Fatalf("follower got %q, want token from a call the leader did not cancel", v)
		}
	})
}

func TestGroupDoKeepsValues(t *testing.T) {
	t.Parallel()
	var g Group[any]
	ctx := context.WithValue(t.Context(), ctxKey{}, "tenant")
	v, err := g.Do(ctx, time.Minute, func(ctx context.Context) (any, error) {
		return ctx.Value(ctxKey{}), nil
	})
	if err != nil || v != "tenant" {
		t.Fatalf("Do = %v, %v, want the tenant of the context", v, err)
	}
}

func TestGroupDoTimeout(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		start := time.Now()
		_, err := g.Do(t.Context(), 3*time.Second, func(ctx context.Context) (int, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed != 3*time.Second {
			t.Fatalf("call ran %v, want 3s", elapsed)
		}
	})
}

func TestGroupDoCallerDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		var wg sync.WaitGroup
		wg.Add(1)
		finished := time.Time{}
		_, err := g.Do(ctx, time.Minute, func(context.Context) (int, error) {
			defer wg.Done()
			time.Sleep(10 * time.Second)
			finished = time.Now()
			return 1, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want DeadlineExceeded", err)
		}
		wg.Wait()
		if finished.IsZero() {
			t.Fatal("call finished = never, want the call to outlive its caller")
		}
	})
}

func TestGroupDoCanceledCaller(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var called atomic.Bool
		_, err := g.Do(ctx, time.Minute, func(context.Context) (int, error) {
			called.Store(true)
			return 1, nil
		})
		if !errors.Is(err, ErrAbandoned) || !errors.Is(err, context.Canceled) ||
			err.Error() != "shared call abandoned: context canceled" {
			t.Fatalf("err = %v, want ErrAbandoned wrapping context.Canceled", err)
		}
		synctest.Wait()
		if called.Load() {
			t.Fatal("fn called = true, want no call for a canceled caller")
		}
	})
}

func TestGroupDoError(t *testing.T) {
	t.Parallel()
	var g Group[int]
	_, err := g.Do(t.Context(), time.Minute, func(context.Context) (int, error) { return 0, errCall })
	if !errors.Is(err, errCall) {
		t.Fatalf("err = %v, want errCall", err)
	}
}

// TestGroupJoinRefused refuses fn while the second of two pauses waits.
func TestGroupJoinRefused(t *testing.T) {
	t.Parallel()
	var g Group[int]
	var idle, failed retry.Backoff
	now := time.Now()
	failed.Fail(now)
	v, ok, err := g.Join(t.Context(), time.Minute, unstarted(t), now, &idle, &failed)
	if v != 0 || ok || err != nil {
		t.Fatalf("Join(refused) = %d, %t, %v, want 0, false, nil", v, ok, err)
	}
	v, err = g.Do(t.Context(), time.Minute, func(context.Context) (int, error) { return sharedValue, nil })
	if v != sharedValue || err != nil {
		t.Fatalf("Do after a refused Join = %d, %v, want 7, nil", v, err)
	}
}

// TestGroupJoinStarts starts fn when no pause waits: one never began, the other ended.
func TestGroupJoinStarts(t *testing.T) {
	t.Parallel()
	var g Group[int]
	var idle, ended retry.Backoff
	now := time.Now()
	ended.Fail(now.Add(-time.Hour))
	v, ok, err := g.Join(t.Context(), time.Minute, func(context.Context) (int, error) { return failedValue, errCall },
		now, &idle, &ended)
	if v != failedValue || !ok || !errors.Is(err, errCall) {
		t.Fatalf("Join(started) = %d, %t, %v, want 5, true, errCall", v, ok, err)
	}
}

// TestGroupJoinJoins joins a call in flight although a pause waits: fn never
// starts, and both callers get the result of that one call.
func TestGroupJoinJoins(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		release := make(chan struct{})
		first := make(chan result, 1)
		go func() {
			v, err := g.Do(t.Context(), time.Minute, func(context.Context) (int, error) {
				<-release
				return 42, errCall
			})
			first <- result{value: v, err: err}
		}()
		synctest.Wait()
		joined := make(chan result, 1)
		go func() {
			var failed retry.Backoff
			now := time.Now()
			failed.Fail(now)
			v, ok, err := g.Join(t.Context(), time.Minute, unstarted(t), now, &failed)
			if !ok {
				t.Error("Join ok = false, want the call in flight joined")
			}
			joined <- result{value: v, err: err}
		}()
		synctest.Wait()
		close(release)
		for _, ch := range []chan result{first, joined} {
			if r := <-ch; r.value != 42 || !errors.Is(r.err, errCall) {
				t.Fatalf("result = %d, %v; want the shared 42 and errCall", r.value, r.err)
			}
		}
	})
}

// TestGroupJoinLockFree joins a call in flight while the lock that starts
// calls is held: joining takes no lock.
func TestGroupJoinLockFree(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		release := make(chan struct{})
		go func() {
			_, err := g.Do(t.Context(), time.Minute, func(context.Context) (int, error) {
				<-release
				return 3, nil
			})
			if err != nil {
				t.Errorf("Do = %v, want nil", err)
			}
		}()
		synctest.Wait()
		if g.current.Load() == nil {
			t.Fatal("Do left no call in flight, want the blocked one")
		}
		g.mu.Lock()
		joined := make(chan result, 2)
		go func() {
			v, _, err := g.Join(t.Context(), time.Minute, unstarted(t), time.Time{})
			joined <- result{value: v, err: err}
		}()
		go func() {
			v, _, err := g.Wait(t.Context())
			joined <- result{value: v, err: err}
		}()
		synctest.Wait()
		close(release)
		for range 2 {
			if r := <-joined; r.value != 3 || r.err != nil {
				t.Errorf("joined = %d, %v, want 3, nil with the lock held", r.value, r.err)
			}
		}
		g.mu.Unlock()
	})
}

func TestGroupWait(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		if v, ok, err := g.Wait(t.Context()); v != 0 || ok || err != nil {
			t.Fatalf("Wait with no call = %d, %t, %v, want 0, false, nil", v, ok, err)
		}
		release := make(chan struct{})
		go func() {
			_, err := g.Do(t.Context(), time.Minute, func(context.Context) (int, error) {
				<-release
				return 9, errCall
			})
			if !errors.Is(err, errCall) {
				t.Errorf("Do = %v, want errCall", err)
			}
		}()
		synctest.Wait()
		go func() {
			synctest.Wait()
			close(release)
		}()
		if v, ok, err := g.Wait(t.Context()); v != 9 || !ok || !errors.Is(err, errCall) {
			t.Fatalf("Wait during a call = %d, %t, %v, want 9, true, errCall", v, ok, err)
		}
		synctest.Wait()
		if _, ok, err := g.Wait(t.Context()); ok || err != nil {
			t.Fatalf("Wait after the call = %t, %v, want no call in flight", ok, err)
		}
	})
}

// TestGroupWaitCanceledCaller gives up while waiting for a call in flight: Wait
// reports the abandonment and the call completes for its own caller.
func TestGroupWaitCanceledCaller(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		release := make(chan struct{})
		leader := make(chan error, 1)
		go func() {
			_, err := g.Do(t.Context(), time.Minute, func(context.Context) (int, error) {
				<-release
				return sharedValue, nil
			})
			leader <- err
		}()
		synctest.Wait()
		waiting, stop := context.WithCancel(t.Context())
		go func() {
			synctest.Wait()
			stop()
		}()
		v, ok, err := g.Wait(waiting)
		if v != 0 || !ok || !errors.Is(err, ErrAbandoned) || !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait given up = %d, %t, %v; want 0, true and ErrAbandoned wrapping context.Canceled", v, ok, err)
		}
		close(release)
		if err := <-leader; err != nil {
			t.Fatalf("Do = %v, want nil: the waiter that gave up leaves the call running", err)
		}
	})
}

// TestGroupJoinCanceledCaller gives up before any call and while waiting for
// one: both times Join reports the abandonment without starting fn.
func TestGroupJoinCanceledCaller(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var g Group[int]
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		_, ok, err := g.Join(canceled, time.Minute, unstarted(t), time.Time{})
		if !ok || !errors.Is(err, ErrAbandoned) {
			t.Fatalf("Join before the call = %t, %v; want true and ErrAbandoned", ok, err)
		}
		release := make(chan struct{})
		leader := make(chan error, 1)
		go func() {
			_, err := g.Do(t.Context(), time.Minute, func(context.Context) (int, error) {
				<-release
				return 1, nil
			})
			leader <- err
		}()
		synctest.Wait()
		waiting, stop := context.WithCancel(t.Context())
		go func() {
			synctest.Wait()
			stop()
		}()
		if _, ok, err := g.Join(waiting, time.Minute, unstarted(t), time.Time{}); !ok || !errors.Is(err, ErrAbandoned) {
			t.Fatalf("Join during the call = %t, %v; want true and ErrAbandoned", ok, err)
		}
		close(release)
		if err := <-leader; err != nil {
			t.Fatalf("Do = %v, want nil: the joiner that gave up leaves the call running", err)
		}
	})
}
