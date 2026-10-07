package authware

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

// countingSource answers each fetch with the number of fetches so far, or
// with errUpstream while failing is set.
type countingSource struct {
	calls         atomic.Int32
	markedFetches atomic.Int32
	failing       atomic.Bool
}

// The value of the third fetch, and the last value a stale cache serves.
const (
	refetched = 3
	lastValue = 7
)

func (s *countingSource) fetch(ctx context.Context, _ time.Time) (int32, error) {
	if isMarked(ctx) {
		s.markedFetches.Add(1)
	}
	n := s.calls.Add(1)
	if s.failing.Load() {
		return 0, errUpstream
	}
	return n, nil
}

// newCountingCache returns a cache of src refetched once older than ttl.
func newCountingCache(src *countingSource, ttl time.Duration) *cache[int32] {
	return &cache[int32]{fetch: src.fetch, ttl: ttl, timeout: time.Second}
}

// cacheStep is one get at the offset from testUnix, with the value, error
// and total fetches expected.
type cacheStep struct {
	at      time.Duration
	result  int32
	want    error
	fetches int32
}

func runCacheSteps(t *testing.T, c *cache[int32], src *countingSource, steps []cacheStep) {
	t.Helper()
	for i, st := range steps {
		v, err := c.get(t.Context(), time.Unix(testUnix, 0).Add(st.at))
		if v != st.result || !errors.Is(err, st.want) || src.calls.Load() != st.fetches {
			t.Fatalf("step %d: get(+%v) = %d, %v after %d fetches; want %d, %v after %d",
				i, st.at, v, err, src.calls.Load(), st.result, st.want, st.fetches)
		}
	}
}

func TestCacheGet(t *testing.T) {
	var src countingSource
	runCacheSteps(t, newCountingCache(&src, defaultKeysCacheTTL), &src, []cacheStep{
		{at: 0, result: 1, fetches: 1},
		{at: defaultKeysCacheTTL - time.Nanosecond, result: 1, fetches: 1},
		{at: defaultKeysCacheTTL, result: 2, fetches: 2},
	})
}

func TestCacheGetStale(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, defaultKeysCacheTTL)
	runCacheSteps(t, c, &src, []cacheStep{{at: 0, result: 1, fetches: 1}})
	src.failing.Store(true)
	ttl, backoff := defaultKeysCacheTTL, fetchPause
	runCacheSteps(t, c, &src, []cacheStep{
		{at: ttl, result: 1, fetches: 2},
		{at: ttl + backoff - time.Nanosecond, result: 1, fetches: 2},
		{at: ttl + backoff, result: 1, fetches: 3},
		{at: staleLimit - time.Nanosecond, result: 1, fetches: 4},
		{at: staleLimit, want: errRetryBackoff, fetches: 4},
		{at: staleLimit + backoff, want: errUpstream, fetches: 5},
		{at: staleLimit + backoff + time.Second, want: errRetryBackoff, fetches: 5},
	})
	src.failing.Store(false)
	runCacheSteps(t, c, &src, []cacheStep{{at: staleLimit + 2*backoff, result: 6, fetches: 6}})
}

// TestCacheGetLongTTL serves a value younger than its TTL, though older than
// staleLimit, while a failed forced refetch backs off, and nothing once expired.
func TestCacheGetLongTTL(t *testing.T) {
	var src countingSource
	const ttl = 2 * staleLimit
	c := newCountingCache(&src, ttl)
	runCacheSteps(t, c, &src, []cacheStep{{at: 0, result: 1, fetches: 1}})
	src.failing.Store(true)
	var gap retry.Backoff
	failed := time.Unix(testUnix, 0).Add(staleLimit + time.Second)
	if v, err := c.force(t.Context(), failed, &gap); !errors.Is(err, errUpstream) || v != 0 {
		t.Fatalf("force(failing) = %d, %v, want 0, errUpstream", v, err)
	}
	runCacheSteps(t, c, &src, []cacheStep{
		{at: staleLimit + 2*time.Second, result: 1, fetches: 2},
		{at: ttl - time.Nanosecond, result: 1, fetches: 2},
		{at: ttl, want: errUpstream, fetches: 3},
	})
}

// TestCacheGetFreshDuringForcedRefetch serves the fresh value at once while a
// refetch that another caller forced is in flight.
func TestCacheGetFreshDuringForcedRefetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		c := &cache[int32]{ttl: time.Hour, timeout: time.Hour, fetch: func(context.Context, time.Time) (int32, error) {
			<-release
			return refetched, nil
		}}
		now := time.Now()
		c.snap.Store(&snapshot[int32]{fetched: now, value: lastValue})
		var gap retry.Backoff
		forced, served := make(chan int32, 1), make(chan int32, 1)
		go func() {
			v, err := c.force(t.Context(), now, &gap)
			if err != nil {
				t.Errorf("force = %v, want the refetched value", err)
			}
			forced <- v
		}()
		synctest.Wait()
		go func() {
			v, err := c.get(t.Context(), now)
			if err != nil {
				t.Errorf("get during the forced refetch = %v, want the fresh value", err)
			}
			served <- v
		}()
		synctest.Wait()
		select {
		case v := <-served:
			if v != lastValue {
				t.Errorf("get during the forced refetch = %d, want the fresh %d", v, lastValue)
			}
		default:
			t.Error("get waited for the forced refetch, want the fresh value at once")
		}
		close(release)
		if v := <-forced; v != refetched {
			t.Errorf("force = %d, want %d", v, refetched)
		}
	})
}

func TestCacheGetCanceled(t *testing.T) {
	var src countingSource
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := newCountingCache(&src, time.Minute).get(ctx, time.Unix(testUnix, 0)); !errors.Is(err,
		context.Canceled) ||
		v != 0 || src.calls.Load() != 0 {
		t.Fatalf("get(canceled) = %d, %v after %d fetches, want context.Canceled before any", v, err, src.calls.Load())
	}
}

func TestCacheGetShared(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		c := &cache[*int]{timeout: time.Second, ttl: time.Minute, fetch: func(context.Context, time.Time) (*int,
			error) {
			calls.Add(1)
			<-release
			return new(int), nil
		}}
		results := make([]*int, 8)
		var done sync.WaitGroup
		for i := range results {
			done.Go(func() {
				v, err := c.get(t.Context(), time.Unix(testUnix, 0))
				if err != nil {
					t.Errorf("get = %v, want nil", err)
				}
				results[i] = v
			})
		}
		synctest.Wait()
		close(release)
		done.Wait()
		if n := calls.Load(); n != 1 {
			t.Fatalf("fetches = %d, want 1", n)
		}
		for _, v := range results {
			if v == nil || v != results[0] {
				t.Fatalf("value = %p, want the shared non-nil %p", v, results[0])
			}
		}
	})
}

func TestCacheUpdate(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, time.Minute)
	now := time.Unix(testUnix, 0)
	c.backoff.Fail(now)
	if v, err := c.update(t.Context(), now); !errors.Is(err, errRetryBackoff) || v != 0 || src.calls.Load() != 0 {
		t.Fatalf("update(backing off) = %d, %v after %d fetches, want errRetryBackoff before any", v, err,
			src.calls.Load())
	}
	if v, err := c.update(t.Context(), now.Add(fetchPause)); err != nil || v != 1 {
		t.Fatalf("update(after the backoff) = %d, %v, want 1, nil", v, err)
	}
	// A caller that looked before that fetch stored its value updates after it.
	if v, err := c.update(t.Context(), now.Add(fetchPause)); err != nil || v != 1 || src.calls.Load() != 1 {
		t.Fatalf("update(after a fetch it did not see) = %d, %v after %d fetches, want 1 after 1", v, err,
			src.calls.Load())
	}
}

// TestCacheRefetch starts no fetch when the fetch that ended after its caller
// looked stored a fresh value, or failed and backs off.
func TestCacheRefetch(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, time.Minute)
	now := time.Unix(testUnix, 0)
	for _, st := range []struct {
		at      time.Duration
		result  int32
		want    error
		fetches int32
		failing bool
	}{
		{at: 0, result: 1, fetches: 1},
		{at: time.Minute - time.Nanosecond, result: 1, fetches: 1},
		{at: time.Minute, want: errUpstream, fetches: 2, failing: true},
		{at: time.Minute + time.Second, want: errRetryBackoff, fetches: 2, failing: true},
	} {
		src.failing.Store(st.failing)
		v, err := c.refetch(t.Context(), now.Add(st.at))
		if v != st.result || !errors.Is(err, st.want) || src.calls.Load() != st.fetches {
			t.Fatalf("refetch(+%v) = %d, %v after %d fetches; want %d, %v after %d", st.at, v, err,
				src.calls.Load(), st.result, st.want, st.fetches)
		}
	}
}

// TestCacheForce forces refetches of a cached value: at most one per
// retry.After.
func TestCacheForce(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, time.Hour)
	runCacheSteps(t, c, &src, []cacheStep{{at: 0, result: 1, fetches: 1}})
	var gap retry.Backoff
	now := time.Unix(testUnix, 0)
	for _, st := range []cacheStep{
		{at: time.Second, result: 2, fetches: 2},
		{at: 2 * time.Second, result: 2, fetches: 2},
		{at: time.Second + fetchPause - time.Nanosecond, result: 2, fetches: 2},
		{at: time.Second + fetchPause, result: refetched, fetches: refetched},
	} {
		if v, err := c.force(t.Context(), now.Add(st.at), &gap); v != st.result || err != nil ||
			src.calls.Load() != st.fetches {
			t.Fatalf("force(+%v) = %d, %v after %d fetches; want %d after %d", st.at, v, err, src.calls.Load(),
				st.result, st.fetches)
		}
	}
}

// TestCacheForcePausedGets serves, while the gap pauses forced refetches, the
// value get returns, refetched under the caller's context once it expired.
func TestCacheForcePausedGets(t *testing.T) {
	var src countingSource
	const ttl = 10 * time.Second
	c := newCountingCache(&src, ttl)
	runCacheSteps(t, c, &src, []cacheStep{{at: 0, result: 1, fetches: 1}})
	now := time.Unix(testUnix, 0)
	var gap retry.Backoff
	gap.Claim(now)
	expired := now.Add(2 * ttl)
	if v, err := c.force(marked(t), expired, &gap); err != nil || v != 2 || src.markedFetches.Load() != 1 {
		t.Fatalf("force(paused, expired) = %d, %v after %d marked fetches; want 2 after 1", v, err,
			src.markedFetches.Load())
	}
}

// TestCacheForcePausedWaitEndsWithTheContext stops waiting for the refetch in
// flight, while the gap pauses forced ones, once the caller's context ends.
func TestCacheForcePausedWaitEndsWithTheContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		c := &cache[int32]{ttl: time.Hour, timeout: time.Hour, fetch: func(context.Context, time.Time) (int32, error) {
			<-release
			return 1, nil
		}}
		now := time.Now()
		var gap retry.Backoff
		first := make(chan error, 1)
		go func() {
			_, err := c.force(t.Context(), now, &gap)
			first <- err
		}()
		synctest.Wait()
		ended, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := c.force(ended, now, &gap); !errors.Is(err, context.Canceled) {
			t.Errorf("force(ended, paused) = %v, want context.Canceled", err)
		}
		close(release)
		if err := <-first; err != nil {
			t.Errorf("force = %v, want the value", err)
		}
	})
}

// TestCacheForcePausedEndedContextGets serves the fresh value to a caller whose
// context has ended while the gap pauses forced refetches and none is in flight.
func TestCacheForcePausedEndedContextGets(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, time.Hour)
	runCacheSteps(t, c, &src, []cacheStep{{at: 0, result: 1, fetches: 1}})
	now := time.Unix(testUnix, 0)
	var gap retry.Backoff
	gap.Claim(now)
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := c.force(ended, now, &gap); err != nil || v != 1 || src.calls.Load() != 1 {
		t.Fatalf("force(ended, paused) = %d, %v after %d fetches; want 1 after 1", v, err, src.calls.Load())
	}
}

// TestCacheForceBackingOff forces a refetch that fails: while the failure
// backs off, force fails fast and claims no gap.
func TestCacheForceBackingOff(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, time.Hour)
	runCacheSteps(t, c, &src, []cacheStep{{at: 0, result: 1, fetches: 1}})
	src.failing.Store(true)
	var gap retry.Backoff
	failed := time.Unix(testUnix, 0).Add(time.Second)
	if v, err := c.force(t.Context(), failed, &gap); !errors.Is(err, errUpstream) || v != 0 || src.calls.Load() != 2 {
		t.Fatalf("force(failing) = %d, %v after %d fetches, want errUpstream after 2", v, err, src.calls.Load())
	}
	var unclaimed retry.Backoff
	later := failed.Add(time.Second)
	if v, err := c.force(t.Context(), later, &unclaimed); !errors.Is(err, errRetryBackoff) || v != 0 ||
		src.calls.Load() != 2 || unclaimed.Waiting(later) {
		t.Fatalf("force(backing off) = %d, %v after %d fetches, claimed %v; want errRetryBackoff after 2, unclaimed",
			v, err, src.calls.Load(), unclaimed.Waiting(later))
	}
}

// TestCacheForcedFetch runs a forced refetch: the refetch, not its creation,
// claims the gap, so the claim follows its publication.
func TestCacheForcedFetch(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, time.Hour)
	now := time.Unix(testUnix, 0)
	var free retry.Backoff
	fn := c.forcedFetch(now, &free)
	if free.Waiting(now) {
		t.Fatal("forcedFetch claimed the gap before the refetch ran, want it unclaimed")
	}
	if v, err := fn(t.Context()); v != 1 || err != nil || src.calls.Load() != 1 || !free.Waiting(now) {
		t.Fatalf("refetch = %d, %v after %d fetches, claimed %v; want 1 after 1, the gap claimed", v, err,
			src.calls.Load(), free.Waiting(now))
	}
}

func TestCacheRefreshFailure(t *testing.T) {
	var src countingSource
	src.failing.Store(true)
	c := newCountingCache(&src, time.Second)
	now := time.Unix(testUnix, 0)
	v, err := c.refresh(t.Context(), now)
	if !errors.Is(err, errUpstream) || v != 0 || c.snap.Load() != nil || !c.backoff.Waiting(now) {
		t.Fatalf("refresh = %d, %v, want errUpstream, no snapshot and the backoff started", v, err)
	}
}

func TestCacheRefreshSuccess(t *testing.T) {
	var src countingSource
	c := newCountingCache(&src, time.Second)
	now := time.Unix(testUnix, 0)
	c.backoff.Fail(now)
	v, err := c.refresh(t.Context(), now)
	if snap := c.snap.Load(); err != nil || v != 1 || *snap != (snapshot[int32]{fetched: now, value: 1}) ||
		c.backoff.Waiting(now) {
		t.Fatalf("refresh = %d, %v with snapshot %+v, want 1 recorded at now and the backoff reset", v, err, snap)
	}
}

// TestStale serves the last value through get while fetches fail, until
// 24h after its fetch; with a TTL of 24h or more nothing stale is served.
func TestStale(t *testing.T) {
	fetched := time.Unix(testUnix, 0)
	failing := func(context.Context, time.Time) (int32, error) { return 0, errUpstream }
	for _, tc := range []struct {
		ttl, at time.Duration
		served  bool
	}{
		{defaultKeysCacheTTL, staleLimit - time.Nanosecond, true},
		{defaultKeysCacheTTL, staleLimit, false},
		{staleLimit, staleLimit, false},
		{2 * staleLimit, 2 * staleLimit, false},
	} {
		c := &cache[int32]{fetch: failing, ttl: tc.ttl, timeout: time.Second}
		c.snap.Store(&snapshot[int32]{fetched: fetched, value: lastValue})
		v, err := c.get(t.Context(), fetched.Add(tc.at))
		if served := err == nil && v == lastValue; served != tc.served || !tc.served && !errors.Is(err, errUpstream) {
			t.Errorf("get(TTL %v, fetched %v ago) = %d, %v; want the last value %v", tc.ttl, tc.at, v, err, tc.served)
		}
	}
	if v, err := stale[int32](nil, fetched, errUpstream); !errors.Is(err, errUpstream) || v != 0 {
		t.Fatalf("stale(no value) = %d, %v, want the cause", v, err)
	}
}

func TestSnapshotYoungerAt(t *testing.T) {
	snap := &snapshot[int32]{fetched: time.Unix(testUnix, 0)}
	for at, want := range map[time.Duration]bool{
		-time.Second: true, time.Minute - time.Nanosecond: true, time.Minute: false,
	} {
		if got := snap.youngerAt(snap.fetched.Add(at), time.Minute); got != want {
			t.Errorf("youngerAt(+%v) = %v, want %v", at, got, want)
		}
	}
	if (*snapshot[int32])(nil).youngerAt(snap.fetched, time.Minute) {
		t.Error("youngerAt(nil) = true, want false")
	}
}
