package retry

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// An instant, a day, the documented 30s pause, and the rounds and concurrent
// claims of the race test.
const (
	epochSeconds = 1_800_000_000
	day          = 24 * time.Hour
	pause        = 30 * time.Second
	rounds       = 50
	claimers     = 64
)

// epoch is the instant the tests start their pauses at.
func epoch() time.Time { return time.Unix(epochSeconds, 0) }

func TestBackoffWaiting(t *testing.T) {
	t.Parallel()
	var b Backoff
	if b.Waiting(epoch()) {
		t.Fatal("zero Backoff Waiting = true, want false")
	}
	b.Fail(epoch())
	for at, want := range map[time.Duration]bool{
		-time.Hour:              true,
		0:                       true,
		pause - time.Nanosecond: true,
		pause:                   false,
		pause + time.Nanosecond: false,
		pause + day:             false,
	} {
		if got := b.Waiting(epoch().Add(at)); got != want {
			t.Errorf("Waiting(Fail + %v) = %v, want %v", at, got, want)
		}
	}
}

func TestBackoffFail(t *testing.T) {
	t.Parallel()
	var b Backoff
	b.Fail(epoch())
	b.Fail(epoch().Add(time.Minute))
	if !b.Waiting(epoch().Add(time.Minute+pause-time.Nanosecond)) || b.Waiting(epoch().Add(time.Minute+pause)) {
		t.Fatal("a second Fail left the first pause, want the pause restarted from the second")
	}
}

func TestBackoffReset(t *testing.T) {
	t.Parallel()
	var b Backoff
	b.Fail(epoch())
	b.Reset()
	if b.Waiting(epoch()) {
		t.Fatal("Waiting after Reset = true, want false")
	}
}

func TestBackoffClaim(t *testing.T) {
	t.Parallel()
	var b Backoff
	for i, st := range []struct {
		at   time.Duration
		want bool
	}{
		{0, true}, {0, false}, {pause - time.Nanosecond, false}, {pause, true},
		{2*pause - time.Nanosecond, false}, {2 * pause, true},
	} {
		if got := b.Claim(epoch().Add(st.at)); got != st.want {
			t.Fatalf("step %d: Claim(+%v) = %v, want %v", i, st.at, got, st.want)
		}
	}
	var failed Backoff
	failed.Fail(epoch())
	if failed.Claim(epoch().Add(pause-time.Nanosecond)) || !failed.Claim(epoch().Add(pause)) {
		t.Fatal("Claim during the pause of a failure = true, or after it = false; want false, then true")
	}
}

// TestBackoffClaimConcurrent releases 64 spinning claims at one instant, round
// after round: exactly one claim of each round wins.
func TestBackoffClaimConcurrent(t *testing.T) {
	t.Parallel()
	for round := range rounds {
		var b Backoff
		var wins atomic.Int32
		var start atomic.Bool
		var ready, done sync.WaitGroup
		for range claimers {
			ready.Add(1)
			done.Go(func() {
				ready.Done()
				for !start.Load() {
					runtime.Gosched()
				}
				if b.Claim(epoch()) {
					wins.Add(1)
				}
			})
		}
		ready.Wait()
		start.Store(true)
		done.Wait()
		if n := wins.Load(); n != 1 {
			t.Fatalf("round %d: concurrent claims won %d times, want 1", round, n)
		}
	}
}
