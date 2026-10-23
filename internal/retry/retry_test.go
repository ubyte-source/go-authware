package retry

import (
	"testing"
	"time"
)

// An instant, a day and the documented 30s pause.
const (
	epochSeconds = 1_800_000_000
	day          = 24 * time.Hour
	pause        = 30 * time.Second
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

// TestBackoffClaim claims at instants inside and past each pause: a claim past
// the end of the pause starts one of 30s, any other leaves the pause as it is.
func TestBackoffClaim(t *testing.T) {
	t.Parallel()
	var b Backoff
	for i, st := range []struct{ at, end time.Duration }{
		{0, pause}, {0, pause}, {pause - time.Nanosecond, pause}, {pause, 2 * pause},
		{2*pause - time.Nanosecond, 2 * pause}, {2 * pause, 2*pause + pause},
	} {
		b.Claim(epoch().Add(st.at))
		last, ended := b.Waiting(epoch().Add(st.end-time.Nanosecond)), b.Waiting(epoch().Add(st.end))
		if !last || ended {
			t.Fatalf("step %d: after Claim(+%v), Waiting(+%v - 1ns) = %t and Waiting(+%v) = %t; want true, then false",
				i, st.at, st.end, last, st.end, ended)
		}
	}
	var failed Backoff
	failed.Fail(epoch())
	failed.Claim(epoch().Add(pause - time.Nanosecond))
	if got := failed.Waiting(epoch().Add(pause)); got {
		t.Fatalf("Claim during the pause of a failure, then Waiting(end of that pause) = %t, want false", got)
	}
	failed.Claim(epoch().Add(pause))
	last, ended := failed.Waiting(epoch().Add(2*pause-time.Nanosecond)), failed.Waiting(epoch().Add(2*pause))
	if !last || ended {
		t.Fatalf("Claim at the end of the pause of a failure, then Waiting just before and at 30s later = %t, %t; "+
			"want true, then false", last, ended)
	}
}

// TestBackoffClaimAfterConcurrentFail replays a claim whose load a Fail follows
// before its swap: the claim starts no pause, and the pause of the failure stays.
func TestBackoffClaimAfterConcurrentFail(t *testing.T) {
	t.Parallel()
	var b Backoff
	loaded := b.until.Load()
	b.Fail(epoch().Add(time.Second))
	b.claimAfter(loaded, epoch())
	if kept, ended := b.Waiting(epoch().Add(pause)), b.Waiting(epoch().Add(time.Second+pause)); !kept || ended {
		t.Fatalf("Waiting at the end of the claim's pause and of the failure's = %t, %t; want true, then false: "+
			"the pause of the failure", kept, ended)
	}
}
