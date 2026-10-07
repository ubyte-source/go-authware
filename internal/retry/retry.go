package retry

import (
	"sync/atomic"
	"time"
)

// After is the pause that follows a failed call or a forced one.
const After = 30 * time.Second

// Backoff holds the end of the current pause. It is safe for concurrent use, and
// its zero value holds no pause.
type Backoff struct {
	until atomic.Pointer[time.Time]
}

// Waiting reports whether now comes before the end of the current pause.
func (b *Backoff) Waiting(now time.Time) bool {
	return inside(b.until.Load(), now)
}

// Fail starts a pause at now, when a call failed.
func (b *Backoff) Fail(now time.Time) {
	b.until.Store(pauseFrom(now))
}

// Reset ends the pause after a call that succeeded.
func (b *Backoff) Reset() {
	b.until.Store(nil)
}

// Claim starts a pause at now unless now comes before the end of the current one or a
// concurrent call changes the pause first, and reports whether it did.
func (b *Backoff) Claim(now time.Time) bool {
	last := b.until.Load()
	return !inside(last, now) && b.until.CompareAndSwap(last, pauseFrom(now))
}

// inside reports whether now comes before until, the end of a pause.
func inside(until *time.Time, now time.Time) bool {
	return until != nil && now.Before(*until)
}

// pauseFrom returns the end of a pause that starts at now.
func pauseFrom(now time.Time) *time.Time {
	until := now.Add(After)
	return &until
}
