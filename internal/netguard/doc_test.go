package netguard

import (
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"slices"
	"strconv"
	"testing"
)

// overHint is a body length past the 8 KiB read hint.
const overHint = 9000

// allocRuns is how many runs assertAllocs averages.
const allocRuns = 100

// raceEnabled reports whether the test binary runs the race detector.
func raceEnabled() bool {
	info, _ := debug.ReadBuildInfo()
	return info != nil &&
		slices.Contains(info.Settings, debug.BuildSetting{Key: "-race", Value: strconv.FormatBool(true)})
}

// assertAllocs fails t unless f allocates want times per run, averaged over
// allocRuns runs. The race detector changes allocation counts and drops pooled
// items, so under it f runs once, unchecked.
func assertAllocs(t *testing.T, want float64, f func()) {
	t.Helper()
	if raceEnabled() {
		f()
		return
	}
	if got := testing.AllocsPerRun(allocRuns, f); got != want {
		t.Errorf("allocs per run = %.0f, want %.0f", got, want)
	}
}

// testLimit is the body limit of the tests, which atLimit reaches and
// pastLimit passes by one byte.
const (
	testLimit = 5
	atLimit   = "12345"
	pastLimit = "123456"
)

var (
	errRead  = errors.New("test: read failed")
	errClose = errors.New("test: close failed")
	// errTooLarge is the error the tests pass for an oversized body.
	errTooLarge = errors.New("test: body too large")
)

// trackedBody is a request body that counts its closes and fails them with err.
type trackedBody struct {
	io.Reader

	err    error
	closes int
}

func (b *trackedBody) Close() error {
	b.closes++
	return b.err
}

// outbound builds a client request carrying payload without GetBody.
func outbound(tb testing.TB, payload io.Reader) *http.Request {
	tb.Helper()
	r, err := http.NewRequestWithContext(tb.Context(), http.MethodPost, "https://example.com/", payload)
	if err != nil {
		tb.Fatalf("NewRequestWithContext = %v, want a request", err)
	}
	r.GetBody = nil
	return r
}
