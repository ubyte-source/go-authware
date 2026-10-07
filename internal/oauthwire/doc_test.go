package oauthwire

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strconv"
	"testing"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
)

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

// tokenPath is the path of the token endpoint in the fixtures.
const tokenPath = "/token"

// tokenURL returns the token endpoint of the fixtures.
func tokenURL() *url.URL {
	return &url.URL{Scheme: "https", Host: "idp.example.com", Path: tokenPath}
}

// errTooLarge is the error the tests pass for an oversized body.
var errTooLarge = errors.New("test: body too large")

// headerContentType names the type of an answer.
const headerContentType = "Content-Type"

// strictObject reports whether body passes the strict walker.
func strictObject(body string) bool {
	return jsonobj.Iterate(body, errNotOAuth, func(_, _ string) error { return nil }) == nil
}

// closeBody reads its content and counts closes, each failing with err.
type closeBody struct {
	io.Reader

	err    error
	closes int
}

func (b *closeBody) Close() error {
	b.closes++
	return b.err
}

// errClose is the error a failing closeBody returns.
var errClose = errors.New("test: close failed")

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errSend is the failure of a transport that sends nothing.
var errSend = errors.New("test: send failed")

// testBody is the answer of the fetch and send tests.
const (
	testBody = "body"
	bodySize = int64(len(testBody))
)
