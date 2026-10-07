package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The timeout Client is given, and one of a base client.
const (
	testTimeout = 3 * time.Second
	baseTimeout = 7 * time.Second
)

func TestClientTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		base    *http.Client
		timeout time.Duration
		want    time.Duration
	}{
		{nil, testTimeout, testTimeout},
		{nil, 0, 0},
		{&http.Client{}, testTimeout, testTimeout},
		{&http.Client{Timeout: time.Second}, testTimeout, time.Second},
		{&http.Client{Timeout: baseTimeout}, testTimeout, testTimeout},
		{&http.Client{Timeout: 2 * time.Second}, 0, 2 * time.Second},
		{&http.Client{Timeout: time.Nanosecond}, testTimeout, time.Nanosecond},
		{&http.Client{Timeout: baseTimeout}, time.Nanosecond, time.Nanosecond},
	}
	for i, tc := range cases {
		if got := Client(tc.base, tc.timeout).Timeout; got != tc.want {
			t.Fatalf("case %d: Timeout = %v, want %v", i, got, tc.want)
		}
	}
}

func TestClientKeepsBase(t *testing.T) {
	t.Parallel()
	transport := &http.Transport{}
	allow := func(*http.Request, []*http.Request) error { return nil }
	base := &http.Client{Transport: transport, CheckRedirect: allow, Timeout: baseTimeout}
	c := Client(base, time.Second)
	if c == base {
		t.Fatal("Client(base) = base, want a copy")
	}
	if c.Transport != transport {
		t.Fatalf("Client transport = %v, want the base transport", c.Transport)
	}
	if base.Timeout != baseTimeout || base.CheckRedirect == nil {
		t.Fatalf("base = timeout %v, redirect policy set %t, want %v and true", base.Timeout,
			base.CheckRedirect != nil, baseTimeout)
	}
	if err := base.CheckRedirect(nil, nil); err != nil {
		t.Fatalf("base CheckRedirect = %v, want nil: base keeps its policy", err)
	}
}

func TestClientRefusesRedirect(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	allow := func(*http.Request, []*http.Request) error { return nil }
	for _, base := range []*http.Client{nil, {CheckRedirect: allow}} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin.URL, strings.NewReader("secret=x"))
		if err != nil {
			t.Fatalf("NewRequestWithContext = %v, want a request", err)
		}
		resp, err := Client(base, time.Second).Do(req)
		if err != nil {
			t.Fatalf("Do = %v, want the redirect answer", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want 307", resp.StatusCode)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("redirect target requests = %d, want 0", n)
	}
}

func TestRefuseRedirect(t *testing.T) {
	t.Parallel()
	if err := refuseRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("refuseRedirect = %v, want http.ErrUseLastResponse", err)
	}
}
