package cred

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestToken_Apply_Defaults(t *testing.T) {
	tok := &Token{Value: "abc"}
	r := newReq(t, http.MethodGet, "/", http.NoBody)
	tok.Apply(r)
	if got := r.Header.Get("Authorization"); got != "Bearer abc" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestToken_Apply_CustomTypeAndHeader(t *testing.T) {
	tok := &Token{Value: "xyz", Type: "Basic", Header: "X-Auth"}
	r := newReq(t, http.MethodGet, "/", http.NoBody)
	tok.Apply(r)
	if got := r.Header.Get("X-Auth"); got != "Basic xyz" {
		t.Fatalf("X-Auth = %q", got)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization should be empty, got %q", got)
	}
}

func TestTokenSourceFunc(t *testing.T) {
	var called bool
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		called = true
		return &Token{Value: "v"}, nil
	})
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("func not called")
	}
}

func TestSignerFunc(t *testing.T) {
	var called bool
	s := SignerFunc(func(_ context.Context, r *http.Request) error {
		called = true
		r.Header.Set("X-Sig", "ok")
		return nil
	})
	r := newReq(t, http.MethodGet, "/", http.NoBody)
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if !called || r.Header.Get("X-Sig") != "ok" {
		t.Fatalf("not signed: called=%v sig=%q", called, r.Header.Get("X-Sig"))
	}
}

func TestAsSigner_AppliesToken(t *testing.T) {
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		return &Token{Value: "abc"}, nil
	})
	r := newReq(t, http.MethodGet, "/", http.NoBody)
	if err := AsSigner(src).Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer abc" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestAsSigner_PropagatesError(t *testing.T) {
	want := errors.New("boom")
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) { return nil, want })
	err := AsSigner(src).Sign(context.Background(), newReq(t, http.MethodGet, "/", http.NoBody))
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// recordingTransport stores the request it sees and returns a 204.
type recordingTransport struct {
	seen *http.Request
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.seen = r
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     http.Header{},
	}, nil
}

func TestRoundTripper_Signs(t *testing.T) {
	rec := &recordingTransport{}
	rt := RoundTripper(rec, AsSigner(TokenSourceFunc(func(_ context.Context) (*Token, error) {
		return &Token{Value: "ok"}, nil
	})))
	req := newReq(t, http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Fatalf("close: %v", closeErr)
	}
	if got := rec.seen.Header.Get("Authorization"); got != "Bearer ok" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestRoundTripper_NoMutateOriginal(t *testing.T) {
	rec := &recordingTransport{}
	rt := RoundTripper(rec, AsSigner(TokenSourceFunc(func(_ context.Context) (*Token, error) {
		return &Token{Value: "ok"}, nil
	})))
	req := newReq(t, http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Fatalf("close: %v", closeErr)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("original mutated: Authorization = %q", got)
	}
}

func TestRoundTripper_PropagatesSignerError(t *testing.T) {
	want := errors.New("signer broken")
	rt := RoundTripper(&recordingTransport{}, SignerFunc(func(_ context.Context, _ *http.Request) error {
		return want
	}))
	resp, err := rt.RoundTrip(newReq(t, http.MethodGet, "/", http.NoBody))
	if resp != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("close: %v", closeErr)
		}
		t.Fatalf("expected nil response on error, got %v", resp)
	}
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestRoundTripper_NilBaseUsesDefault(t *testing.T) {
	rt := RoundTripper(nil, SignerFunc(func(_ context.Context, _ *http.Request) error { return nil }))
	if rt == nil {
		t.Fatal("expected non-nil RoundTripper")
	}
}

func TestCache_PanicOnNilSource(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = Cache(nil)
}

func TestCache_ServesFreshFromUpstream(t *testing.T) {
	calls := 0
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		calls++
		return &Token{Value: "v", Expires: time.Now().Add(time.Hour)}, nil
	})
	c := Cache(src)
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "v" {
		t.Fatalf("Value = %q", tok.Value)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestCache_ReusesUntilSkew(t *testing.T) {
	calls := 0
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		calls++
		return &Token{Value: "v", Expires: time.Unix(1000, 0)}, nil
	})
	clock := time.Unix(0, 0)
	c := Cache(src, WithSkew(10*time.Second), WithClock(func() time.Time { return clock }))

	for range 5 {
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected single upstream call, got %d", calls)
	}
}

func TestCache_RefreshesNearExpiry(t *testing.T) {
	calls := atomic.Int64{}
	clock := time.Unix(0, 0)
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		calls.Add(1)
		return &Token{Value: "v", Expires: clock.Add(1000 * time.Second)}, nil
	})
	c := Cache(src, WithSkew(60*time.Second), WithClock(func() time.Time { return clock }))

	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	// First token expires at +1000s. With skew=60s the cache treats it as
	// stale once clock crosses +940s; move past that and force a refresh.
	clock = time.Unix(950, 0)
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
}

func TestCache_NoExpiryNeverRefreshes(t *testing.T) {
	calls := 0
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		calls++
		return &Token{Value: "v"}, nil
	})
	c := Cache(src)
	for range 100 {
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestCache_PropagatesError(t *testing.T) {
	want := errors.New("upstream down")
	c := Cache(TokenSourceFunc(func(_ context.Context) (*Token, error) {
		return nil, want
	}))
	_, err := c.Token(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestCache_DoesNotStoreOnError(t *testing.T) {
	failures := atomic.Int64{}
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		if failures.Add(1) <= 1 {
			return nil, errors.New("transient")
		}
		return &Token{Value: "v", Expires: time.Now().Add(time.Hour)}, nil
	})
	c := Cache(src)
	if _, err := c.Token(context.Background()); err == nil {
		t.Fatal("expected first call to fail")
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatalf("expected second call to succeed: %v", err)
	}
	if tok.Value != "v" {
		t.Fatalf("Value = %q", tok.Value)
	}
}

// TestCache_Stampede verifies that under heavy concurrent load only one
// upstream refresh is issued per refresh window (manual singleflight).
func TestCache_Stampede(t *testing.T) {
	calls := atomic.Int64{}
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		calls.Add(1)
		// Hold the slot long enough for sibling goroutines to pile up.
		time.Sleep(20 * time.Millisecond)
		return &Token{Value: "v", Expires: time.Now().Add(time.Hour)}, nil
	})
	c := Cache(src)

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	start := make(chan struct{})
	for range N {
		go func() {
			defer wg.Done()
			<-start
			if _, err := c.Token(context.Background()); err != nil {
				t.Errorf("Token: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestCache_RespectsContextCancellation(t *testing.T) {
	leaderStarted := make(chan struct{})
	leaderRelease := make(chan struct{})
	src := TokenSourceFunc(func(_ context.Context) (*Token, error) {
		close(leaderStarted)
		<-leaderRelease
		return &Token{Value: "v", Expires: time.Now().Add(time.Hour)}, nil
	})
	c := Cache(src)

	// Leader: a long-running call.
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		if _, err := c.Token(context.Background()); err != nil {
			t.Errorf("leader: %v", err)
		}
	}()
	<-leaderStarted

	// Waiter: a cancelable call that should bail early.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err = %v, want context.Canceled", err)
	}
	close(leaderRelease)
	<-leaderDone
}

// BenchmarkCache_Hit measures the steady-state hit path. Target: 0 alloc.
func BenchmarkCache_Hit(b *testing.B) {
	c := Cache(TokenSourceFunc(func(_ context.Context) (*Token, error) {
		return &Token{Value: "v", Expires: time.Now().Add(time.Hour)}, nil
	}))
	if _, err := c.Token(context.Background()); err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		if _, err := c.Token(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkToken_Apply measures the per-request header attach.
func BenchmarkToken_Apply(b *testing.B) {
	tok := &Token{Value: "supersecrettoken"}
	r := newReq(b, http.MethodGet, "/", http.NoBody)
	b.ReportAllocs()

	for b.Loop() {
		tok.Apply(r)
	}
}

// BenchmarkRoundTripper measures the signing overhead added by the
// RoundTripper wrapper. The base transport is a no-op stub.
func BenchmarkRoundTripper(b *testing.B) {
	stub := &nopTransport{}
	rt := RoundTripper(stub, AsSigner(TokenSourceFunc(func(_ context.Context) (*Token, error) {
		return &Token{Value: "v"}, nil
	})))
	req := newReq(b, http.MethodGet, "https://example.com/", http.NoBody)
	b.ReportAllocs()

	for b.Loop() {
		resp, err := rt.RoundTrip(req)
		if err != nil {
			b.Fatal(err)
		}
		if closeErr := resp.Body.Close(); closeErr != nil {
			b.Fatal(closeErr)
		}
	}
}

// nopTransport returns an empty 204 response without touching the network.
type nopTransport struct{}

func (n *nopTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       http.NoBody,
		Header:     http.Header{},
	}, nil
}
