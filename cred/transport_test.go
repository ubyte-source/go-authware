package cred

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// errTransport is the failure of a base transport.
var errTransport = errors.New("test: transport failed")

const bearerSeq2 = "Bearer t2"

// recorder answers the status that reject maps a token to and 204 otherwise,
// and keeps the Authorization, body and answer of every request.
type recorder struct {
	reject     map[string]int
	auth       []string
	sentBodies []string
	answers    []*closeTracker
	mu         sync.Mutex
}

func (rec *recorder) RoundTrip(r *http.Request) (*http.Response, error) {
	auth := r.Header.Get(authorization)
	var body []byte
	if r.Body != nil {
		var err error
		if body, err = io.ReadAll(r.Body); err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		if err := r.Body.Close(); err != nil {
			return nil, fmt.Errorf("close request body: %w", err)
		}
	}
	status, ok := rec.reject[auth]
	if !ok {
		status = http.StatusNoContent
	}
	respBody := &closeTracker{Reader: strings.NewReader("")}
	rec.mu.Lock()
	rec.auth = append(rec.auth, auth)
	rec.sentBodies = append(rec.sentBodies, string(body))
	rec.answers = append(rec.answers, respBody)
	rec.mu.Unlock()
	return &http.Response{StatusCode: status, Body: respBody, Request: r}, nil
}

func cachedSequence(t *testing.T) (*CachedSource, *sequence) {
	t.Helper()
	src := &sequence{}
	c, err := NewCachedSource(src)
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	return c, src
}

// Literals of the transport tests: what a token round trip allocates, the
// requests denied in a row, the token fetches once the pause ends, the bytes
// drained from a refused answer, a token length and a filler.
const (
	tokenTripAllocs   = 6
	deniedRequests    = 5
	fetchesAfterPause = 3
	drainBytes        = 4 << 10
	tokenLen          = 64
	fillByte          = "x"
	wantAnswer        = "RoundTrip = %v, want an answer"
)

func TestNewTransport(t *testing.T) {
	rec := &recorder{}
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	resp, err := NewTransport(rec, AsSigner(&sequence{})).RoundTrip(r)
	if err != nil {
		t.Fatalf(wantAnswer, err)
	}
	closeResponse(t, resp)
	if rec.auth[0] != bearerSeq1 {
		t.Fatalf("sent Authorization %q, want %q", rec.auth[0], bearerSeq1)
	}
	if r.Header.Get(authorization) != "" {
		t.Fatalf("original Authorization = %q, want none: the transport signs a clone",
			r.Header.Get(authorization))
	}
}

// lastAuth answers 204 and keeps the Authorization of the last request.
type lastAuth struct {
	auth string
	mu   sync.Mutex
}

func (l *lastAuth) RoundTrip(r *http.Request) (*http.Response, error) {
	l.mu.Lock()
	l.auth = r.Header.Get(authorization)
	l.mu.Unlock()
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: r}, nil
}

func TestNewTransportToken(t *testing.T) {
	tok := &Token{Value: secret.New(strings.Repeat("a", tokenLen))}
	base := &lastAuth{}
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	trip := func(rt http.RoundTripper) func() {
		return func() {
			resp, err := rt.RoundTrip(r)
			if err != nil {
				t.Fatalf(wantAnswer, err)
			}
			closeResponse(t, resp)
		}
	}
	rt := NewTransport(base, tok)
	// The token renders its header value once; a generic signer renders it on
	// every request.
	assertAllocs(t, tokenTripAllocs, trip(rt))
	assertAllocs(t, tokenTripAllocs+1, trip(&signedTransport{base: base, signer: tok}))
	want := "Bearer " + tok.Value.Reveal()
	if base.auth != want {
		t.Fatalf("RoundTrip sent %q, want %q", base.auth, want)
	}
	tok.Type, tok.Value = dpop, secret.New(testPayload)
	resp, err := rt.RoundTrip(r)
	if err != nil || base.auth != want {
		t.Fatalf("RoundTrip after an edit of the token = %v, sent %.20q, want the copy NewTransport took", err,
			base.auth)
	}
	closeResponse(t, resp)
}

// TestNewTransportRenewingAllocs signs with the token a cache shares, whose
// header value is rendered once.
func TestNewTransportRenewingAllocs(t *testing.T) {
	tok := &Token{Value: secret.New(strings.Repeat("a", tokenLen)), Expires: time.Now().Add(time.Hour)}
	cached, err := NewCachedSource(TokenSourceFunc(func(context.Context) (*Token, error) { return tok, nil }))
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	base := &lastAuth{}
	rt := NewTransport(base, AsSigner(cached))
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	assertAllocs(t, tokenTripAllocs, func() {
		resp, err := rt.RoundTrip(r)
		if err != nil {
			t.Fatalf(wantAnswer, err)
		}
		closeResponse(t, resp)
	})
	if want := "Bearer " + tok.Value.Reveal(); base.auth != want {
		t.Fatalf("RoundTrip sent %.20q, want %.20q", base.auth, want)
	}
}

func TestNewTransportNilBase(t *testing.T) {
	if rt, ok := NewTransport(nil, AsSigner(&sequence{})).(*signedTransport); !ok || rt.base != http.DefaultTransport {
		t.Fatalf("NewTransport(nil) = %+v, want base http.DefaultTransport", rt)
	}
}

func TestNewTransportSignError(t *testing.T) {
	renewing := func() Signer {
		failing := &sequence{}
		failing.fail(errSource)
		cached, err := NewCachedSource(failing)
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		return AsSigner(cached)
	}
	for kind, signer := range map[string]func() Signer{
		"plain": func() Signer {
			return SignerFunc(func(context.Context,
				*http.Request) error {
				return errSource
			})
		},
		"renewing": renewing,
	} {
		body := &closeTracker{Reader: strings.NewReader(fillByte)}
		for _, r := range []*http.Request{
			newReq(t, http.MethodPost, testAPIURL, body),
			newReq(t, http.MethodGet, testAPIURL, nil),
		} {
			rec := &recorder{}
			resp, err := NewTransport(rec, signer()).RoundTrip(r)
			if resp != nil {
				closeResponse(t, resp)
			}
			if !errors.Is(err, ErrCredential) || !errors.Is(err, errSource) || len(rec.auth) != 0 {
				t.Fatalf("%s %s: err = %v after %d sends, want ErrCredential wrapping errSource and none",
					kind, r.Method, err, len(rec.auth))
			}
		}
		if !body.closed.Load() {
			t.Fatalf("%s: request body closed = false, want true", kind)
		}
	}
}

func TestNewTransportRetriesUnauthorized(t *testing.T) {
	c, src := cachedSequence(t)
	rec := &recorder{reject: map[string]int{bearerSeq1: http.StatusUnauthorized}}
	r := newReq(t, http.MethodPost, testAPIURL, strings.NewReader("payload"))
	resp, err := NewTransport(rec, AsSigner(c)).RoundTrip(r)
	if err != nil {
		t.Fatalf(wantAnswer, err)
	}
	closeResponse(t, resp)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if fmt.Sprint(rec.auth) != "[Bearer t1 Bearer t2]" || fmt.Sprint(rec.sentBodies) != "[payload payload]" {
		t.Fatalf("sent %v with bodies %v, want both tokens, each with the payload", rec.auth, rec.sentBodies)
	}
	if src.calls.Load() != 2 {
		t.Fatalf("source calls = %d, want 2", src.calls.Load())
	}
	if !rec.answers[0].closed.Load() {
		t.Fatal("401 answer body closed = false, want true before the retry")
	}
}

// invalidations is a sequence that records the tokens it is asked to drop.
type invalidations struct {
	sequence

	mu    sync.Mutex
	stale []string
}

func (s *invalidations) Invalidate(stale *Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stale = append(s.stale, stale.Value.Reveal())
}

// TestNewTransportInvalidatesEachRejectedToken asks an Invalidator other than
// a CachedSource to drop the token of every first send a 401 answers, with no
// pause between two of them.
func TestNewTransportInvalidatesEachRejectedToken(t *testing.T) {
	src := &invalidations{}
	const denied, sends = http.StatusUnauthorized, 4
	rec := &recorder{reject: map[string]int{bearerSeq1: denied, bearerSeq2: denied, "Bearer t3": denied,
		"Bearer t4": denied}}
	rt := NewTransport(rec, AsSigner(src))
	for range 2 {
		resp := roundTrip(t, rt, newReq(t, http.MethodGet, testAPIURL, nil))
		closeResponse(t, resp)
		if resp.StatusCode != denied {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	}
	if want := []string{seq1, seq3}; !slices.Equal(src.stale, want) || len(rec.auth) != sends {
		t.Fatalf("invalidated %q after %d sends, want %q after 4: package cred: \"a 401 answer invalidates the "+
			"token it carried\"", src.stale, len(rec.auth), want)
	}
}

// TestNewTransportSignsUnderTheContext signs and sends under the context of
// the request.
func TestNewTransportSignsUnderTheContext(t *testing.T) {
	signed := false
	signer := SignerFunc(func(ctx context.Context, _ *http.Request) error {
		signed = isMarked(ctx)
		return nil
	})
	base := &markedTransport{}
	resp, err := NewTransport(base, signer).RoundTrip(newReq(t, http.MethodGet, testAPIURL, http.NoBody).WithContext(
		marked(t)))
	if err != nil || !signed || base.marked.Load() != 1 {
		t.Fatalf("RoundTrip = %v, signed under the context %t, %d marked sends; want nil, true, 1", err, signed,
			base.marked.Load())
	}
	closeResponse(t, resp)
}

// TestNewTransportRetriesUnderTheContext fetches both tokens and sends both
// requests of a retry after a 401 under the context of the request.
func TestNewTransportRetriesUnderTheContext(t *testing.T) {
	var fetches, sends atomic.Int32
	c, err := NewCachedSource(TokenSourceFunc(func(ctx context.Context) (*Token, error) {
		if !isMarked(ctx) {
			return nil, errSource
		}
		return &Token{Value: secret.New("t" + strconv.Itoa(int(fetches.Add(1))))}, nil
	}))
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	rejecting := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status := http.StatusNoContent
		if r.Header.Get(authorization) == bearerSeq1 {
			status = http.StatusUnauthorized
		}
		if isMarked(r.Context()) {
			sends.Add(1)
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	})
	resp, err := NewTransport(rejecting, AsSigner(c)).RoundTrip(newReq(t, http.MethodGet, testAPIURL,
		http.NoBody).WithContext(marked(t)))
	if err != nil || resp.StatusCode != http.StatusNoContent || fetches.Load() != 2 || sends.Load() != 2 {
		t.Fatalf("RoundTrip after a 401 = %v, %d marked fetches and %d marked sends; want 204, 2 and 2", err,
			fetches.Load(), sends.Load())
	}
	closeResponse(t, resp)
}

func TestNewTransportRetriesOnce(t *testing.T) {
	c, _ := cachedSequence(t)
	rec := &recorder{reject: map[string]int{
		bearerSeq1: http.StatusUnauthorized, bearerSeq2: http.StatusUnauthorized,
	}}
	resp, err := NewTransport(rec, AsSigner(c)).RoundTrip(newReq(t, http.MethodGet, testAPIURL, nil))
	if err != nil {
		t.Fatalf(wantAnswer, err)
	}
	closeResponse(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || len(rec.auth) != 2 {
		t.Fatalf("status %d after %d attempts, want 401 after 2", resp.StatusCode, len(rec.auth))
	}
}

func TestNewTransportNoRetry(t *testing.T) {
	get := func() *http.Request { return newReq(t, http.MethodGet, testAPIURL, nil) }
	unreplayable := func() *http.Request {
		r := newReq(t, http.MethodPost, testAPIURL, strings.NewReader(fillByte))
		r.GetBody = nil
		return r
	}
	failingRewind := func() *http.Request {
		r := newReq(t, http.MethodPost, testAPIURL, strings.NewReader(fillByte))
		r.GetBody = func() (io.ReadCloser, error) { return nil, io.ErrUnexpectedEOF }
		return r
	}
	tests := []struct {
		name    string
		req     func() *http.Request
		status  int
		next    string
		fetches int64
		cached  bool
	}{
		{"no invalidator", get, http.StatusUnauthorized, bearerSeq2, 1, false},
		{"unreplayable body", unreplayable, http.StatusUnauthorized, bearerSeq2, 1, true},
		{"GetBody fails", failingRewind, http.StatusUnauthorized, bearerSeq2, 2, true},
		{"forbidden", get, http.StatusForbidden, bearerSeq1, 1, true},
		{"server error", get, http.StatusInternalServerError, bearerSeq1, 1, true},
	}
	for _, tt := range tests {
		src := &sequence{}
		signer := AsSigner(src)
		if tt.cached {
			c, err := NewCachedSource(src)
			if err != nil {
				t.Fatalf(wantCache, err)
			}
			signer = AsSigner(c)
		}
		rec := &recorder{reject: map[string]int{bearerSeq1: tt.status}}
		rt := NewTransport(rec, signer)
		resp := roundTrip(t, rt, tt.req())
		if rec.answers[0].closed.Load() {
			t.Errorf("%s: answer closed = true, want the answer open for the caller", tt.name)
		}
		closeResponse(t, resp)
		if resp.StatusCode != tt.status || len(rec.auth) != 1 || src.calls.Load() != tt.fetches {
			t.Errorf("%s: status %d after %d attempts and %d token fetches, want %d after 1 and %d",
				tt.name, resp.StatusCode, len(rec.auth), src.calls.Load(), tt.status, tt.fetches)
		}
		if got := sentAuth(t, rt, rec, tt.req()); got != tt.next {
			t.Errorf("%s: next request carried %q, want %q", tt.name, got, tt.next)
		}
	}
}

// sentAuth sends r through rt, which ends in rec, and returns the
// Authorization it carried.
func sentAuth(t *testing.T, rt http.RoundTripper, rec *recorder, r *http.Request) string {
	t.Helper()
	resp, err := rt.RoundTrip(r)
	if err != nil {
		t.Fatalf(wantAnswer, err)
	}
	closeResponse(t, resp)
	return rec.auth[len(rec.auth)-1]
}

// roundTrip sends r through rt and fails the test on an error.
func roundTrip(t *testing.T, rt http.RoundTripper, r *http.Request) *http.Response {
	t.Helper()
	resp, err := rt.RoundTrip(r)
	if err != nil {
		t.Fatalf(wantAnswer, err)
	}
	return resp
}

func TestNewTransportReusesConnection(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(authorization) == bearerSeq1 {
			writeJSON(t, w, http.StatusUnauthorized, `{"error":"invalid_token","error_description":"expired"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	c, _ := cachedSequence(t)
	client := &http.Client{Transport: NewTransport(srv.Client().Transport, AsSigner(c))}
	if err := getStatus(t, client, srv.URL, http.StatusNoContent); err != nil {
		t.Fatalf("GET = %v, want 204", err)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("401 retry opened %d connections, want 1", n)
	}
}

// signers returns a plain and a renewing signer over fresh sequences.
func signers(t *testing.T) map[string]Signer {
	t.Helper()
	c, _ := cachedSequence(t)
	return map[string]Signer{"plain": AsSigner(&sequence{}), "renewing": AsSigner(c)}
}

// redirected builds the request to the last of urls, reached through a
// redirect from each URL before it.
func redirected(tb testing.TB, urls ...string) *http.Request {
	tb.Helper()
	var r *http.Request
	for _, u := range urls {
		next := newReq(tb, http.MethodGet, u, http.NoBody)
		if r != nil {
			next.Response = &http.Response{Body: http.NoBody, Request: r}
		}
		r = next
	}
	return r
}

func TestNewTransportRedirect(t *testing.T) {
	const api, other = "https://api.example/b", "https://other.example/"
	unknown := newReq(t, http.MethodGet, api, http.NoBody)
	unknown.Response = &http.Response{Body: http.NoBody}
	for _, tt := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"first hop", redirected(t, api), bearerSeq1},
		{"same origin", redirected(t, "https://API.example/a", api), bearerSeq1},
		{"same origin twice", redirected(t, "https://api.example/a", "https://api.example:443/c", api), bearerSeq1},
		{"other host", redirected(t, other, api), ""},
		{"other port", redirected(t, "https://api.example:8443/", api), ""},
		{"other scheme", redirected(t, "http://api.example/", api), ""},
		{"back to the origin", redirected(t, "https://api.example/a", other, api), ""},
		{"within another origin", redirected(t, api, other, other+"c"), ""},
		{"unknown origin", unknown, ""},
	} {
		for kind, signer := range signers(t) {
			rec := &recorder{}
			resp, err := NewTransport(rec, signer).RoundTrip(tt.req)
			if err != nil {
				t.Fatalf("%s %s: RoundTrip = %v, want a response", kind, tt.name, err)
			}
			closeResponse(t, resp)
			if fmt.Sprint(rec.auth) != "["+tt.want+"]" {
				t.Errorf("%s %s: sent Authorization %q, want [%s]", kind, tt.name, rec.auth, tt.want)
			}
		}
	}
}

func TestNewTransportBaseError(t *testing.T) {
	failing := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errTransport })
	for kind, signer := range signers(t) {
		resp, err := NewTransport(failing, signer).RoundTrip(newReq(t, http.MethodGet, testAPIURL, nil))
		if resp != nil {
			closeResponse(t, resp)
		}
		if resp != nil || !errors.Is(err, errTransport) || errors.Is(err, ErrCredential) {
			t.Errorf("%s: RoundTrip = %v, %v, want the transport error alone", kind, resp, err)
		}
	}
}

func TestNewTransportRedirectClient(t *testing.T) {
	var seen atomic.Pointer[string]
	var routes atomic.Pointer[map[string]string]
	hop := func(w http.ResponseWriter, r *http.Request) {
		if to, ok := (*routes.Load())[r.Host+r.URL.Path]; ok {
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		auth := r.Header.Get(authorization)
		seen.Store(&auth)
		w.WriteHeader(http.StatusNoContent)
	}
	a, b := serve(t, hop), serve(t, hop)
	hostA, hostB := strings.TrimPrefix(a.URL, "http://"), strings.TrimPrefix(b.URL, "http://")
	routes.Store(&map[string]string{
		hostA + "/in": "/end", hostA + "/to-b": b.URL + "/end", hostA + "/via-b": b.URL + "/hop",
		hostB + "/hop": "/end", hostA + "/back-a": b.URL + "/back", hostB + "/back": a.URL + "/end",
	})
	for _, tt := range []struct {
		name      string
		rawTarget string
		signed    bool
	}{
		{"within the origin", a.URL + "/in", true},
		{"to another origin", a.URL + "/to-b", false},
		{"within another origin", a.URL + "/via-b", false},
		{"back to the origin", a.URL + "/back-a", false},
	} {
		for kind, signer := range signers(t) {
			seen.Store(nil)
			client := &http.Client{Transport: NewTransport(nil, signer)}
			resp, err := client.Do(newReq(t, http.MethodGet, tt.rawTarget, http.NoBody))
			if err != nil {
				t.Fatalf("%s %s: Do = %v, want a response", kind, tt.name, err)
			}
			closeResponse(t, resp)
			switch got := seen.Load(); {
			case got == nil:
				t.Errorf("%s %s: no request reached the last hop, want one", kind, tt.name)
			case (*got != "") != tt.signed:
				t.Errorf("%s %s: last hop saw Authorization %q, want signed %v", kind, tt.name, *got, tt.signed)
			}
		}
	}
}

func TestReplayBody(t *testing.T) {
	withBody := newReq(t, http.MethodPost, testAPIURL, strings.NewReader(testPayload))
	body, ok := replayBody(withBody)
	if !ok || body == withBody.Body {
		t.Fatalf("replayBody = %v, %v, want a fresh copy from GetBody", body, ok)
	}
	if b, err := io.ReadAll(body); err != nil || string(b) != testPayload {
		t.Fatalf("replayed body = %q, %v, want abc", b, err)
	}
	failing := newReq(t, http.MethodPost, testAPIURL, strings.NewReader(testPayload))
	failing.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(testPayload)), io.ErrUnexpectedEOF
	}
	for _, tt := range []struct {
		name string
		req  *http.Request
		want io.ReadCloser
		ok   bool
	}{
		{"nil body", newReq(t, http.MethodGet, testAPIURL, nil), nil, true},
		{"NoBody", newReq(t, http.MethodGet, testAPIURL, http.NoBody), http.NoBody, true},
		{"GetBody fails", failing, nil, false},
	} {
		if body, ok := replayBody(tt.req); ok != tt.ok || body != tt.want {
			t.Errorf("%s: replayBody = %v, %v, want %v and %v", tt.name, body, ok, tt.want, tt.ok)
		}
	}
}

func TestReplayable(t *testing.T) {
	noGetBody := newReq(t, http.MethodPost, testAPIURL, strings.NewReader(testPayload))
	noGetBody.GetBody = nil
	for _, tt := range []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"nil body", newReq(t, http.MethodGet, testAPIURL, nil), true},
		{"NoBody", newReq(t, http.MethodGet, testAPIURL, http.NoBody), true},
		{"GetBody", newReq(t, http.MethodPost, testAPIURL, strings.NewReader(testPayload)), true},
		{"body without GetBody", noGetBody, false},
	} {
		if got := replayable(tt.req); got != tt.want {
			t.Errorf("%s: replayable = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestNewTransportUnauthorizedPaced answers every request 401: within one
// pause only the first 401 fetches another token, so 5 requests cost 2
// fetches, and a later request retries once more.
func TestNewTransportUnauthorizedPaced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &sequence{}
		c, err := NewCachedSource(src)
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		const denied = http.StatusUnauthorized
		rec := &recorder{reject: map[string]int{bearerSeq1: denied, bearerSeq2: denied, "Bearer t3": denied}}
		rt := NewTransport(rec, AsSigner(c))
		for range deniedRequests {
			resp := roundTrip(t, rt, newReq(t, http.MethodGet, testAPIURL, nil))
			closeResponse(t, resp)
			if resp.StatusCode != denied {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			time.Sleep(time.Second)
		}
		if src.calls.Load() != 2 || len(rec.auth) != deniedRequests+1 {
			t.Fatalf("%d token fetches and %d sends, want 2 and 6: one retry within the pause", src.calls.Load(),
				len(rec.auth))
		}
		time.Sleep(pause)
		resp := roundTrip(t, rt, newReq(t, http.MethodGet, testAPIURL, nil))
		closeResponse(t, resp)
		if resp.StatusCode != denied || src.calls.Load() != fetchesAfterPause ||
			fmt.Sprint(rec.auth[deniedRequests+1:]) != "[Bearer t2 Bearer t3]" {
			t.Fatalf("after the pause: %d after %d fetches, sent %v; want 401 after 3 and a retry with t3",
				resp.StatusCode, src.calls.Load(), rec.auth[deniedRequests+1:])
		}
	})
}

// TestNewTransportRefreshFails fails the fetch that follows a 401: the 401 is
// returned unread, without an error, as http.RoundTripper requires.
func TestNewTransportRefreshFails(t *testing.T) {
	c, src := cachedSequence(t)
	rec := &recorder{reject: map[string]int{bearerSeq1: http.StatusUnauthorized}}
	failAfter := func(r *http.Request) (*http.Response, error) {
		resp, err := rec.RoundTrip(r)
		src.fail(errSource)
		return resp, err
	}
	rt := NewTransport(roundTripFunc(failAfter), AsSigner(c))
	resp, err := rt.RoundTrip(newReq(t, http.MethodGet, testAPIURL, nil))
	if err != nil || resp == nil || resp.Body != rec.answers[0] || rec.answers[0].closed.Load() || len(rec.auth) != 1 {
		t.Fatalf("RoundTrip = %v, %v after %d sends; want the open 401 and no error: \"RoundTrip must return "+
			"err == nil if it obtained a response\"", resp, err, len(rec.auth))
	}
	closeResponse(t, resp)
}

// secondCloseFails is a body whose second Close fails, as an os.File's does.
type secondCloseFails struct {
	io.Reader

	closes atomic.Int32
}

func (b *secondCloseFails) Close() error {
	if b.closes.Add(1) > 1 {
		return errStore
	}
	return nil
}

// TestNewTransportSignerConsumesBody signs an oversized body without GetBody:
// the signer reads and closes it, so the error carries no second close.
func TestNewTransportSignerConsumesBody(t *testing.T) {
	signer, err := NewSigV4(&SigV4Config{AccessKey: "a", SecretKey: secret.New("k"), Region: "r", Service: "s"})
	if err != nil {
		t.Fatalf("NewSigV4 = %v, want a signer", err)
	}
	body := &secondCloseFails{Reader: strings.NewReader(strings.Repeat(fillByte, mib+1))}
	r := newReq(t, http.MethodPost, testAPIURL, body)
	r.GetBody, r.ContentLength = nil, -1
	resp, err := NewTransport(&recorder{}, signer).RoundTrip(r)
	if resp != nil {
		closeResponse(t, resp)
	}
	if resp != nil || !errors.Is(err, ErrCredential) || !errors.Is(err, ErrBodyTooLarge) || errors.Is(err, errStore) ||
		body.closes.Load() != 1 {
		t.Fatalf("RoundTrip = %v, %v after %d closes; want ErrCredential wrapping ErrBodyTooLarge alone after 1",
			resp, err, body.closes.Load())
	}
}

// failingCloser is an empty body that fails to close.
type failingCloser struct{}

func (failingCloser) Read([]byte) (int, error) { return 0, io.EOF }

func (failingCloser) Close() error { return errStore }

func TestUnsent(t *testing.T) {
	if err := unsent(errSource, nil); !errors.Is(err, ErrCredential) || !errors.Is(err, errSource) {
		t.Fatalf("unsent without a body = %v, want ErrCredential wrapping errSource", err)
	}
	body := &closeTracker{Reader: strings.NewReader(fillByte)}
	if err := unsent(errSource, body); !body.closed.Load() || !errors.Is(err, ErrCredential) ||
		!errors.Is(err, errSource) || strings.Contains(err.Error(), newline) {
		t.Fatalf("unsent = %v, closed %v, want the credential error alone and a closed body", err, body.closed.Load())
	}
	err := unsent(errSource, failingCloser{})
	if !errors.Is(err, ErrCredential) || !errors.Is(err, errSource) || !errors.Is(err, errStore) {
		t.Fatalf("unsent with a failed close = %v, want both errors", err)
	}
}

func TestDrain(t *testing.T) {
	for size, left := range map[int]int{0: 0, drainBytes: 0, drainBytes + 1: 1} {
		r := strings.NewReader(strings.Repeat(fillByte, size))
		body := &closeTracker{Reader: r}
		drain(body)
		if r.Len() != left || !body.closed.Load() {
			t.Errorf("%d bytes: %d left unread, closed %v, want %d and true", size, r.Len(), body.closed.Load(), left)
		}
	}
}

func ExampleNewTransport() {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	src := TokenSourceFunc(func(context.Context) (*Token, error) {
		return &Token{Value: secret.New(testPayload)}, nil
	})
	client := &http.Client{Transport: NewTransport(nil, AsSigner(src))}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := resp.Body.Close(); err != nil {
		fmt.Println(err)
	}
	// Output: Bearer abc
}

// requireAuth answers 204 to requests whose Authorization is auth, and fails
// the others with errTransport.
func requireAuth(auth string) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get(authorization) != auth {
			return nil, errTransport
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: r}, nil
	})
}

func BenchmarkNewTransport(b *testing.B) {
	// A JWT access token is typically 1 to 2 KiB long.
	tok := &Token{Value: secret.New(strings.Repeat("a", longToken)), Expires: time.Now().Add(time.Hour)}
	cached, err := NewCachedSource(TokenSourceFunc(func(context.Context) (*Token, error) { return tok, nil }))
	if err != nil {
		b.Fatalf(wantCache, err)
	}
	for _, bc := range []struct {
		name   string
		signer Signer
	}{
		{"plain", tok},
		{"renewing", AsSigner(cached)},
	} {
		b.Run(bc.name, func(b *testing.B) {
			benchTransport(b, NewTransport(requireAuth("Bearer "+tok.Value.Reveal()), bc.signer))
		})
	}
}

// benchTransport times concurrent GETs through rt, which fails a request
// that does not carry the expected token, after checking one.
func benchTransport(b *testing.B, rt http.RoundTripper) {
	b.Helper()
	r := newReq(b, http.MethodGet, testAPIURL, http.NoBody)
	if err := tripClosed(rt, r); err != nil {
		b.Fatalf("RoundTrip = %v, want 204 for Bearer and the 1.5 KiB token", err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := tripClosed(rt, r); err != nil {
				b.Errorf(wantAnswer, err)
				return
			}
		}
	})
}

// tripClosed sends r through rt and closes the answer.
func tripClosed(rt http.RoundTripper, r *http.Request) error {
	resp, err := rt.RoundTrip(r)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("close answer: %w", err)
	}
	return nil
}
