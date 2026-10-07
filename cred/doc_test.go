package cred

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// A token longer than a stack buffer, and a token value.
const (
	longToken   = 1536
	testPayload = "abc"
)

// decimalBase is the base of the numbers the reference parsers read.
const decimalBase = 10

// The documented bounds: a body of 1 MiB, the pause of 30s after a failed
// refresh or an invalidation, and the cap of one year on a token lifetime.
const (
	mib         = 1 << 20
	pause       = 30 * time.Second
	maxLifetime = 365 * 24 * time.Hour
)

// newline separates the problems of a joined error.
const newline = "\n"

// authorization is the header a Token sets by default.
const authorization = "Authorization"

// The precision of the reference lifetime, the drift float64 seconds allow
// and a JSON null.
const (
	floatPrecision = 128
	driftNanos     = 8
	jsonNull       = "null"
)

// canonicalEpoch returns raw, a JSON number or string, as positive Unix
// seconds of any size when its text is written the way math/big writes them.
func canonicalEpoch(raw string) (*big.Int, bool) {
	text := raw
	if err := json.Unmarshal([]byte(raw), &text); err != nil {
		text = raw
	}
	n, ok := new(big.Int).SetString(text, decimalBase)
	return n, ok && n.Sign() > 0 && n.String() == text
}

// epochWithin reports whether got is the Unix second n, or the cap of a parse
// between lo and hi when n may lie beyond it.
func epochWithin(n *big.Int, got, lo, hi time.Time) bool {
	capped := !got.Before(lo) && !got.After(hi)
	switch {
	case n.Cmp(big.NewInt(hi.Unix())) > 0:
		return capped
	case n.Cmp(big.NewInt(lo.Unix())) <= 0:
		return got.Equal(time.Unix(n.Int64(), 0))
	}
	return got.Equal(time.Unix(n.Int64(), 0)) || capped
}

// checkExpiry fails unless exp, parsed at before from the epoch text raw, is
// that Unix second, or the cap of one year from the parse.
func checkExpiry(t *testing.T, raw string, exp, before time.Time) {
	t.Helper()
	n, canonical := canonicalEpoch(raw)
	lo, hi := before.Add(maxLifetime), time.Now().Add(maxLifetime)
	if !canonical || !epochWithin(n, exp, lo, hi) {
		t.Fatalf("%s: %v, want the Unix second %v, or a cap between %v and %v", raw, exp, n, lo, hi)
	}
}

// referenceAnswer is a token answer as the reference reads it: the access
// token, its scheme and expires_in, zero when absent or null.
type referenceAnswer struct {
	access   string
	scheme   string
	lifetime time.Duration
}

// readAnswer reads the strict JSON object body with encoding/json; nil unless
// access_token is a header value, token_type empty or a token, refresh_token a
// string and expires_in a positive number.
func readAnswer(body string) *referenceAnswer {
	members, ok := strictMembers(body)
	a := &referenceAnswer{}
	var refresh string
	ok = ok && decodeStrings(members, map[string]*string{"access_token": &a.access, "token_type": &a.scheme,
		"refresh_token": &refresh})
	if raw, set := members["expires_in"]; ok && set && string(raw) != jsonNull {
		a.lifetime, ok = referenceLifetime(raw)
	}
	if !ok || !syntax.IsFieldValue(a.access) || a.scheme != "" && !syntax.IsToken(a.scheme) {
		return nil
	}
	return a
}

// decodeStrings decodes into each destination the member it names, unless
// null or absent, and reports whether every one of them is a string.
func decodeStrings(members map[string]json.RawMessage, dsts map[string]*string) bool {
	for name, dst := range dsts {
		if raw, ok := members[name]; ok && string(raw) != jsonNull && json.Unmarshal(raw, dst) != nil {
			return false
		}
	}
	return true
}

// strictMembers decodes with encoding/json the members of body, false unless
// the strict walker accepts body: a UTF-8 object without a repeated name or
// trailing data, nested at most 32 deep.
func strictMembers(body string) (map[string]json.RawMessage, bool) {
	var members map[string]json.RawMessage
	strict := jsonobj.Iterate(body, ErrInvalidTokenResponse, func(_, _ string) error { return nil }) == nil
	return members, strict && json.Unmarshal([]byte(body), &members) == nil
}

// referenceLifetime reads raw, a JSON number or a string holding one, with
// math/big as seconds clamped to 1ns..1 year; false unless it is positive.
func referenceLifetime(raw json.RawMessage) (time.Duration, bool) {
	text, ok := referenceNumber(raw)
	if !ok {
		return 0, false
	}
	secs, _, err := big.ParseFloat(text, decimalBase, floatPrecision, big.ToNearestEven)
	if err != nil {
		return overflowLifetime(text)
	}
	switch {
	case secs.Sign() <= 0:
		return 0, false
	case secs.Cmp(big.NewFloat(maxLifetime.Seconds())) >= 0:
		return maxLifetime, true
	}
	ns, _ := secs.Mul(secs, big.NewFloat(float64(time.Second))).Int64()
	return max(time.Duration(ns), time.Nanosecond), true
}

// referenceNumber returns the JSON number raw holds, directly or inside a
// JSON string, false when it holds none.
func referenceNumber(raw json.RawMessage) (string, bool) {
	text := string(raw)
	if raw[0] == '"' && json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	return text, text != "" && strings.TrimSpace(text) == text && json.Valid([]byte(text)) &&
		strings.ContainsRune("-0123456789", rune(text[0]))
}

// overflowLifetime reads the JSON number text whose exponent math/big cannot
// hold: a positive one lives 1ns below 1 and 1 year above.
func overflowLifetime(text string) (time.Duration, bool) {
	mantissa, exponent, _ := strings.Cut(strings.ToLower(text), "e")
	switch {
	case strings.Trim(mantissa, "-0.") == "" || mantissa[0] == '-':
		return 0, false
	case strings.HasPrefix(exponent, "-"):
		return time.Nanosecond, true
	}
	return maxLifetime, true
}

// checkToken fails unless tok, accepted from body, is the token that want,
// the reference reading of body, holds.
func checkToken(t *testing.T, body string, tok *Token, want *referenceAnswer) {
	t.Helper()
	if tok.Value.Reveal() != want.access || tok.Type != want.scheme || tok.Header != "" || tok.Bare {
		t.Fatalf("%q accepted as %+v, want the token %q of type %q", body, tok, want.access, want.scheme)
	}
}

// checkRefusal fails unless the reference refused body too, want nil, and the
// parser answered no token and an error wrapping ErrInvalidTokenResponse.
func checkRefusal(t *testing.T, body string, tok *Token, err error, want *referenceAnswer) {
	t.Helper()
	if want != nil || tok != nil || !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("%q: %v, %v; want the reference's reading %+v and a refusal wrapping ErrInvalidTokenResponse",
			body, tok, err, want)
	}
}

// checkLifetime fails unless exp, parsed at before from body, lies lifetime
// after the parse, within the drift of float64 seconds, or is zero without a
// lifetime.
func checkLifetime(t *testing.T, body string, exp time.Time, lifetime time.Duration, before time.Time) {
	t.Helper()
	after := time.Now()
	if lifetime == 0 {
		if !exp.IsZero() {
			t.Fatalf("%q expires %v, want no expiry without expires_in", body, exp)
		}
		return
	}
	if lo, hi := before.Add(lifetime-driftNanos), after.Add(lifetime+driftNanos); exp.Before(lo) || exp.After(hi) {
		t.Fatalf("%q expires %v, want %v after the parse, between %v and %v", body, exp, lifetime, lo, hi)
	}
}

// jsonMember returns the text of the member name of the JSON object doc as
// encoding/json reads it, and whether doc holds it with a value but null.
func jsonMember(doc, name string) (string, bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal([]byte(doc), &members) != nil {
		return "", false
	}
	raw, ok := members[name]
	return string(raw), ok && string(raw) != jsonNull
}

// spacedScheme is a token type that is not a token.
const spacedScheme = "Be arer"

// Leak check of TestMain: the module whose frames mark a goroutine as ours,
// the bytes of every stack it reads, how often it yields to goroutines that
// are ending, and the blank line between two stacks.
const (
	modulePath = "github.com/ubyte-source/go-authware/v2"
	stackBytes = 1 << 20
	leakRounds = 100
	stackGap   = "\n\n"
)

// TestMain runs the tests, then fails the run when a goroutine running code
// of this module outlives them.
func TestMain(m *testing.M) {
	code := m.Run()
	if stray := strayGoroutines(); code == 0 && stray != "" {
		code = 1
		if _, err := fmt.Fprintf(os.Stderr, "goroutines left by the tests:\n%s\n", stray); err != nil {
			code = 2
		}
	}
	os.Exit(code)
}

// strayGoroutines returns the stacks of the goroutines that run code of this
// module once those ending had leakRounds chances to finish, or "".
func strayGoroutines() string {
	stray := moduleStacks()
	for i := 0; i < leakRounds && stray != ""; i++ {
		runtime.Gosched()
		stray = moduleStacks()
	}
	return stray
}

// moduleStacks returns the stacks of the goroutines but the caller's whose
// frames name this module, or "".
func moduleStacks() string {
	buf := make([]byte, stackBytes)
	_, others, _ := strings.Cut(string(buf[:runtime.Stack(buf, true)]), stackGap)
	var ours []string
	for stack := range strings.SplitSeq(others, stackGap) {
		if strings.Contains(stack, modulePath) {
			ours = append(ours, stack)
		}
	}
	return strings.Join(ours, stackGap)
}

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

// testAPIURL is the target of the outbound test requests, and wantCache fails
// a test whose NewCachedSource refused its options.
const (
	testAPIURL = "https://api.example/"
	wantCache  = "NewCachedSource = %v, want a cache"
)

// Times of the credential tests: the default and a custom exchange timeout,
// and a token expiry in seconds.
const (
	wantTimeout   = 10 * time.Second
	customTimeout = 3 * time.Second
	expiresOn     = 1_700_000_000
)

const (
	testClientID = "client-id"
	idpEndpoint  = "https://idp.example/token"
	wantAccess   = "at"
	seq1         = "t1"
	seq3         = "t3"
	bearerSeq1   = "Bearer t1"
	okToken      = `{"access_token":"at","token_type":"Bearer","expires_in":3600}`
	firstRT      = "rt-0"
	// dpop is a scheme other than Bearer, and dpopABC its header of the value abc.
	dpop    = "DPoP"
	dpopABC = dpop + " abc"
	// customHeader is a request header other than Authorization.
	customHeader = "X-Api-Key"
)

// rotatedRT is the refresh token that a rotation of firstRT yields.
const rotatedRT = "rt-1"

var (
	// errSource is the failure of a token source, a signer or a parser.
	errSource = errors.New("test: source failed")
	// errStore is the failure of a refresh token store.
	errStore = errors.New("test: store failed")
)

// nilSource wrongly returns neither a token nor an error.
type nilSource struct{}

func (nilSource) Token(context.Context) (*Token, error) {
	var none *Token
	return none, nil
}

// mustToken returns the value of the next token of src.
func mustToken(t *testing.T, src TokenSource) string {
	t.Helper()
	return nextToken(t, src).Value.Reveal()
}

// nextToken returns the next token of src, failing unless there is one.
func nextToken(t *testing.T, src TokenSource) *Token {
	t.Helper()
	tok, err := src.Token(t.Context())
	if err != nil || tok == nil {
		t.Fatalf("Token() = %v, %v, want a token", tok, err)
	}
	return tok
}

// closeTracker records whether it was closed.
type closeTracker struct {
	io.Reader

	closed atomic.Bool
}

func (c *closeTracker) Close() error {
	c.closed.Store(true)
	return nil
}

// newReq builds an outbound request bound to the test context.
func newReq(tb testing.TB, method, target string, body io.Reader) *http.Request {
	tb.Helper()
	r, err := http.NewRequestWithContext(tb.Context(), method, target, body)
	if err != nil {
		tb.Fatalf("NewRequestWithContext = %v, want a request", err)
	}
	return r
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// writeJSON answers with status and a JSON body.
func writeJSON(tb testing.TB, w http.ResponseWriter, status int, body string) {
	tb.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := io.WriteString(w, body); err != nil {
		tb.Errorf("WriteString = %v, want the body written", err)
	}
}

// hugeAnswer starts a server answering status and a body over 1 MiB in 4 KiB
// writes, which end once the client hangs up.
func hugeAnswer(tb testing.TB, status int) *httptest.Server {
	tb.Helper()
	chunk := strings.Repeat("x", 4<<10)
	return serve(tb, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		for range mib/len(chunk) + 1 {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	})
}

// serve starts a test server for h and closes it with the test.
func serve(tb testing.TB, h http.HandlerFunc) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(h)
	tb.Cleanup(srv.Close)
	return srv
}

// sequence is a TokenSource yielding t1, t2, ... that expire ttl after they
// are issued; a zero ttl yields tokens without expiry.
type sequence struct {
	ttl   time.Duration
	err   atomic.Pointer[error]
	calls atomic.Int64
}

func (s *sequence) Token(context.Context) (*Token, error) {
	n := s.calls.Add(1)
	if err := s.err.Load(); err != nil {
		return nil, *err
	}
	tok := &Token{Value: secret.New("t" + strconv.FormatInt(n, decimalBase))}
	if s.ttl > 0 {
		tok.Expires = time.Now().Add(s.ttl)
	}
	return tok, nil
}

// fail makes every later call return err; nil restores success.
func (s *sequence) fail(err error) {
	if err == nil {
		s.err.Store(nil)
		return
	}
	s.err.Store(&err)
}

// captured is one request seen by a recording server.
type captured struct {
	method        string
	path          string
	query         url.Values
	requestHeader http.Header
	form          url.Values
}

// recording is a test server that records requests and answers through
// respond.
type recording struct {
	srv     *httptest.Server
	respond func(c captured) (int, string)
	mu      sync.Mutex
	seen    []captured
}

func newRecording(t *testing.T, respond func(c captured) (int, string)) *recording {
	t.Helper()
	rec := &recording{respond: respond}
	rec.srv = serve(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm = %v, want a form", err)
		}
		c := captured{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.Query(), requestHeader: r.Header,
			form: r.PostForm}
		rec.mu.Lock()
		rec.seen = append(rec.seen, c)
		rec.mu.Unlock()
		status, body := rec.respond(c)
		writeJSON(t, w, status, body)
	})
	return rec
}

// requests returns a copy of the requests seen so far.
func (rec *recording) requests() []captured {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]captured(nil), rec.seen...)
}

// answer returns a respond function with a fixed status and body.
func answer(status int, body string) func(captured) (int, string) {
	return func(captured) (int, string) { return status, body }
}

func closeResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if err := resp.Body.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

// rotatingServer issues rt-(n+1) for rt-n and fails on any reuse.
func rotatingServer(t *testing.T) *recording {
	t.Helper()
	var mu sync.Mutex
	used := map[string]bool{}
	next := 1
	return newRecording(t, func(c captured) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		rt := c.form.Get("refresh_token")
		if used[rt] || rt != "rt-"+strconv.Itoa(next-1) {
			t.Errorf("refresh token = %q, want rt-%d, each presented once", rt, next-1)
			return http.StatusBadRequest, `{"error":"invalid_grant"}`
		}
		used[rt] = true
		n := strconv.Itoa(next)
		next++
		return http.StatusOK, `{"access_token":"at-` + n + `","refresh_token":"rt-` + n + `","expires_in":60}`
	})
}

// fakeStore records saved tokens and can fail Load or Save.
type fakeStore struct {
	initial string
	loadErr error
	saveErr error
	saved   chan string
	loads   atomic.Int32
}

func (s *fakeStore) Load(context.Context) (secret.Value, error) {
	s.loads.Add(1)
	return secret.New(s.initial), s.loadErr
}

func (s *fakeStore) Save(_ context.Context, v secret.Value) error {
	s.saved <- v.Reveal()
	return s.saveErr
}

func newRefresh(t *testing.T, client *http.Client, tokenURL string, st RefreshTokenStore) TokenSource {
	t.Helper()
	src, err := NewRefreshToken(&ClientConfig{
		HTTPClient: client, TokenURL: tokenURL, ClientID: testClientID,
	}, st)
	if err != nil {
		t.Fatalf("NewRefreshToken = %v, want a source", err)
	}
	return src
}

// tokenWithError yields t1, t2, ... together with err and counts its calls.
func tokenWithError(calls *atomic.Int32, err error) TokenSource {
	return TokenSourceFunc(func(context.Context) (*Token, error) {
		return &Token{Value: secret.New("t" + strconv.Itoa(int(calls.Add(1))))}, err
	})
}

// drained closes saved and returns what it held.
func drained(saved chan string) []string {
	close(saved)
	var out []string
	for s := range saved {
		out = append(out, s)
	}
	return out
}

// getStatus sends a GET of target through client and requires status when
// the request succeeds.
func getStatus(t *testing.T, client *http.Client, target string, status int) error {
	t.Helper()
	resp, err := client.Do(newReq(t, http.MethodGet, target, http.NoBody))
	if err != nil {
		return fmt.Errorf("get %s: %w", target, err)
	}
	closeResponse(t, resp)
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d", resp.StatusCode, status)
	}
	return nil
}

// ctxKey keys the mark that a test puts on the context it passes.
type ctxKey struct{}

// mark is the value of the mark.
const mark = "marked"

// marked returns the context of tb carrying the mark.
func marked(tb testing.TB) context.Context {
	tb.Helper()
	return context.WithValue(tb.Context(), ctxKey{}, mark)
}

// isMarked reports whether ctx carries the mark.
func isMarked(ctx context.Context) bool {
	return ctx != nil && ctx.Value(ctxKey{}) == mark
}

// markedTransport answers every request with the token okToken, counting the
// requests whose context carries the mark.
type markedTransport struct {
	marked, requests atomic.Int32
}

func (m *markedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m.requests.Add(1)
	if isMarked(r.Context()) {
		m.marked.Add(1)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
		Body: io.NopCloser(strings.NewReader(okToken))}, nil
}

// markHandler is a slog.Handler that counts the records logged under a marked
// context.
type markHandler struct {
	marked *atomic.Int32
}

func (markHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle counts a record logged under a marked context.
//
//nolint:gocritic // hugeParam: slog.Handler requires the Record by value.
func (h markHandler) Handle(ctx context.Context, _ slog.Record) error {
	if isMarked(ctx) {
		h.marked.Add(1)
	}
	return nil
}

func (h markHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h markHandler) WithGroup(string) slog.Handler { return h }

// pauseAfter runs load on a goroutine of its own and returns, once load has
// returned, a resume function that lets the goroutine pass the result to
// finish and returns what finish returns.
func pauseAfter[L, R any](load func() L, finish func(L) R) (resume func() R) {
	loaded, release, done := make(chan struct{}), make(chan struct{}), make(chan R, 1)
	go func() {
		l := load()
		close(loaded)
		<-release
		done <- finish(l)
	}()
	<-loaded
	return func() R {
		close(release)
		return <-done
	}
}
