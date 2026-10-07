package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

const storeCapacity = 16

// unauthorizedBody is the fixed body of a 401 from Verifier.Middleware.
const unauthorizedBody = "unauthorized\n"

// errStoreDown is a nonce store failure whose text must not reach clients.
var errStoreDown = errors.New("dial tcp 10.0.0.5:6379: connect: connection refused")

// stubStore answers Seen with fixed results and counts the calls.
type stubStore struct {
	calls atomic.Int64
	err   error
	fresh bool
}

func (s *stubStore) Seen(context.Context, string, time.Time) (bool, error) {
	s.calls.Add(1)
	return s.fresh, s.err
}

// ctxKey keys the value that marks the context a test passes.
type ctxKey struct{}

// ctxStore finds every nonce fresh and records the mark on the context of its
// last call.
type ctxStore struct {
	got any
}

func (s *ctxStore) Seen(ctx context.Context, _ string, _ time.Time) (bool, error) {
	s.got = ctx.Value(ctxKey{})
	return true, nil
}

var (
	canonicalDecimal = regexp.MustCompile(`^(0|[1-9]\d*)$`)
	lowerHex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// The documented forms of the envelope: a decimal timestamp, a nonce of 16 random
// bytes and a signature of 64 hex digits.
const (
	decimal      = 10
	nonceSize    = 16
	sigHexDigits = 64
)

// referenceEnvelope applies the header rules of Verify independently of
// the production code and returns the values in envelopeNames order.
func referenceEnvelope(h http.Header) ([envelopeHeaders]string, error) {
	var values [envelopeHeaders]string
	for _, name := range envelopeNames() {
		if len(h.Values(name)) == 0 {
			return [envelopeHeaders]string{}, ErrMissingHeaders
		}
	}
	for i, name := range envelopeNames() {
		if len(h.Values(name)) != 1 {
			return [envelopeHeaders]string{}, ErrMalformedHeaders
		}
		values[i] = h.Get(name)
	}
	unix, ok := new(big.Int).SetString(values[0], decimal)
	if !canonicalDecimal.MatchString(values[0]) || !ok || !unix.IsInt64() ||
		!lowerHex32.MatchString(values[1]) || !lowerHex64.MatchString(values[2]) {
		return [envelopeHeaders]string{}, ErrMalformedHeaders
	}
	return values, nil
}

// referenceVerify decides the outcome of a first Verify at now with the
// default window, independently of the production code.
func referenceVerify(now time.Time, r *http.Request, body []byte) error {
	values, err := referenceEnvelope(r.Header)
	if err != nil {
		return err
	}
	ts, nonce, sig := values[0], values[1], values[2]
	unix, _ := new(big.Int).SetString(ts, decimal)
	skew := new(big.Int).Sub(big.NewInt(now.Unix()), unix)
	if skew.CmpAbs(big.NewInt(windowSeconds)) > 0 {
		return ErrTimestampSkew
	}
	if len(body) > mib {
		return ErrInvalidBody
	}
	if referenceSignature(r, body, ts, nonce) != sig {
		return ErrInvalidSignature
	}
	return nil
}

// resign gives r, which a Signer signed over body, the timestamp unix and the
// reference signature of it.
func resign(r *http.Request, body []byte, unix int64) {
	ts := strconv.FormatInt(unix, decimal)
	r.Header.Set(HeaderTimestamp, ts)
	r.Header.Set(HeaderSignature, referenceSignature(r, body, ts, r.Header.Get(HeaderNonce)))
}

// flipByte xors the byte of s at pos (modulo its length) with x.
func flipByte(s string, pos uint16, x byte) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	b[int(pos)%len(b)] ^= x
	return string(b)
}

// The parts of a signed request that mutateRequest changes, by fuzzed field.
const (
	keepRequest = iota
	flipMethod
	flipHost
	flipPath
	flipQuery
	flipBody
	flipTimestamp
	flipNonce
	flipSignature
	setEnvelope
	dropEnvelope
	repeatEnvelope
	requestMutations
)

// mutateRequest changes one part of a signed request as the fuzzer selects
// and returns the body to send.
func mutateRequest(r *http.Request, body []byte, field uint8, pos uint16, flip byte, raw string) []byte {
	names := envelopeNames()
	name := names[int(pos)%len(names)]
	switch field % requestMutations {
	case flipMethod:
		r.Method = flipByte(r.Method, pos, flip)
	case flipHost:
		r.Host = flipByte(r.Host, pos, flip)
	case flipPath:
		r.URL.Path = flipByte(r.URL.Path, pos, flip)
	case flipQuery:
		r.URL.RawQuery = flipByte(r.URL.RawQuery, pos, flip)
	case flipBody:
		body = []byte(flipByte(string(body), pos, flip))
	case flipTimestamp, flipNonce, flipSignature:
		name = names[field%requestMutations-flipTimestamp]
		r.Header.Set(name, flipByte(r.Header.Get(name), pos, flip))
	case setEnvelope:
		r.Header.Set(name, raw)
	case dropEnvelope:
		r.Header.Del(name)
	case repeatEnvelope:
		r.Header.Add(name, raw)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body
}

// tweakHex changes digit i of the hex string s to another hex digit.
func tweakHex(s string, i int) string {
	d := byte('0')
	if s[i] == '0' {
		d = '1'
	}
	return s[:i] + string(d) + s[i+1:]
}

func TestNewVerifier(t *testing.T) {
	t.Parallel()
	store, err := NewMemoryStore(1)
	if err != nil {
		t.Fatalf("NewMemoryStore = %v, want a store", err)
	}
	if _, err = NewVerifier(testKey(), nil); !errors.Is(err, ErrInvalidConfig) || !errors.Is(err, errNilStore) {
		t.Fatalf("nil store: err = %v, want errNilStore under ErrInvalidConfig", err)
	}
	if _, err = NewVerifier(secret.New(testKeyRaw[1:]), store); !errors.Is(err, ErrShortKey) {
		t.Fatalf("short key: err = %v, want ErrShortKey", err)
	}
	if _, err = NewVerifier(testKey(), store, WithWindow(2*time.Hour)); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad window: err = %v, want ErrInvalidOption", err)
	}
	if v, err := NewVerifier(testKey(), store); err != nil || v.window != windowSeconds*time.Second {
		t.Fatalf("NewVerifier = %v, %v, want a verifier of the default window", v, err)
	}
}

func TestVerifierVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	for _, target := range []string{testURL, "https://api.example/a%2Fb?x=1&y=%20"} {
		for _, body := range []string{"", `{"a":1}`} {
			r := signedRequest(t, s, http.MethodPost, target, body)
			if err := v.Verify(t.Context(), r); err != nil {
				t.Fatalf("Verify(%s %q) = %v, want nil", target, body, err)
			}
			if body == "" {
				continue
			}
			if b, err := io.ReadAll(r.Body); err != nil || string(b) != body {
				t.Fatalf("body after Verify = %q, %v, want %q", b, err, body)
			}
		}
	}
}

func TestVerifierVerifyReplay(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	r := signedRequest(t, s, http.MethodGet, testURL, "")
	if err := v.Verify(t.Context(), r); err != nil {
		t.Fatalf("Verify = %v, want nil", err)
	}
	if err := v.Verify(t.Context(), r); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("replay: err = %v, want ErrNonceReplayed", err)
	}
}

// tamperCases returns one edit per signed input of a request, each breaking
// its signature.
func tamperCases() map[string]func(r *http.Request) {
	otherNonce := strings.Repeat("ab", nonceSize)
	cases := map[string]func(r *http.Request){
		"method": func(r *http.Request) { r.Method = http.MethodDelete },
		"host":   func(r *http.Request) { r.Host = "evil.example" },
		"port":   func(r *http.Request) { r.Host = "api.example:444" },
		"path":   func(r *http.Request) { r.URL.Path = "/admin" },
		"escape": func(r *http.Request) { r.URL.RawPath = "/items%2Fx" },
		"query":  func(r *http.Request) { r.URL.RawQuery = "id=2&all=true" },
		"body":   func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"id":2}`)) },
		"nobody": func(r *http.Request) { r.Body = http.NoBody },
		"ts+1":   func(r *http.Request) { r.Header.Set(HeaderTimestamp, strconv.Itoa(testUnix+1)) },
		"ts-1":   func(r *http.Request) { r.Header.Set(HeaderTimestamp, strconv.Itoa(testUnix-1)) },
		"nonce":  func(r *http.Request) { r.Header.Set(HeaderNonce, otherNonce) },
	}
	for i := range sigHexDigits {
		cases["sig"+strconv.Itoa(i)] = func(r *http.Request) {
			r.Header.Set(HeaderSignature, tweakHex(r.Header.Get(HeaderSignature), i))
		}
	}
	return cases
}

func TestVerifierVerifyTamper(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s, v := newTestSigner(t), newTestVerifier(t)
		for name, tamper := range tamperCases() {
			r := signedRequest(t, s, http.MethodPost, "https://api.example/items/x?id=1", `{"id":1}`)
			tamper(r)
			if err := v.Verify(t.Context(), r); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("%s: err = %v, want ErrInvalidSignature", name, err)
			}
		}
		r := signedRequest(t, s, http.MethodGet, "https://api.example/items", "")
		r.Host = "API.EXAMPLE"
		if err := v.Verify(t.Context(), r); err != nil {
			t.Fatalf("Verify(upper-case host) = %v, want nil", err)
		}
	})
}

func TestVerifierVerifyForgedThenLegit(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	legit := signedRequest(t, s, http.MethodGet, testURL, "")
	forged := legit.Clone(t.Context())
	forged.Header.Set(HeaderSignature, tweakHex(legit.Header.Get(HeaderSignature), 0))
	if err := v.Verify(t.Context(), forged); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("forged: err = %v, want ErrInvalidSignature", err)
	}
	if err := v.Verify(t.Context(), legit); err != nil {
		t.Fatalf("Verify(legit after forged) = %v, want nil", err)
	}
}

func TestVerifierVerifyStoreAfterMAC(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	store := &stubStore{fresh: true}
	v, err := NewVerifier(testKey(), store)
	if err != nil {
		t.Fatalf(wantVerifier, err)
	}
	bad := signedRequest(t, s, http.MethodGet, testURL, "")
	bad.Header.Set(HeaderSignature, tweakHex(bad.Header.Get(HeaderSignature), 0))
	stale := signedRequest(t, s, http.MethodGet, testURL, "")
	stale.Header.Set(HeaderTimestamp, "1")
	for name, tc := range map[string]struct {
		req     *http.Request
		wantErr error
	}{
		"bad signature":   {bad, ErrInvalidSignature},
		"stale timestamp": {stale, ErrTimestampSkew},
		"no headers":      {newRequest(t, http.MethodGet, testURL, ""), ErrMissingHeaders},
	} {
		if err = v.Verify(t.Context(), tc.req); !errors.Is(err, tc.wantErr) || store.calls.Load() != 0 {
			t.Fatalf("%s: err = %v, store calls %d; want %v, 0", name, err, store.calls.Load(), tc.wantErr)
		}
	}
	if err = v.Verify(t.Context(), signedRequest(t, s, http.MethodGet, testURL, "")); err != nil {
		t.Fatalf("Verify(valid) = %v, want nil", err)
	}
	if store.calls.Load() != 1 {
		t.Fatalf("store calls = %d, want 1", store.calls.Load())
	}
}

func TestVerifierVerifyStoreErrors(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	for _, store := range []*stubStore{{err: errBoom}, {fresh: false}} {
		v, err := NewVerifier(testKey(), store)
		if err != nil {
			t.Fatalf(wantVerifier, err)
		}
		err = v.Verify(t.Context(), signedRequest(t, s, http.MethodGet, testURL, ""))
		switch {
		case store.err != nil && (!errors.Is(err, errBoom) || errors.Is(err, ErrRejected)):
			t.Fatalf("store error: err = %v, want the store error, not a rejection", err)
		case store.err == nil && !errors.Is(err, ErrNonceReplayed):
			t.Fatalf("stale nonce: err = %v, want ErrNonceReplayed", err)
		}
	}
}

func TestVerifierVerifyConcurrentSameNonce(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	r := signedRequest(t, s, http.MethodGet, testURL, "")
	const n = 64
	errs := make(chan error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			<-start
			errs <- v.Verify(t.Context(), r.Clone(t.Context()))
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	accepted := 0
	for err := range errs {
		switch {
		case err == nil:
			accepted++
		case !errors.Is(err, ErrNonceReplayed):
			t.Fatalf("err = %v, want ErrNonceReplayed", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d copies of one request, want 1", accepted)
	}
}

// TestVerifierVerifyRetention keeps the nonce of a request signed one window ahead
// live up to its last admitted nanosecond, T+2w+1s-1ns, and frees its place in a
// store of one at T+2w+1s, when a fresh request takes it.
func TestVerifierVerifyRetention(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const w = time.Minute
		s := newTestSigner(t)
		v, err := NewVerifier(testKey(), newTestStore(t, 1), WithWindow(w))
		if err != nil {
			t.Fatalf(wantVerifier, err)
		}
		r := signedRequest(t, s, http.MethodGet, testURL, "")
		resign(r, nil, testUnix+int64(w/time.Second))
		if err = v.Verify(t.Context(), r); err != nil {
			t.Fatalf("Verify(clock ahead by the window) = %v, want nil", err)
		}
		for _, at := range []time.Duration{w, 2 * w, 2*w + time.Second - time.Nanosecond} {
			time.Sleep(time.Until(time.Unix(testUnix, 0).Add(at)))
			if err = v.Verify(t.Context(), r); !errors.Is(err, ErrNonceReplayed) {
				t.Fatalf("replay at T+%v: err = %v, want ErrNonceReplayed", at, err)
			}
		}
		time.Sleep(time.Until(time.Unix(testUnix, 0).Add(2*w + time.Second)))
		if err = v.Verify(t.Context(), r); !errors.Is(err, ErrTimestampSkew) {
			t.Fatalf("replay at T+2w+1s: err = %v, want ErrTimestampSkew", err)
		}
		if err = v.Verify(t.Context(), signedRequest(t, s, http.MethodGet, testURL, "")); err != nil {
			t.Fatalf("README: \"twice the window plus one second, the longest a nonce stays live\": fresh "+
				"request at T+2w+1s with a store of one: Verify = %v, want nil", err)
		}
	})
}

// stall is an empty reader that calls its function before it ends: ahead of a
// body in an io.MultiReader, it holds the body back as a slow client does.
type stall func()

func (f stall) Read([]byte) (int, error) {
	f()
	return 0, io.EOF
}

// lateClone returns a copy of r whose body, oneByte, comes once wait returns.
func lateClone(t *testing.T, r *http.Request, wait func()) *http.Request {
	t.Helper()
	c := r.Clone(t.Context())
	c.Body = io.NopCloser(io.MultiReader(stall(wait), strings.NewReader(oneByte)))
	return c
}

const lateWindow = time.Minute

// lateReplayAt is half a second before the record of a nonce signed at testUnix,
// kept until ts+lateWindow+1s, expires.
func lateReplayAt() time.Time { return time.Unix(testUnix, 0).Add(lateWindow + time.Second/2) }

// TestVerifierVerifyReplayWithLateBody replays a verified request half a second
// before its nonce's record expires, its body completing before the expiry and
// after it: the store refuses the first, the window checked again the second.
func TestVerifierVerifyReplayWithLateBody(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s, v := newTestSigner(t), newTestVerifier(t, WithWindow(lateWindow))
		r := signedRequest(t, s, http.MethodPost, testURL, oneByte)
		if err := v.Verify(t.Context(), lateClone(t, r, func() {})); err != nil {
			t.Fatalf("Verify = %v, want nil", err)
		}
		time.Sleep(time.Until(lateReplayAt()))
		for _, tc := range []struct {
			delay   time.Duration
			wantErr error
		}{{2 * time.Second / 5, ErrNonceReplayed}, {time.Second, ErrTimestampSkew}} {
			late := lateClone(t, r, func() { time.Sleep(tc.delay) })
			if err := v.Verify(t.Context(), late); !errors.Is(err, tc.wantErr) {
				t.Errorf("Verify godoc: \"records the nonce and checks the window again\"; ErrTimestampSkew "+
					"godoc: \"reports a timestamp outside the window\": replay whose body completes %v later: "+
					"Verify = %v, want %v", tc.delay, err, tc.wantErr)
			}
		}
	})
}

// TestVerifierMiddlewareReplayWithLateBody replays a served request half a second
// before its nonce's record expires, its body completing after the expiry.
func TestVerifierMiddlewareReplayWithLateBody(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s, v := newTestSigner(t), newTestVerifier(t, WithWindow(lateWindow))
		served := 0
		h := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served++ }))
		r := signedRequest(t, s, http.MethodPost, testURL, oneByte)
		h.ServeHTTP(httptest.NewRecorder(), lateClone(t, r, func() {}))
		time.Sleep(time.Until(lateReplayAt()))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, lateClone(t, r, func() { time.Sleep(time.Second) }))
		if rec.Code != http.StatusUnauthorized || served != 1 {
			t.Fatalf("Middleware godoc: \"passes next each request v verifies ...; it answers a rejected request "+
				"401\": replay whose body completes after its nonce's record expires: %d, next served %d "+
				"times; want 401, once", rec.Code, served)
		}
	})
}

// shortWindow is a window shorter than the default.
const shortWindow = 10 * time.Second

func TestVerifierVerifyWindow(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := newTestSigner(t)
		for _, tc := range []struct {
			opts   []VerifierOption
			window time.Duration
		}{{nil, windowSeconds * time.Second}, {[]VerifierOption{WithWindow(shortWindow)}, shortWindow}} {
			secs := int64(tc.window / time.Second)
			for _, offset := range []int64{-secs, secs, -secs - 1, secs + 1} {
				r := signedRequest(t, s, http.MethodGet, testURL, "")
				resign(r, nil, testUnix+offset)
				err := newTestVerifier(t, tc.opts...).Verify(t.Context(), r)
				inside := offset >= -secs && offset <= secs
				if (inside && err != nil) || (!inside && !errors.Is(err, ErrTimestampSkew)) {
					t.Errorf("window %ds, offset %ds: Verify = %v, want an error exactly outside the window",
						secs, offset, err)
				}
			}
		}
	})
}

func TestReadEnvelope(t *testing.T) {
	t.Parallel()
	ts, nonce, sig := strconv.Itoa(testUnix), strings.Repeat("0a", nonceSize), strings.Repeat("f1", sha256.Size)
	valid := func() http.Header {
		return http.Header{HeaderTimestamp: {ts}, HeaderNonce: {nonce}, HeaderSignature: {sig}}
	}
	env, err := readEnvelope(valid())
	if err != nil || env != (envelope{nonce: nonce, signature: sig, unix: testUnix}) {
		t.Fatalf("readEnvelope = %+v, %v, want the three values", env, err)
	}
	cases := map[string]struct {
		edit    func(h http.Header)
		wantErr error
	}{
		"no timestamp":     {func(h http.Header) { h.Del(HeaderTimestamp) }, ErrMissingHeaders},
		"no nonce":         {func(h http.Header) { h.Del(HeaderNonce) }, ErrMissingHeaders},
		"no signature":     {func(h http.Header) { h.Del(HeaderSignature) }, ErrMissingHeaders},
		"empty list":       {func(h http.Header) { h[HeaderNonce] = []string{} }, ErrMissingHeaders},
		"two timestamps":   {func(h http.Header) { h.Add(HeaderTimestamp, ts) }, ErrMalformedHeaders},
		"two nonces":       {func(h http.Header) { h.Add(HeaderNonce, nonce) }, ErrMalformedHeaders},
		"two signatures":   {func(h http.Header) { h.Add(HeaderSignature, sig) }, ErrMalformedHeaders},
		"plus timestamp":   {func(h http.Header) { h.Set(HeaderTimestamp, "+"+ts) }, ErrMalformedHeaders},
		"zero-padded ts":   {func(h http.Header) { h.Set(HeaderTimestamp, "0"+ts) }, ErrMalformedHeaders},
		"empty timestamp":  {func(h http.Header) { h.Set(HeaderTimestamp, "") }, ErrMalformedHeaders},
		"upper nonce":      {func(h http.Header) { h.Set(HeaderNonce, strings.ToUpper(nonce)) }, ErrMalformedHeaders},
		"short nonce":      {func(h http.Header) { h.Set(HeaderNonce, nonce[2:]) }, ErrMalformedHeaders},
		"long nonce":       {func(h http.Header) { h.Set(HeaderNonce, nonce+"00") }, ErrMalformedHeaders},
		"non-hex nonce":    {func(h http.Header) { h.Set(HeaderNonce, "g"+nonce[1:]) }, ErrMalformedHeaders},
		"upper signature":  {func(h http.Header) { h.Set(HeaderSignature, strings.ToUpper(sig)) }, ErrMalformedHeaders},
		"short signature":  {func(h http.Header) { h.Set(HeaderSignature, sig[1:]) }, ErrMalformedHeaders},
		"non-hex sig tail": {func(h http.Header) { h.Set(HeaderSignature, sig[:63]+"/") }, ErrMalformedHeaders},
	}
	for name, tc := range cases {
		h := valid()
		tc.edit(h)
		if _, err := readEnvelope(h); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.wantErr)
		}
	}
}

func TestParseTimestamp(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]int64{
		"0": 0, "2": 2, strconv.Itoa(testUnix): testUnix, "9223372036854775807": math.MaxInt64,
	} {
		if got, ok := parseTimestamp(s); !ok || got != want {
			t.Errorf("parseTimestamp(%q) = %d, %t, want %d, true", s, got, ok, want)
		}
	}
	for _, s := range []string{
		"", "+1", "-1", "-0", "00", "01700000000", " 1", "1 ", "1e3", "0x10",
		"9223372036854775808", "-9223372036854775808",
	} {
		if _, ok := parseTimestamp(s); ok {
			t.Errorf("parseTimestamp(%q) ok = true, want false", s)
		}
	}
}

// sampleHexLen is the length of the strings TestIsLowerHex checks.
const sampleHexLen = 16

func TestIsLowerHex(t *testing.T) {
	t.Parallel()
	if !isLowerHex("0123456789abcdef", sampleHexLen) {
		t.Fatal("isLowerHex(0123456789abcdef, 16) = false, want true")
	}
	for _, s := range []string{
		"0123456789abcdeF", "0123456789abcde", "0123456789abcdefa",
		"0123456789abcde:", "0123456789abcde`", "0123456789abcdeg",
	} {
		if isLowerHex(s, sampleHexLen) {
			t.Errorf("isLowerHex(%q, 16) = true, want false", s)
		}
	}
}

func TestWithinWindow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		now, ts, bound int64
		want           bool
	}{
		{testUnix, testUnix, 0, true},
		{testUnix, testUnix + 1, 1, true},
		{testUnix + 1, testUnix, 1, true},
		{testUnix, testUnix + 2, 1, false},
		{testUnix + 2, testUnix, 1, false},
		{testUnix, math.MinInt64 + testUnix, windowSeconds, false},
		{math.MinInt64 + testUnix, testUnix, windowSeconds, false},
		{0, math.MaxInt64, windowSeconds, false},
		{math.MinInt64, -1, math.MaxInt64, true},
		{math.MinInt64, 0, math.MaxInt64, false},
		{math.MinInt64, math.MaxInt64, math.MaxInt64, false},
	} {
		if got := withinWindow(tc.now, tc.ts, tc.bound); got != tc.want {
			t.Errorf("withinWindow(%d, %d, %d) = %t, want %t", tc.now, tc.ts, tc.bound, got, tc.want)
		}
	}
}

func TestBodyDigest(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	atLimit := strings.Repeat("a", mib)
	r := signedRequest(t, s, http.MethodPost, testURL, atLimit)
	if err := v.Verify(t.Context(), r); err != nil {
		t.Fatalf("Verify(body at the limit) = %v, want nil", err)
	}
	if restored, err := io.ReadAll(r.Body); err != nil || string(restored) != atLimit {
		t.Fatalf("restored body of %d bytes, %v, want the %d bytes read", len(restored), err, len(atLimit))
	}
	over := signedRequest(t, s, http.MethodPost, testURL, oneByte)
	over.Body = io.NopCloser(strings.NewReader(atLimit + "a"))
	if err := v.Verify(t.Context(), over); !errors.Is(err, ErrInvalidBody) || !errors.Is(err, errBodyOverLimit) {
		t.Fatalf("body over the limit: err = %v, want errBodyOverLimit, built once under ErrInvalidBody", err)
	}
	broken := signedRequest(t, s, http.MethodPost, testURL, oneByte)
	broken.Body = errBody{}
	if err := v.Verify(t.Context(), broken); !errors.Is(err, ErrInvalidBody) || !errors.Is(err, errBoom) {
		t.Fatalf("unreadable body: err = %v, want ErrInvalidBody wrapping errBoom", err)
	}
}

// echoBody is the body echoX expects.
const echoBody = "x"

// echoX is a handler that expects the body echoBody, answers ok and records
// that it ran.
func echoX(t *testing.T, called *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		if b, err := io.ReadAll(r.Body); err != nil || string(b) != echoBody {
			t.Errorf("handler body = %q, %v, want %s", b, err, echoBody)
		}
		if _, err := io.WriteString(w, "ok"); err != nil {
			t.Errorf("WriteString = %v, want nil", err)
		}
	})
}

func TestVerifierMiddleware(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	sign := func(edit func(r *http.Request)) *http.Request {
		r := signedRequest(t, s, http.MethodPost, testURL, echoBody)
		edit(r)
		return r
	}
	full := newTestStore(t, 1)
	if _, err := full.Seen(t.Context(), "taken", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Seen = %v, want nil", err)
	}
	leaky := &stubStore{err: errStoreDown}
	memory := func() NonceStore { return newTestStore(t, storeCapacity) }
	cases := []struct {
		name   string
		store  NonceStore
		req    *http.Request
		status int
	}{
		{"valid", memory(), sign(func(*http.Request) {}), http.StatusOK},
		{"missing", memory(), newRequest(t, http.MethodGet, testURL, ""), http.StatusUnauthorized},
		{"malformed", memory(), sign(func(r *http.Request) { r.Header.Set(HeaderNonce, "x") }),
			http.StatusUnauthorized},
		{"skew", memory(), sign(func(r *http.Request) { r.Header.Set(HeaderTimestamp, "1") }), http.StatusUnauthorized},
		{"body", memory(), sign(func(r *http.Request) { r.Body = errBody{} }), http.StatusUnauthorized},
		{"signature", memory(), sign(func(r *http.Request) { r.Method = http.MethodPut }), http.StatusUnauthorized},
		{"replayed", &stubStore{}, sign(func(*http.Request) {}), http.StatusUnauthorized},
		{"full", full, sign(func(*http.Request) {}), http.StatusServiceUnavailable},
		{"store", leaky, sign(func(*http.Request) {}), http.StatusServiceUnavailable},
	}
	answers := map[int]struct{ body, challenge, retry string }{
		http.StatusOK:                 {"ok", "", ""},
		http.StatusUnauthorized:       {unauthorizedBody, "X-Auth-Signature", ""},
		http.StatusServiceUnavailable: {"service unavailable\n", "", "1"},
	}
	for _, tc := range cases {
		v, err := NewVerifier(testKey(), tc.store)
		if err != nil {
			t.Fatalf(wantVerifier, err)
		}
		called := false
		h := v.Middleware(echoX(t, &called))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tc.req)
		want := answers[tc.status]
		if rec.Code != tc.status || rec.Body.String() != want.body || called != (tc.status == http.StatusOK) ||
			rec.Header().Get("WWW-Authenticate") != want.challenge || rec.Header().Get("Retry-After") != want.retry {
			t.Errorf("%s: %d %q, WWW-Authenticate %q, Retry-After %q, next called %t; want %d %q, %q, %q, %t",
				tc.name, rec.Code, rec.Body.String(), rec.Header().Get("WWW-Authenticate"),
				rec.Header().Get("Retry-After"), called, tc.status, want.body, want.challenge, want.retry,
				tc.status == http.StatusOK)
		}
	}
}

// TestVerifierMiddlewareServesACopy hands next a copy of a request with a body,
// carrying the verified body, and a bodiless request itself; the caller's request
// keeps its body.
func TestVerifierMiddlewareServesACopy(t *testing.T) {
	t.Parallel()
	s, v := freshPair(t)
	r := signedRequest(t, s, http.MethodPost, testURL, echoBody)
	body := r.Body
	var served *http.Request
	called := false
	echo := echoX(t, &called)
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
		served = got
		echo.ServeHTTP(w, got)
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !called || served == nil || served == r || r.Body != body {
		t.Fatalf("Middleware served %p (caller %p) after handler call %t, caller body replaced %t; want a copy "+
			"and the caller's body kept", served, r, called, r.Body != body)
	}
	client := signedRequest(t, s, http.MethodGet, testURL, "")
	for _, bodiless := range []*http.Request{client, bodilessServerRequest(t, s)} {
		served = nil
		v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) { served = got })).
			ServeHTTP(httptest.NewRecorder(), bodiless)
		if served != bodiless {
			t.Fatalf("Middleware godoc: \"passes next each request v verifies, a copy with the body restored when "+
				"it has one\": served %p for the bodiless request %p (Body %T), want the request itself", served,
				bodiless, bodiless.Body)
		}
	}
}

// bodilessServerRequest returns a signed server request without a body whose Body,
// as the one an HTTP/2 server gives, is not http.NoBody.
func bodilessServerRequest(t *testing.T, s *Signer) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testURL, strings.NewReader(""))
	r.Header = signedRequest(t, s, http.MethodGet, testURL, "").Header
	return r
}

// delivery is what a handler behind Middleware received.
type delivery struct {
	outer, served *http.Request
	body          string
}

// middlewareServer starts a TLS server, HTTP/2 when h2, that passes each request
// through the Middleware of a verifier of freshPair and reports what next got.
func middlewareServer(t *testing.T, h2 bool) (*httptest.Server, *Signer, <-chan delivery) {
	t.Helper()
	s, v := freshPair(t)
	got := make(chan delivery, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, outer *http.Request) {
		v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, served *http.Request) {
			b, err := io.ReadAll(served.Body)
			if err != nil {
				t.Errorf("ReadAll = %v, want nil", err)
			}
			got <- delivery{outer: outer, served: served, body: string(b)}
		})).ServeHTTP(w, outer)
	}))
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, s, got
}

// TestVerifierMiddlewareServerRequests sends signed requests through HTTP/1.1 and
// HTTP/2 servers: next gets a bodiless request itself, whatever Body the server
// gives it, and a copy of a request with a body, carrying the body.
func TestVerifierMiddlewareServerRequests(t *testing.T) {
	t.Parallel()
	for _, h2 := range []bool{false, true} {
		srv, s, got := middlewareServer(t, h2)
		for _, body := range []string{"", oneByte} {
			resp, err := srv.Client().Do(signedRequest(t, s, http.MethodPost, srv.URL+"/p", body))
			if err != nil {
				t.Fatalf("Do = %v, want an answer", err)
			}
			if err = resp.Body.Close(); err != nil || resp.StatusCode != http.StatusOK || (resp.ProtoMajor == 2) != h2 {
				t.Fatalf("HTTP/2 %t: %s %d, close %v; want 200 over the protocol asked", h2, resp.Proto,
					resp.StatusCode, err)
			}
			if d := <-got; (d.served == d.outer) != (body == "") || d.body != body {
				t.Errorf("Middleware godoc: \"passes next each request v verifies, a copy with the body restored "+
					"when it has one\": %s, body %q: next got the request itself %t (Body %T, ContentLength %d) "+
					"and the body %q; want itself only without a body", resp.Proto, body, d.served == d.outer,
					d.outer.Body, d.outer.ContentLength, d.body)
			}
		}
	}
}

// TestVerifierVerifyPassesTheContext hands the store the context Verify gets,
// and Middleware the context of the request.
func TestVerifierVerifyPassesTheContext(t *testing.T) {
	t.Parallel()
	store := &ctxStore{}
	v, err := NewVerifier(testKey(), store)
	if err != nil {
		t.Fatalf(wantVerifier, err)
	}
	s := newTestSigner(t)
	ctx := context.WithValue(t.Context(), ctxKey{}, "verify")
	if err := v.Verify(ctx, signedRequest(t, s, http.MethodGet, testURL, "")); err != nil || store.got != "verify" {
		t.Fatalf("Verify = %v with the store given the mark %v, want the caller's context", err, store.got)
	}
	r := signedRequest(t, s, http.MethodGet, testURL, "")
	r = r.WithContext(context.WithValue(t.Context(), ctxKey{}, "middleware"))
	v.Middleware(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), r)
	if store.got != "middleware" {
		t.Fatalf("Middleware gave the store the mark %v, want the request's context", store.got)
	}
}

// roundTrip sends a fresh copy of the body of r through c and returns the
// status and the response body.
func roundTrip(t *testing.T, c *http.Client, r *http.Request) (status int, body string) {
	t.Helper()
	rc, err := r.GetBody()
	if err != nil {
		t.Fatalf("GetBody = %v, want a copy", err)
	}
	r.Body = rc
	resp, err := c.Do(r)
	if err != nil {
		t.Fatalf("Do = %v, want an answer", err)
	}
	b, err := io.ReadAll(resp.Body)
	if err = errors.Join(err, resp.Body.Close()); err != nil {
		t.Fatalf("read and close answer = %v, want nil", err)
	}
	return resp.StatusCode, string(b)
}

func TestVerifierMiddlewareOverHTTP(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	srv := httptest.NewServer(v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(w, r.Body); err != nil {
			t.Errorf("Copy = %v, want nil", err)
		}
	})))
	defer srv.Close()
	r := newRequest(t, http.MethodPost, srv.URL+"/a%2Fb/c?q=%C3%A9&x=1", `{"id":7}`)
	r.Header.Set("X-Other", "not signed")
	if err := s.Sign(t.Context(), r); err != nil {
		t.Fatalf("Sign = %v, want nil", err)
	}
	if status, body := roundTrip(t, srv.Client(), r); status != http.StatusOK || body != `{"id":7}` {
		t.Fatalf("first send = %d %q, want 200 with the body echoed", status, body)
	}
	if status, body := roundTrip(t, srv.Client(), r); status != http.StatusUnauthorized || body != unauthorizedBody {
		t.Fatalf("replayed send = %d %q, want 401 %q", status, body, unauthorizedBody)
	}
}

func ExampleNewVerifier() {
	const capacity = 8192
	key := secret.New("an example key of at least 32 bytes")
	store, err := NewMemoryStore(capacity)
	if err != nil {
		fmt.Println(err)
		return
	}
	verifier, err := NewVerifier(key, store, WithWindow(time.Minute))
	if err != nil {
		fmt.Println(err)
		return
	}
	protected := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))
	fmt.Println(rec.Code, rec.Header().Get("WWW-Authenticate"), strings.TrimSpace(rec.Body.String()))
	// Output: 401 X-Auth-Signature unauthorized
}

// signUnderLimit signs r, whose body holds size bytes, and reports false
// when Sign refuses a body over 1 MiB as it must.
func signUnderLimit(t *testing.T, s *Signer, r *http.Request, size int) bool {
	t.Helper()
	err := s.Sign(t.Context(), r)
	if size > mib {
		if !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("Sign of %d bytes = %v, want errBodyTooLarge", size, err)
		}
		return false
	}
	if err != nil {
		t.Fatalf("Sign = %v, want nil", err)
	}
	return true
}

// Seeds of FuzzVerifierVerify: a skew, a position and the bit that flips the
// case of an ASCII letter.
const (
	seedSkew = 7
	seedPos  = 3
	caseBit  = 0x20
)

// overLimitNonce is the nonce FuzzVerifierVerify gives a request whose body Sign
// refuses, so that Verify meets that body behind a valid envelope.
const overLimitNonce = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"

func FuzzVerifierVerify(f *testing.F) {
	f.Add(http.MethodGet, "api.example", "/v1/items", "a=1", []byte(nil),
		int32(0), uint8(0), uint16(0), byte(0), "")
	f.Add(http.MethodPost, "API.example:8443", "/a b", "x=%2F", []byte(`{"a":1}`),
		int32(-windowSeconds), uint8(0), uint16(0), byte(0), "")
	f.Add(http.MethodPut, "h", "/p", "", []byte("body"),
		int32(windowSeconds+1), uint8(0), uint16(0), byte(0), "")
	f.Add(http.MethodPut, "h", "/p", "", bytes.Repeat([]byte("b"), mib+1),
		int32(0), uint8(0), uint16(0), byte(0), "")
	for field := range uint8(requestMutations) {
		f.Add(http.MethodGet, "api.example", "/p", "q", []byte("b"), int32(seedSkew), field, uint16(seedPos),
			byte(caseBit), "+1700000007")
	}
	for _, raw := range []string{
		"01700000000", "-1", "9223372036854775808", strings.Repeat("A", 2*nonceSize), strings.Repeat("0", sigHexDigits),
	} {
		f.Add("", "", "", "", []byte(nil), int32(0), uint8(setEnvelope), uint16(0), byte(0), raw)
	}
	f.Fuzz(func(t *testing.T, method, host, path, query string, body []byte, skew int32,
		field uint8, pos uint16, flip byte, raw string,
	) {
		synctest.Test(t, func(t *testing.T) {
			r := &http.Request{
				Method: method, Host: host, URL: &url.URL{Path: path, RawQuery: query},
				Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)),
			}
			if !signUnderLimit(t, newTestSigner(t), r, len(body)) {
				r.Header.Set(HeaderNonce, overLimitNonce)
			}
			resign(r, body, testUnix+int64(skew))
			body = mutateRequest(r, body, field, pos, flip, raw)
			want := referenceVerify(time.Now(), r, body)
			v := newTestVerifier(t)
			got := v.Verify(t.Context(), r)
			if (want == nil && got != nil) || (want != nil && !errors.Is(got, want)) {
				t.Fatalf("Verify = %v, want %v as the reference", got, want)
			}
			if got == nil {
				if err := v.Verify(t.Context(), r); !errors.Is(err, ErrNonceReplayed) {
					t.Fatalf("second Verify = %v, want ErrNonceReplayed", err)
				}
			}
		})
	})
}

func BenchmarkVerifierVerify(b *testing.B) {
	s := newTestSigner(b)
	store := &stubStore{fresh: true}
	v, err := NewVerifier(testKey(), store)
	if err != nil {
		b.Fatalf(wantVerifier, err)
	}
	for _, bc := range []struct{ name, body string }{{"no body", ""}, {"4 KiB body", body4KiB()}} {
		r := signedRequest(b, s, http.MethodPost, "https://api.example/v1/items?page=2", bc.body)
		b.Run(bc.name, func(b *testing.B) {
			if err := v.Verify(b.Context(), r); err != nil {
				b.Fatalf("Verify = %v, want nil", err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := v.Verify(b.Context(), r); err != nil {
					b.Fatalf("Verify = %v, want nil", err)
				}
			}
		})
	}
	if store.calls.Load() == 0 {
		b.Fatal("Verify recorded no nonce, want every verified nonce recorded")
	}
}

// BenchmarkVerifierVerifyReplayedParallel verifies one recorded request on
// every goroutine, all sharing the Verifier's MAC pool and memory store.
func BenchmarkVerifierVerifyReplayedParallel(b *testing.B) {
	v := newTestVerifier(b)
	r := signedRequest(b, newTestSigner(b), http.MethodGet, "https://api.example/v1/items?page=2", "")
	if err := v.Verify(b.Context(), r); err != nil {
		b.Fatalf("Verify = %v, want nil", err)
	}
	if err := v.Verify(b.Context(), r); !errors.Is(err, ErrNonceReplayed) {
		b.Fatalf("Verify(replay) = %v, want ErrNonceReplayed", err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := v.Verify(b.Context(), r); !errors.Is(err, ErrNonceReplayed) {
				b.Errorf("Verify(replay) = %v, want ErrNonceReplayed", err)
				return
			}
		}
	})
}

// freshPair returns a signer and a verifier of testKey on the real clock,
// the verifier recording into a store that finds every nonce fresh.
func freshPair(tb testing.TB) (*Signer, *Verifier) {
	tb.Helper()
	v, err := NewVerifier(testKey(), &stubStore{fresh: true})
	if err != nil {
		tb.Fatalf(wantVerifier, err)
	}
	return newTestSigner(tb), v
}

// rewindable gives r a body of data and returns the function that rewinds it, so
// that every run of an allocation test reads the same body.
func rewindable(r *http.Request, data []byte) func() {
	rd := bytes.NewReader(data)
	rc := io.NopCloser(rd)
	return func() {
		rd.Reset(data)
		r.Body = rc
	}
}

// verifyBodyAllocs counts what Verify allocates for a body, the bytes read and the
// reader and closer that restore them; a bodiless request takes none.
const verifyBodyAllocs = 3

// TestVerifierVerifyAllocs verifies signed requests with the MAC state from the
// pool, with and without a body, the bodiless server request included.
func TestVerifierVerifyAllocs(t *testing.T) {
	s, v := freshPair(t)
	body := body4KiB()
	withBody := signedRequest(t, s, http.MethodPost, testURL, body)
	for _, tc := range []struct {
		r      *http.Request
		rewind func()
		allocs float64
	}{
		{signedRequest(t, s, http.MethodGet, testURL, ""), func() {}, 0},
		{bodilessServerRequest(t, s), func() {}, 0},
		{withBody, rewindable(withBody, []byte(body)), verifyBodyAllocs},
	} {
		assertAllocs(t, tc.allocs, func() {
			tc.rewind()
			if err := v.Verify(t.Context(), tc.r); err != nil {
				t.Fatalf("Verify(%s request) = %v, want nil", tc.r.Method, err)
			}
		})
	}
}

// TestVerifierMiddlewareAllocs admits signed requests: bodiless ones, client and
// server, served themselves without an allocation, and one with a body with its
// copy of the request on top of the allocations of Verify.
func TestVerifierMiddlewareAllocs(t *testing.T) {
	s, v := freshPair(t)
	admitted := false
	h := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { admitted = true }))
	w := httptest.NewRecorder()
	body := body4KiB()
	withBody := signedRequest(t, s, http.MethodPost, testURL, body)
	for _, tc := range []struct {
		r      *http.Request
		rewind func()
		allocs float64
	}{
		{signedRequest(t, s, http.MethodGet, testURL, ""), func() {}, 0},
		{bodilessServerRequest(t, s), func() {}, 0},
		{withBody, rewindable(withBody, []byte(body)), verifyBodyAllocs + 1},
	} {
		assertAllocs(t, tc.allocs, func() {
			tc.rewind()
			admitted = false
			h.ServeHTTP(w, tc.r)
			if !admitted {
				t.Fatalf("Middleware(%s request) = %d, want the request admitted", tc.r.Method, w.Code)
			}
		})
	}
}

func BenchmarkVerifierMiddleware(b *testing.B) {
	s, v := freshPair(b)
	r := signedRequest(b, s, http.MethodGet, testURL, "")
	var admitted atomic.Int64
	h := v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { admitted.Add(1) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if admitted.Load() != 1 {
		b.Fatalf("Middleware = %d, want the request admitted", w.Code)
	}
	b.Run("no body", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			h.ServeHTTP(w, r)
		}
	})
	b.Run("no body parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			pw := httptest.NewRecorder()
			for pb.Next() {
				h.ServeHTTP(pw, r)
			}
		})
	})
}
