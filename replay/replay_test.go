package replay

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// goodKey is a 32-byte fixture used by every test. Real deployments must
// supply an unguessable secret.
var goodKey = bytes.Repeat([]byte{0x42}, 32)

func newSigner(t *testing.T) *Signer {
	t.Helper()
	return &Signer{Key: goodKey}
}

func newVerifier() *Verifier {
	store, err := Memory(64)
	if err != nil {
		panic(err)
	}
	return &Verifier{Key: goodKey, Window: time.Minute, NonceStore: store}
}

func mustRequest(tb testing.TB, method, urlStr string) *http.Request {
	tb.Helper()
	return newHTTPReq(tb, method, urlStr, http.NoBody)
}

func TestSignVerify_RoundTrip(t *testing.T) {
	s := newSigner(t)
	v := newVerifier()
	r := mustRequest(t, http.MethodGet, "https://api.example/path")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := v.Verify(context.Background(), r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	s := newSigner(t)
	v := newVerifier()
	r := mustRequest(t, http.MethodGet, "https://api.example/path")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), r); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("second Verify err = %v, want ErrNonceReplayed", err)
	}
}

func TestVerify_MissingHeaders(t *testing.T) {
	v := newVerifier()
	r := mustRequest(t, http.MethodGet, "/")
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrMissingHeaders) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_BadTimestamp(t *testing.T) {
	v := newVerifier()
	r := mustRequest(t, http.MethodGet, "/")
	r.Header.Set(HeaderTimestamp, "not-a-number")
	r.Header.Set(HeaderNonce, strings.Repeat("a", hexNonceLen))
	r.Header.Set(HeaderSignature, "deadbeef")
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrMissingHeaders) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_NonceLengthRejected(t *testing.T) {
	v := newVerifier()
	r := mustRequest(t, http.MethodGet, "/")
	r.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	r.Header.Set(HeaderNonce, "short")
	r.Header.Set(HeaderSignature, "x")
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrMissingHeaders) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_SkewBackward(t *testing.T) {
	v := newVerifier()
	v.Now = func() time.Time { return time.Unix(10000, 0) }
	s := &Signer{Key: goodKey, Now: func() time.Time { return time.Unix(0, 0) }}
	r := mustRequest(t, http.MethodGet, "/path")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_SkewForward(t *testing.T) {
	v := newVerifier()
	v.Now = func() time.Time { return time.Unix(0, 0) }
	s := &Signer{Key: goodKey, Now: func() time.Time { return time.Unix(10000, 0) }}
	r := mustRequest(t, http.MethodGet, "/path")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_SignatureMismatch(t *testing.T) {
	s := newSigner(t)
	v := newVerifier()
	r := mustRequest(t, http.MethodGet, "/path")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// Flip one byte of the signature.
	sig := r.Header.Get(HeaderSignature)
	flipped := flipFirstHexDigit(sig)
	r.Header.Set(HeaderSignature, flipped)
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_PathChangeBreaksSignature(t *testing.T) {
	s := newSigner(t)
	v := newVerifier()
	r := mustRequest(t, http.MethodGet, "/original")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// Mutate the URL after signing — the signature must no longer verify.
	r.URL.Path = "/tampered"
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestSign_RejectsShortKey(t *testing.T) {
	s := &Signer{Key: []byte("short")}
	r := mustRequest(t, http.MethodGet, "/")
	if err := s.Sign(context.Background(), r); !errors.Is(err, ErrShortKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_RejectsShortKey(t *testing.T) {
	v := &Verifier{Key: []byte("short")}
	r := mustRequest(t, http.MethodGet, "/")
	if err := v.Verify(context.Background(), r); !errors.Is(err, ErrShortKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestMiddleware_AllowsValid(t *testing.T) {
	s := newSigner(t)
	v := newVerifier()
	called := false
	h := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	r := mustRequest(t, http.MethodGet, "/api")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !called {
		t.Fatal("inner handler not called")
	}
}

func TestMiddleware_RejectsMissingHeaders(t *testing.T) {
	v := newVerifier()
	h := Middleware(v)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be called")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mustRequest(t, http.MethodGet, "/api"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMemory_FirstSeenIsFresh(t *testing.T) {
	m, mErr := Memory(8)
	if mErr != nil {
		t.Fatal(mErr)
	}
	seen, err := m.Seen(context.Background(), "n1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("first sighting should report seen=false")
	}
}

func TestMemory_DuplicateIsSeen(t *testing.T) {
	m, mErr := Memory(8)
	if mErr != nil {
		t.Fatal(mErr)
	}
	if _, err := m.Seen(context.Background(), "n1", time.Minute); err != nil {
		t.Fatal(err)
	}
	seen, err := m.Seen(context.Background(), "n1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("duplicate sighting should report seen=true")
	}
}

func TestMemory_Expiry(t *testing.T) {
	m, mErr := Memory(8)
	if mErr != nil {
		t.Fatal(mErr)
	}
	if _, err := m.Seen(context.Background(), "n1", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	seen, err := m.Seen(context.Background(), "n1", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("expired entry should report seen=false")
	}
}

func TestMemory_LRUOverflow(t *testing.T) {
	m, mErr := Memory(2)
	if mErr != nil {
		t.Fatal(mErr)
	}
	if _, err := m.Seen(context.Background(), "a", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Seen(context.Background(), "b", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Seen(context.Background(), "c", time.Hour); err != nil {
		t.Fatal(err)
	}
	// "a" was the LRU and must have been evicted.
	seen, err := m.Seen(context.Background(), "a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("LRU entry should have been evicted")
	}
}

func TestMemory_RejectsZeroCapacity(t *testing.T) {
	if _, err := Memory(0); !errors.Is(err, ErrMemoryCapacity) {
		t.Fatalf("Memory(0) err = %v, want %v", err, ErrMemoryCapacity)
	}
}

func TestMemory_ConcurrentSafe(t *testing.T) {
	m, mErr := Memory(64)
	if mErr != nil {
		t.Fatal(mErr)
	}
	var wg sync.WaitGroup
	const goroutines = 32
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			nonce := strconv.Itoa(idx)
			if _, err := m.Seen(context.Background(), nonce, time.Minute); err != nil {
				t.Errorf("Seen: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestVerifier_DefaultStoreInstalled(t *testing.T) {
	v := &Verifier{Key: goodKey, Window: time.Minute}
	s := newSigner(t)
	r := mustRequest(t, http.MethodGet, "/")
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.NonceStore == nil {
		t.Fatal("expected default NonceStore to be installed")
	}
}

func TestVerifier_DefaultWindow(t *testing.T) {
	v := &Verifier{Key: goodKey}
	if got := v.window(); got != defaultWindow {
		t.Fatalf("window = %v", got)
	}
}

func TestAbs(t *testing.T) {
	cases := []struct {
		want int64
		in   int64
	}{{5, 5}, {5, -5}, {0, 0}}
	for _, tc := range cases {
		if got := abs(tc.in); got != tc.want {
			t.Errorf("abs(%d) = %d", tc.in, got)
		}
	}
}

func flipFirstHexDigit(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	switch b[0] {
	case '0':
		b[0] = '1'
	default:
		b[0] = '0'
	}
	return string(b)
}

// stubReader returns deterministic bytes for nonce tests.
type stubReader struct {
	calls atomic.Int64
}

func (s *stubReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(s.calls.Add(1) & 0xff)
	}
	return len(p), nil
}

func TestSigner_DeterministicWithStubRand(t *testing.T) {
	r := mustRequest(t, http.MethodGet, "/x")
	s := &Signer{
		Key:  goodKey,
		Now:  func() time.Time { return time.Unix(1000, 0) },
		Rand: &stubReader{},
	}
	if err := s.Sign(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get(HeaderTimestamp); got != "1000" {
		t.Fatalf("timestamp = %q", got)
	}
	if got := len(r.Header.Get(HeaderNonce)); got != hexNonceLen {
		t.Fatalf("nonce len = %d", got)
	}
}

// FuzzVerify exercises the Verify path with arbitrary header inputs to
// surface panics and unexpected error categories.
func FuzzVerify(f *testing.F) {
	f.Add("", "", "")
	f.Add("not-a-number", "abcdef", "deadbeef")
	f.Add("1700000000", strings.Repeat("a", hexNonceLen), strings.Repeat("0", 64))
	f.Add(strings.Repeat("9", 30), "", "")

	v := newVerifier()
	f.Fuzz(func(t *testing.T, ts, nonce, sig string) {
		r := mustRequest(t, http.MethodGet, "/x")
		r.Header.Set(HeaderTimestamp, ts)
		r.Header.Set(HeaderNonce, nonce)
		r.Header.Set(HeaderSignature, sig)
		err := v.Verify(context.Background(), r)
		if err == nil {
			return
		}
		switch {
		case errors.Is(err, ErrMissingHeaders):
		case errors.Is(err, ErrTimestampSkew):
		case errors.Is(err, ErrSignatureInvalid):
		case errors.Is(err, ErrNonceReplayed):
		default:
			t.Fatalf("unexpected error category: %v", err)
		}
	})
}

// BenchmarkSigner_Sign measures signing cost on a small request.
func BenchmarkSigner_Sign(b *testing.B) {
	s := &Signer{Key: goodKey}
	b.ReportAllocs()

	for b.Loop() {
		r := mustRequest(b, http.MethodGet, "/api/path")
		if err := s.Sign(context.Background(), r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerify_Hit measures verification of a freshly-signed request.
func BenchmarkVerify_Hit(b *testing.B) {
	s := &Signer{Key: goodKey}
	store, mErr := Memory(1 << 16)
	if mErr != nil {
		b.Fatal(mErr)
	}
	v := &Verifier{Key: goodKey, Window: time.Hour, NonceStore: store}
	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		r := mustRequest(b, http.MethodGet, "/api")
		if err := s.Sign(ctx, r); err != nil {
			b.Fatal(err)
		}
		if err := v.Verify(ctx, r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMemory_Seen measures the LRU+TTL store hot path.
func BenchmarkMemory_Seen(b *testing.B) {
	m, mErr := Memory(1 << 16)
	if mErr != nil {
		b.Fatal(mErr)
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		nonce := strconv.Itoa(i)
		if _, err := m.Seen(ctx, nonce, time.Minute); err != nil {
			b.Fatal(err)
		}
	}
}
