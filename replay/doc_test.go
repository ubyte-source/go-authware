package replay

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ubyte-source/go-authware/v2/secret"
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

// testURL is the target of the signed test requests.
const testURL = "https://api.example/"

// wantVerifier fails a test whose NewVerifier refused its options.
const wantVerifier = "NewVerifier = %v, want a verifier"

// largeCapacity holds every nonce a verifier test records.
const largeCapacity = 1024

// testUnix is midnight UTC 2000-01-01 in Unix seconds, the time at which the
// clock of a synctest bubble starts.
const testUnix = 946684800

// windowSeconds is the documented default window, 5m, in seconds.
const windowSeconds = 300

// mib is one mebibyte, the body limit of signing and verifying.
const mib = 1 << 20

// oneByte is a one-byte header value or body.
const oneByte = "x"

// lowerHex32 matches the 32 lowercase hex digits of a nonce.
var lowerHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// envelopeHeaders is the number of headers of a signed request.
const envelopeHeaders = 3

// envelopeNames lists the documented names of the three headers in a fixed order.
func envelopeNames() [envelopeHeaders]string {
	return [...]string{"X-Auth-Timestamp", "X-Auth-Nonce", "X-Auth-Signature"}
}

// testKeyRaw is the 32-byte fixture key; real keys must be random.
const testKeyRaw = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

// errBoom is the error errBody returns and failing stubs carry.
var errBoom = errors.New("test: boom")

// errBody fails every read and close.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errBoom }

func (errBody) Close() error { return errBoom }

func testKey() secret.Value { return secret.New(testKeyRaw) }

// newTestSigner returns a Signer of testKey.
func newTestSigner(tb testing.TB) *Signer {
	tb.Helper()
	s, err := NewSigner(testKey())
	if err != nil {
		tb.Fatalf("NewSigner = %v, want a signer", err)
	}
	return s
}

func newTestStore(tb testing.TB, capacity int) *memoryStore {
	tb.Helper()
	store, err := NewMemoryStore(capacity)
	if err != nil {
		tb.Fatalf("NewMemoryStore = %v, want a store", err)
	}
	m, ok := store.(*memoryStore)
	if !ok {
		tb.Fatalf("NewMemoryStore = %T, want a *memoryStore", store)
	}
	return m
}

// newTestVerifier returns a Verifier of testKey recording into a memory store.
func newTestVerifier(tb testing.TB, opts ...VerifierOption) *Verifier {
	tb.Helper()
	v, err := NewVerifier(testKey(), newTestStore(tb, largeCapacity), opts...)
	if err != nil {
		tb.Fatalf(wantVerifier, err)
	}
	return v
}

// ipv6Zone matches an IPv6 literal host around the zone net/http drops from it:
// the last "%" before the last "]".
var ipv6Zone = regexp.MustCompile(`(?s)^(\[.*)%[^%]*(\][^\]]*)$`)

// referenceHost returns, independently of the production code, host without
// the zone net/http drops and with ASCII letters lowercased.
func referenceHost(host string) string {
	b := []byte(ipv6Zone.ReplaceAllString(host, "$1$2"))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// referenceSignature returns, independently of the production code, the
// signature of r over body, ts and nonce under testKey.
func referenceSignature(r *http.Request, body []byte, ts, nonce string) string {
	method := cmp.Or(r.Method, http.MethodGet)
	host := referenceHost(cmp.Or(r.Host, r.URL.Host))
	input := fmt.Sprintf("%s\n%s\n%s\n%x\n%s\n%s",
		method, host, r.URL.RequestURI(), sha256.Sum256(body), ts, nonce)
	mac := hmac.New(sha256.New, []byte(testKeyRaw))
	_, _ = mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

// body4KiB returns the 4 KiB body the allocation tests and benchmarks send.
func body4KiB() string { return strings.Repeat("a", 4<<10) }

// newRequest builds a client request; an empty body means no body.
func newRequest(tb testing.TB, method, target, body string) *http.Request {
	tb.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequestWithContext(tb.Context(), method, target, rd)
	if err != nil {
		tb.Fatalf("NewRequestWithContext = %v, want a request", err)
	}
	return r
}

func signedRequest(tb testing.TB, s *Signer, method, target, body string) *http.Request {
	tb.Helper()
	r := newRequest(tb, method, target, body)
	if err := s.Sign(tb.Context(), r); err != nil {
		tb.Fatalf("Sign = %v, want nil", err)
	}
	return r
}
