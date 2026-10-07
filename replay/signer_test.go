package replay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/cred"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// Literals of the signer tests: the nonces drawn and a body.
const (
	nonceDraws  = 1000
	testPayload = "payload"
)

func TestNewSigner(t *testing.T) {
	t.Parallel()
	if _, err := NewSigner(secret.New(testKeyRaw[1:])); !errors.Is(err, ErrShortKey) {
		t.Fatalf("short key: err = %v, want ErrShortKey", err)
	}
	if s, err := NewSigner(testKey()); err != nil || s == nil {
		t.Fatalf("NewSigner = %v, %v, want a signer", s, err)
	}
}

// TestSignerSignMatchesTheReference signs at the second of the clock with a
// nonce of 32 lowercase hex digits and the reference signature of the request.
func TestSignerSignMatchesTheReference(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := newTestSigner(t)
		names := envelopeNames()
		for _, tc := range []struct{ method, target, body string }{
			{http.MethodGet, "https://api.example/v1/items?b=2&a=1", ""},
			{http.MethodPost, "https://API.Example:8443/a%20b/c?x=%2F", `{"a":1}`},
		} {
			r := signedRequest(t, s, tc.method, tc.target, tc.body)
			ts, nonce := r.Header.Values(names[0]), r.Header.Values(names[1])
			if len(ts) != 1 || ts[0] != strconv.Itoa(testUnix) || len(nonce) != 1 || !lowerHex32.MatchString(nonce[0]) {
				t.Fatalf("%s %s: timestamp %q and nonce %q, want %d and 32 hex digits", tc.method,
					tc.target, ts, nonce, testUnix)
			}
			want := referenceSignature(r, []byte(tc.body), ts[0], nonce[0])
			if got := r.Header.Values(names[2]); len(got) != 1 || got[0] != want {
				t.Errorf("%s %s: signature %q, want %s", tc.method, tc.target, got, want)
			}
		}
	})
}

func TestSignerSignNonceUnique(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	seen := make(map[string]bool, nonceDraws)
	for range nonceDraws {
		n := signedRequest(t, s, http.MethodGet, testURL, "").Header.Get(HeaderNonce)
		if !lowerHex32.MatchString(n) {
			t.Fatalf("nonce = %q, want 32 lowercase hex digits", n)
		}
		if seen[n] {
			t.Fatalf("nonce = %s again, want a fresh nonce per request", n)
		}
		seen[n] = true
	}
}

// TestSignerSignHeaderSlices adds a value to each signed header in turn:
// every header keeps its own values.
func TestSignerSignHeaderSlices(t *testing.T) {
	t.Parallel()
	r := signedRequest(t, newTestSigner(t), http.MethodGet, testURL, "")
	signed := r.Header.Clone()
	names := []string{HeaderTimestamp, HeaderNonce, HeaderSignature}
	for _, name := range names {
		r.Header.Add(name, oneByte)
	}
	for _, name := range names {
		if got, want := r.Header.Values(name), signed.Get(name); len(got) != 2 || got[0] != want || got[1] != oneByte {
			t.Errorf("%s after an Add to each header = %q, want [%s x]", name, got, want)
		}
	}
}

// TestSignerSignZoneHost signs requests to IPv6 literal hosts, one with a zone,
// sends them through net/http's wire form and verifies what a server reads.
func TestSignerSignZoneHost(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	for _, target := range []string{"http://[fe80::1%25eth0]:8080/p", "http://[::1]:8080/p"} {
		r := signedRequest(t, s, http.MethodGet, target, "")
		var wire bytes.Buffer
		if err := r.Write(&wire); err != nil {
			t.Fatalf("Write = %v, want nil", err)
		}
		got, err := http.ReadRequest(bufio.NewReader(&wire))
		if err != nil {
			t.Fatalf("ReadRequest = %v, want a request", err)
		}
		if err := v.Verify(t.Context(), got); err != nil {
			t.Errorf("Signer godoc: \"signing a valid ASCII host with its letters lowercased and without an "+
				"IPv6 zone\": signed %q, received %q: Verify = %v, want nil", r.URL.Host, got.Host, err)
		}
	}
}

func TestSignerSignNilHeader(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	r := newRequest(t, http.MethodGet, testURL, "")
	r.Header = nil
	if err := s.Sign(t.Context(), r); err != nil || r.Header.Get(HeaderSignature) == "" {
		t.Fatalf("Sign = %v with headers %v, want the signed headers", err, r.Header)
	}
}

func TestSignerSignBuffersBody(t *testing.T) {
	t.Parallel()
	s, v := newTestSigner(t), newTestVerifier(t)
	buffered := newRequest(t, http.MethodPut, "https://api.example/doc", "")
	buffered.Body = io.NopCloser(strings.NewReader(testPayload))
	if err := s.Sign(t.Context(), buffered); err != nil {
		t.Fatalf("Sign = %v, want nil", err)
	}
	if b, err := io.ReadAll(buffered.Body); err != nil || string(b) != testPayload {
		t.Fatalf("restored body = %q, %v, want payload", b, err)
	}
	if buffered.ContentLength != int64(len(testPayload)) {
		t.Fatalf("ContentLength = %d, want %d, the length of the copy", buffered.ContentLength, len(testPayload))
	}
	rc, err := buffered.GetBody()
	if err != nil {
		t.Fatalf("GetBody = %v, want a copy", err)
	}
	buffered.Body = rc
	if err = v.Verify(t.Context(), buffered); err != nil {
		t.Fatalf("Verify(buffered body) = %v, want nil", err)
	}
}

func TestSignerSignKeepsGetBody(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	rewound := newRequest(t, http.MethodPut, "https://api.example/doc", testPayload)
	body, getBody, calls := rewound.Body, rewound.GetBody, 0
	rewound.GetBody = func() (io.ReadCloser, error) {
		calls++
		return getBody()
	}
	if err := s.Sign(t.Context(), rewound); err != nil {
		t.Fatalf("Sign = %v, want nil", err)
	}
	if rewound.Body != body {
		t.Fatal("body after Sign = replaced, want the body of a request with GetBody kept")
	}
	if _, err := rewound.GetBody(); err != nil || calls != 2 {
		t.Fatalf("GetBody calls = %d, %v; want 2 (Sign kept the caller's GetBody)", calls, err)
	}
	if b, err := io.ReadAll(rewound.Body); err != nil || string(b) != testPayload {
		t.Fatalf("r.Body = %q, %v, want payload unread", b, err)
	}
}

// closeFails is a body that reads its text and fails its close.
type closeFails struct {
	io.Reader
}

func (closeFails) Close() error { return errBoom }

// TestSignerSignBodyErrors fails Sign on a body that fails to read or close, with
// and without GetBody.
func TestSignerSignBodyErrors(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	unreadable := newRequest(t, http.MethodPut, testURL, "")
	unreadable.Body = errBody{}
	unclosable := newRequest(t, http.MethodPut, testURL, "")
	unclosable.Body = closeFails{strings.NewReader(oneByte)}
	noRewind := newRequest(t, http.MethodPut, testURL, oneByte)
	noRewind.GetBody = func() (io.ReadCloser, error) { return nil, errBoom }
	badRewind := newRequest(t, http.MethodPut, testURL, oneByte)
	badRewind.GetBody = func() (io.ReadCloser, error) { return errBody{}, nil }
	badRewindClose := newRequest(t, http.MethodPut, testURL, oneByte)
	badRewindClose.GetBody = func() (io.ReadCloser, error) { return closeFails{strings.NewReader(oneByte)}, nil }
	for name, r := range map[string]*http.Request{
		"unreadable body": unreadable, "unclosable body": unclosable, "GetBody error": noRewind,
		"GetBody reader error": badRewind, "GetBody close error": badRewindClose,
	} {
		want := bodyAfterFailedSign(r)
		assertSignFailed(t, name, r, s.Sign(t.Context(), r), errBoom, "errBoom", want)
	}
}

// bodyAfterFailedSign returns the body r keeps once Sign fails on it: its own
// with GetBody, else http.NoBody, as the package comment states.
func bodyAfterFailedSign(r *http.Request) io.ReadCloser {
	if r.GetBody == nil {
		return http.NoBody
	}
	return r.Body
}

// assertSignFailed fails t unless err, of a Sign of r, wraps ErrInvalidBody and
// cause, named causeName, and r has no header and the body want.
func assertSignFailed(t *testing.T, name string, r *http.Request, err, cause error, causeName string,
	want io.ReadCloser,
) {
	t.Helper()
	if !errors.Is(err, ErrInvalidBody) || !errors.Is(err, cause) || len(r.Header) != 0 || r.Body != want {
		t.Errorf("%s: err = %v, headers %v, body %T; want ErrInvalidBody, %s, no header and the body %T",
			name, err, r.Header, r.Body, causeName, want)
	}
}

func TestSignerSignBodyLimit(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	for _, size := range []int{mib, mib + 1} {
		body := strings.Repeat("a", size)
		buffered := newRequest(t, http.MethodPut, testURL, "")
		buffered.Body = io.NopCloser(strings.NewReader(body))
		for name, r := range map[string]*http.Request{
			"GetBody": newRequest(t, http.MethodPut, testURL, body), "buffered": buffered,
		} {
			want := bodyAfterFailedSign(r)
			err := s.Sign(t.Context(), r)
			if size > mib {
				assertSignFailed(t, name+" over 1 MiB", r, err, errBodyTooLarge, "errBodyTooLarge", want)
			} else if err != nil || r.Header.Get(HeaderSignature) == "" {
				t.Errorf("%s of 1 MiB: err = %v, want a signature", name, err)
			}
		}
	}
}

func ExampleNewSigner() {
	mux := http.NewServeMux()
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	const capacity, window = 8192, 5 * time.Minute
	key := secret.New("an example key of at least 32 bytes")

	store, err := NewMemoryStore(capacity)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := NewVerifier(key, store, WithWindow(window))
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/api/", verifier.Middleware(apiHandler))

	signer, err := NewSigner(key)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: cred.NewTransport(nil, signer)}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/api/orders?id=7", strings.NewReader(`{"qty":1}`))
	if err != nil {
		fmt.Println(err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err = resp.Body.Close(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.StatusCode)
	// Output: 204
}

// The allocations of a signature, one string for the values and one array for
// their header slices, and of the signature of a body, which adds the two of the
// copy GetBody returns.
const (
	signAllocs     = 2
	signBodyAllocs = signAllocs + 2
)

func TestSignerSignAllocs(t *testing.T) {
	s := newTestSigner(t)
	for _, tc := range []struct {
		body   string
		allocs float64
	}{{"", signAllocs}, {body4KiB(), signBodyAllocs}} {
		r := newRequest(t, http.MethodPost, "https://api.example/v1/items?page=2", tc.body)
		assertAllocs(t, tc.allocs, func() {
			if err := s.Sign(t.Context(), r); err != nil {
				t.Fatalf("Sign(%d-byte body) = %v, want nil", len(tc.body), err)
			}
		})
	}
	// The copy GetBody returns, and nothing for the refusal, built once.
	over := newRequest(t, http.MethodPost, "https://api.example/v1/items", strings.Repeat("x", maxBodyBytes+1))
	assertAllocs(t, signBodyAllocs-signAllocs, func() {
		if err := s.Sign(t.Context(), over); !errors.Is(err, ErrInvalidBody) || !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("Sign(body over 1 MiB) = %v, want ErrInvalidBody wrapping errBodyTooLarge", err)
		}
	})
}

func BenchmarkSignerSign(b *testing.B) {
	s := newTestSigner(b)
	for _, bc := range []struct{ name, body string }{{"no body", ""}, {"4 KiB body", body4KiB()}} {
		r := newRequest(b, http.MethodPost, "https://api.example/v1/items?page=2", bc.body)
		b.Run(bc.name, func(b *testing.B) {
			if err := s.Sign(b.Context(), r); err != nil {
				b.Fatalf("Sign = %v, want nil", err)
			}
			if err := newTestVerifier(b).Verify(b.Context(), r); err != nil {
				b.Fatalf("Verify(signed request) = %v, want nil", err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := s.Sign(b.Context(), r); err != nil {
					b.Fatalf("Sign = %v, want nil", err)
				}
			}
		})
	}
}

// BenchmarkSignerSignParallel signs a bodiless request on every goroutine, all
// sharing the Signer's MAC pool.
func BenchmarkSignerSignParallel(b *testing.B) {
	s := newTestSigner(b)
	r := newRequest(b, http.MethodGet, "https://api.example/v1/items?page=2", "")
	if err := s.Sign(b.Context(), r); err != nil {
		b.Fatalf("Sign = %v, want nil", err)
	}
	if err := newTestVerifier(b).Verify(b.Context(), r); err != nil {
		b.Fatalf("Verify(signed request) = %v, want nil", err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		own := r.Clone(b.Context())
		for pb.Next() {
			if err := s.Sign(b.Context(), own); err != nil {
				b.Errorf("Sign = %v, want nil", err)
				return
			}
		}
	})
}
