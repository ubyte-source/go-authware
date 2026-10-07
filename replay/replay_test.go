package replay

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// prefix is the text the append tests append to.
const prefix = "x"

func TestErrRejected(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		ErrMissingHeaders, ErrMalformedHeaders, ErrTimestampSkew,
		ErrInvalidBody, ErrInvalidSignature, ErrNonceReplayed,
	} {
		if !errors.Is(err, ErrRejected) {
			t.Errorf("errors.Is(%v, ErrRejected) = false, want true", err)
		}
	}
	for _, err := range []error{ErrShortKey, ErrInvalidOption, errNilStore, ErrInvalidCapacity} {
		if !errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrRejected) ||
			!strings.HasPrefix(err.Error(), "replay: invalid config: ") {
			t.Errorf("%v: want ErrInvalidConfig alone, named by replay", err)
		}
	}
	if errors.Is(ErrStoreFull, ErrRejected) || errors.Is(ErrStoreFull, ErrInvalidConfig) {
		t.Errorf("%v wraps ErrRejected or ErrInvalidConfig, want neither", ErrStoreFull)
	}
}

func TestNewMACScratch(t *testing.T) {
	t.Parallel()
	if _, err := newMACScratch(secret.New(testKeyRaw[1:])); !errors.Is(err, ErrShortKey) {
		t.Fatalf("31-byte key: err = %v, want ErrShortKey", err)
	}
	if _, err := newMACScratch(secret.Value{}); !errors.Is(err, ErrShortKey) {
		t.Fatalf("empty key: err = %v, want ErrShortKey", err)
	}
	k, err := newMACScratch(testKey())
	if err != nil {
		t.Fatalf("newMACScratch(32-byte key) = %v, want a MAC", err)
	}
	mac := hmac.New(sha256.New, []byte(testKeyRaw))
	_, _ = mac.Write([]byte("data"))
	if got := k.keyed.Sum(nil, []byte("data")); !hmac.Equal(got, mac.Sum(nil)) {
		t.Fatalf("MAC of data = %x, want the HMAC-SHA256 of the key", got)
	}
}

func TestMACScratchPut(t *testing.T) {
	t.Parallel()
	var k macScratch
	const pooledCap = 4 << 10
	for size, kept := range map[int]bool{pooledCap: true, pooledCap + 1: false} {
		st := &macState{buf: make([]byte, 0, size)}
		k.put(st)
		if (cap(st.buf) == size) != kept {
			t.Errorf("put(state with a %d-byte buffer) left %d bytes, want the buffer kept %t", size, cap(st.buf), kept)
		}
	}
}

// TestMACScratchKeyedSum signs the canonical input of a request with a body: the
// lines of input, then the timestamp and the nonce.
func TestMACScratchKeyedSum(t *testing.T) {
	t.Parallel()
	k, err := newMACScratch(testKey())
	if err != nil {
		t.Fatalf("newMACScratch = %v, want a MAC", err)
	}
	r := newRequest(t, http.MethodPost, "https://API.Example:8443/a%20b/c?x=%2F", "")
	st := k.get()
	defer k.put(st)
	body := sha256.Sum256([]byte(`{"a":1}`))
	input := append(st.input(r, &body), "1700000000\n000102030405060708090a0b0c0d0e0f"...)
	wantInput := "POST\napi.example:8443\n/a%20b/c?x=%2F\n" +
		"015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862\n" +
		"1700000000\n000102030405060708090a0b0c0d0e0f"
	if string(input) != wantInput {
		t.Fatalf("input = %q, want %q", input, wantInput)
	}
	const wantSig = "dd9afc784100a61e9ec23c1b5e78f794975ffe1dcb70aa082f9545bb3fd08442"
	if sig := hex.EncodeToString(k.keyedSum(st, input)); sig != wantSig {
		t.Fatalf("sig = %s, want %s", sig, wantSig)
	}
}

// TestHasBody decides which requests carry a body as the package comment states:
// none with a nil Body or http.NoBody, nor a server request whose ContentLength is 0.
func TestHasBody(t *testing.T) {
	t.Parallel()
	server := func(body io.Reader) *http.Request {
		return httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/p", body)
	}
	for _, tc := range []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"client, nil Body", &http.Request{}, false},
		{"client, http.NoBody", &http.Request{Body: http.NoBody}, false},
		{"client, Body of unknown length", &http.Request{Body: io.NopCloser(strings.NewReader(oneByte))}, true},
		{"client, Body of length 1", &http.Request{Body: io.NopCloser(strings.NewReader(oneByte)), ContentLength: 1},
			true},
		{"server, http.NoBody", server(nil), false},
		{"server, ContentLength 0", server(strings.NewReader("")), false},
		{"server, unknown length", server(iotest.OneByteReader(strings.NewReader(oneByte))), true},
		{"server, ContentLength 1", server(strings.NewReader(oneByte)), true},
	} {
		if got := hasBody(tc.r); got != tc.want {
			t.Errorf("package comment: \"a request has no body when its Body is nil or http.NoBody, or when it is "+
				"a server request, RequestURI set, whose ContentLength is 0\": %s (RequestURI %q, ContentLength %d): "+
				"hasBody = %t, want %t", tc.name, tc.r.RequestURI, tc.r.ContentLength, got, tc.want)
		}
	}
}

// TestMACStateInputDefaults builds the input of a request without a method,
// Host or body: it names GET, the URL host and the SHA-256 of an empty body.
func TestMACStateInputDefaults(t *testing.T) {
	t.Parallel()
	r := newRequest(t, http.MethodGet, "https://URL.example/", "")
	r.Method, r.Host = "", ""
	var st macState
	empty := sha256.Sum256(nil)
	if got, want := string(st.input(r, nil)), "GET\nurl.example\n/\n"+hex.EncodeToString(empty[:])+"\n"; got != want {
		t.Fatalf("input = %q, want %q", got, want)
	}
	r.Method, r.Host = http.MethodDelete, "Header.example"
	if got, want := string(st.input(r, nil)), "DELETE\nheader.example\n/\n"; !strings.HasPrefix(got, want) {
		t.Fatalf("input = %q, want it to start with %q", got, want)
	}
}

// wireHost returns the Host a server reads from a request net/http writes for
// host, and false when net/http refuses to write it.
func wireHost(host string) (string, bool) {
	r := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "http", Host: host, Path: "/"}, Host: host}
	var wire bytes.Buffer
	if r.Write(&wire) != nil {
		return "", false
	}
	got, err := http.ReadRequest(bufio.NewReader(&wire))
	if err != nil {
		return "", false
	}
	return got.Host, true
}

// TestAppendHost appends the host net/http sends for a host, lowercased: an
// IPv6 literal loses its zone, the last "%" before the last "]".
func TestAppendHost(t *testing.T) {
	t.Parallel()
	for _, host := range []string{
		"API.Example:8443", "a.example:", "[FE80::1%eth0]:8080", "[fe80::1%en0]", "[::1]:80", "[a%b%c]:1",
		"[a%b]%c", "[%]", "[fe80::1%en0", "x%y", "x%y]:80", "[]", "",
	} {
		wire, ok := wireHost(host)
		if !ok {
			t.Fatalf("net/http refused the host %q, want it written", host)
		}
		if got, want := string(appendHost([]byte(prefix), host)), prefix+strings.ToLower(wire); got != want {
			t.Errorf("appendHost(%q) = %q, want %q, the host net/http sends lowercased", host, got, want)
		}
	}
}

// FuzzAppendHost checks appendHost against the reference for every host, and
// against the host net/http sends for every valid ASCII host: net/http sends an
// invalid one empty.
func FuzzAppendHost(f *testing.F) {
	for _, seed := range []string{
		"a.example:80", "[fe80::1%en0]:80", "[a%b%c]:1", "[a%b]%c", "[x", "x%y]:80", "a b", "[\xff%\n]",
		"AZ@[`{.Example",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		got := string(appendHost(nil, host))
		if want := referenceHost(host); got != want {
			t.Fatalf("appendHost(%q) = %q, want %q, the reference", host, got, want)
		}
		wire, ok := wireHost(host)
		nonASCII := strings.ContainsFunc(host, func(c rune) bool { return c >= utf8.RuneSelf })
		if !ok || (wire == "" && host != "") || nonASCII {
			return
		}
		if want := strings.ToLower(wire); got != want {
			t.Fatalf("appendHost(%q) = %q, want %q, the host net/http sends lowercased", host, got, want)
		}
	})
}

func TestAppendRequestURI(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://a.example", "https://a.example/p?", "https://a.example/a%2Fb?x=%2F&y", "http:opaque?q", "*",
		"https://a.example//x", "mailto:user@example.com",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q) = %v, want a URL", raw, err)
		}
		if got, want := string(appendRequestURI([]byte(prefix), u)), prefix+u.RequestURI(); got != want {
			t.Errorf("appendRequestURI(%q) = %q, want %q", raw, got, want)
		}
	}
	for _, u := range []*url.URL{
		{Opaque: "//host/p", Scheme: "https", RawQuery: "a=1"}, {Path: "/a b", ForceQuery: true},
	} {
		query, force := u.RawQuery, u.ForceQuery
		if got, want := string(appendRequestURI(nil, u)), u.RequestURI(); got != want || u.RawQuery != query ||
			u.ForceQuery != force {
			t.Errorf("appendRequestURI(%#v) = %q, want %q and the URL untouched", u, got, want)
		}
	}
}

func TestAppendRequestURIAllocs(t *testing.T) {
	u, err := url.Parse("https://a.example/v1/items?page=2")
	if err != nil {
		t.Fatalf("Parse = %v, want a URL", err)
	}
	b := make([]byte, 0, 64)
	assertAllocs(t, 0, func() { b = appendRequestURI(b[:0], u) })
	if string(b) != u.RequestURI() {
		t.Fatalf("appendRequestURI = %q, want %q: the query joins in b", b, u.RequestURI())
	}
}

// BenchmarkAppendRequestURI appends the request URI of a URL with a query, and
// the string URL.RequestURI returns for it.
func BenchmarkAppendRequestURI(b *testing.B) {
	u, err := url.Parse("https://a.example/v1/items?page=2")
	if err != nil {
		b.Fatalf("Parse = %v, want a URL", err)
	}
	want := u.RequestURI()
	dst := make([]byte, 0, len(want))
	for _, bc := range []struct {
		name      string
		appendURI func([]byte, *url.URL) []byte
	}{
		{"appendRequestURI", appendRequestURI},
		{"URL.RequestURI", func(buf []byte, target *url.URL) []byte { return append(buf, target.RequestURI()...) }},
	} {
		b.Run(bc.name, func(b *testing.B) {
			if got := string(bc.appendURI(dst[:0], u)); got != want {
				b.Fatalf("%s = %q, want %q", bc.name, got, want)
			}
			b.ReportAllocs()
			for b.Loop() {
				dst = bc.appendURI(dst[:0], u)
			}
		})
	}
}

// FuzzAppendRequestURI checks appendRequestURI against URL.RequestURI for
// every URL that parses, the form of a request target included.
func FuzzAppendRequestURI(f *testing.F) {
	for _, seed := range []string{"https://a.example/p?q", "/p?", "http:o?q", "*", "/a%2Fb", "//h/p?x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		for _, parse := range []func(string) (*url.URL, error){url.Parse, url.ParseRequestURI} {
			u, err := parse(raw)
			if err != nil {
				continue
			}
			if got, want := string(appendRequestURI([]byte(prefix), u)), prefix+u.RequestURI(); got != want {
				t.Fatalf("appendRequestURI(%q) = %q, want %q", raw, got, want)
			}
		}
	})
}

func TestAppendLower(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"":                 "",
		"API.Example:8443": "api.example:8443",
		"az@[`{ÄZ":         "az@[`{Äz",
	} {
		if got := string(appendLower([]byte(prefix), in)); got != prefix+want {
			t.Errorf("appendLower(%q) = %q, want %q", in, got, prefix+want)
		}
	}
}

// BenchmarkAppendLower appends a host with upper-case letters lowercased, and
// the string strings.ToLower returns for it.
func BenchmarkAppendLower(b *testing.B) {
	const host, want = "API.Example:8443", "api.example:8443"
	dst := make([]byte, 0, len(want))
	for _, bc := range []struct {
		name  string
		lower func([]byte, string) []byte
	}{
		{"appendLower", appendLower},
		{"strings.ToLower", func(buf []byte, s string) []byte { return append(buf, strings.ToLower(s)...) }},
	} {
		b.Run(bc.name, func(b *testing.B) {
			if got := string(bc.lower(dst[:0], host)); got != want {
				b.Fatalf("%s = %q, want %q", bc.name, got, want)
			}
			b.ReportAllocs()
			for b.Loop() {
				dst = bc.lower(dst[:0], host)
			}
		})
	}
}
