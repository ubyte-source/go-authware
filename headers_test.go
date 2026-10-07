package authware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const frameDeny = "DENY"

// An HSTS max-age and a header the security headers set.
const (
	hstsAge            = 60
	headerFrameOptions = "X-Frame-Options"
)

func TestSecurityHeaders(t *testing.T) {
	mw := SecurityHeaders(&SecurityHeadersConfig{
		HSTSMaxAge: 31536000, HSTSIncludeSubDomains: true, HSTSPreload: true, CSP: "default-src 'self'",
		FrameOptions: frameDeny, ContentTypeNosniff: true, ReferrerPolicy: "no-referrer",
		PermissionsPolicy: "geolocation=()",
	})
	first := true
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if first {
			w.Header()[headerFrameOptions][0] = "SAMEORIGIN"
			first = false
		}
	}))
	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		"Content-Security-Policy":   "default-src 'self'",
		headerFrameOptions:          frameDeny,
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Permissions-Policy":        "geolocation=()",
	}
	h.ServeHTTP(httptest.NewRecorder(), newReq(t, http.MethodGet, pathRoot, http.NoBody))
	appended := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k := range want {
			w.Header().Add(k, "added")
		}
	}))
	w := httptest.NewRecorder()
	appended.ServeHTTP(w, newReq(t, http.MethodGet, pathRoot, http.NoBody))
	for k, v := range want {
		if got := w.Header().Values(k); !slices.Equal(got, []string{v, "added"}) {
			t.Fatalf("%s after Add = %q, want [%s added]", k, got, v)
		}
	}
	for range 2 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newReq(t, http.MethodGet, pathRoot, http.NoBody))
		if len(w.Header()) != len(want) {
			t.Fatalf("headers = %v, want %v", w.Header(), want)
		}
		for k, v := range want {
			if got := w.Header().Get(k); got != v {
				t.Fatalf("%s = %q, want %q", k, got, v)
			}
		}
	}
}

func TestSecurityHeadersReplaces(t *testing.T) {
	h := SecurityHeaders(&SecurityHeadersConfig{FrameOptions: frameDeny})(http.NotFoundHandler())
	w := httptest.NewRecorder()
	w.Header().Set(headerFrameOptions, "SAMEORIGIN")
	h.ServeHTTP(w, newReq(t, http.MethodGet, pathRoot, http.NoBody))
	if got := w.Header().Values(headerFrameOptions); !slices.Equal(got, []string{frameDeny}) {
		t.Fatalf("X-Frame-Options = %q, want only %q", got, frameDeny)
	}
}

func TestSecurityHeadersPassthrough(t *testing.T) {
	next := http.NotFoundHandler()
	for _, cfg := range []*SecurityHeadersConfig{nil, {}} {
		if got := SecurityHeaders(cfg)(next); fmt.Sprint(got) != fmt.Sprint(next) {
			t.Fatalf("SecurityHeaders(%v)(next) = %v, want next unchanged", cfg, got)
		}
	}
}

func TestPassthrough(t *testing.T) {
	next := http.NotFoundHandler()
	if got := passthrough(next); fmt.Sprint(got) != fmt.Sprint(next) {
		t.Fatalf("passthrough(next) = %v, want next", got)
	}
}

// TestBuildSecurityHeadersShortestHSTS writes HSTS from a max age of one second.
func TestBuildSecurityHeadersShortestHSTS(t *testing.T) {
	got := buildSecurityHeaders(&SecurityHeadersConfig{HSTSMaxAge: 1})
	if len(got) != 1 || got[0] != (headerKV{"Strict-Transport-Security", "max-age=1"}) {
		t.Fatalf("buildSecurityHeaders(1s HSTS) = %v, want max-age=1", got)
	}
}

func TestBuildHSTS(t *testing.T) {
	for cfg, want := range map[SecurityHeadersConfig]string{
		{HSTSMaxAge: hstsAge}:                              "max-age=60",
		{HSTSMaxAge: hstsAge, HSTSIncludeSubDomains: true}: "max-age=60; includeSubDomains",
		{HSTSMaxAge: hstsAge, HSTSPreload: true}:           "max-age=60; preload",
	} {
		if got := buildHSTS(&cfg); got != want {
			t.Errorf("buildHSTS = %q, want %q", got, want)
		}
	}
}

func ExampleSecurityHeaders() {
	apiHandler := http.NotFoundHandler()
	headers := SecurityHeaders(&SecurityHeadersConfig{
		HSTSMaxAge:            31536000,
		HSTSIncludeSubDomains: true,
		ContentTypeNosniff:    true,
		FrameOptions:          "DENY",
		ReferrerPolicy:        "no-referrer",
	})
	handler := headers(apiHandler)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, pathRoot, http.NoBody))
	fmt.Println(w.Header().Get("Strict-Transport-Security"), w.Header().Get(headerFrameOptions))
	// Output: max-age=31536000; includeSubDomains DENY
}

func BenchmarkSecurityHeaders(b *testing.B) {
	h := SecurityHeaders(&SecurityHeadersConfig{HSTSMaxAge: 31536000, ContentTypeNosniff: true,
		FrameOptions: frameDeny})(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	r := newReq(b, http.MethodGet, pathRoot, http.NoBody)
	w := newBenchWriter()
	h.ServeHTTP(w, r)
	if got := w.headers.Get(headerFrameOptions); got != frameDeny {
		b.Fatalf("X-Frame-Options = %q, want %q", got, frameDeny)
	}
	b.ReportAllocs()
	for b.Loop() {
		w.reset()
		h.ServeHTTP(w, r)
	}
}

// dirtyTail is long enough that a builder not grown first would reallocate.
const dirtyTail = 62

func TestSanitizeHeaderValue(t *testing.T) {
	for in, want := range map[string]string{
		"a\r\nb\x00c\x1f\x7fd é~": "a  b c  d é~",
		"clean é~":                "clean é~",
		"\x7f":                    " ",
		"":                        "",
	} {
		if got := sanitizeHeaderValue(in); got != want {
			t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", in, got, want)
		}
	}
	assertAllocs(t, 0, func() { sanitizeHeaderValue("clean value") })
	dirty := "a\n" + strings.Repeat("b", dirtyTail)
	assertAllocs(t, 1, func() { sanitizeHeaderValue(dirty) })
}

// FuzzSanitizeHeaderValue checks every control byte becomes a space and every
// other byte is kept.
func FuzzSanitizeHeaderValue(f *testing.F) {
	for _, seed := range []string{"clean", "with\rCR", "with\nLF", "\x00null", "\x1f\x7f\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeHeaderValue(in)
		if len(out) != len(in) {
			t.Fatalf("sanitizeHeaderValue(%q) = %q, want the same length", in, out)
		}
		for i := range len(in) {
			want := in[i]
			if want < 0x20 || want == 0x7F {
				want = ' '
			}
			if out[i] != want {
				t.Fatalf("sanitizeHeaderValue(%q) byte %d = %q, want %q", in, i, out[i], want)
			}
		}
	})
}
