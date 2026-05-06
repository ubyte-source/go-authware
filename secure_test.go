package authware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaxBytes_Enforced(t *testing.T) {
	hit := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Error("expected size error from MaxBytesReader")
		}
		http.Error(w, "too big", http.StatusRequestEntityTooLarge)
	})
	handler := MaxBytes(8)(inner)
	body := strings.NewReader("0123456789")
	req := newReq(t, http.MethodPost, "/", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !hit {
		t.Fatal("inner handler not called")
	}
}

func TestMaxBytes_Passthrough_OnZero(t *testing.T) {
	handler := MaxBytes(0)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newReq(t, http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSecurityHeaders_AllSet(t *testing.T) {
	handler := SecurityHeaders(&SecureHeadersConfig{
		HSTSMaxAge:         31536000,
		HSTSIncludeSubs:    true,
		HSTSPreload:        true,
		CSP:                "default-src 'self'",
		FrameOptions:       testFrameDeny,
		ContentTypeNosniff: true,
		ReferrerPolicy:     testReferrerNone,
		PermissionsPolicy:  "geolocation=()",
		XSSProtection:      "0",
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newReq(t, http.MethodGet, "/", http.NoBody))

	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Frame-Options":           testFrameDeny,
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           testReferrerNone,
		"Permissions-Policy":        "geolocation=()",
		"X-Xss-Protection":          "0",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestSecurityHeaders_Empty_Passthrough(t *testing.T) {
	called := false
	handler := SecurityHeaders(&SecureHeadersConfig{})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newReq(t, http.MethodGet, "/", http.NoBody))
	if !called {
		t.Fatal("expected pass-through")
	}
}

func TestSecurityHeaders_HSTSOnlyWithMaxAge(t *testing.T) {
	mw := SecurityHeaders(&SecureHeadersConfig{HSTSMaxAge: 60})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newReq(t, http.MethodGet, "/", http.NoBody))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=60" {
		t.Fatalf("HSTS = %q", got)
	}
}

func TestCSRF_BypassPath(t *testing.T) {
	called := false
	mw, err := CSRF(CSRFOptions{BypassPaths: []string{"/safe"}})
	if err != nil {
		t.Fatalf("CSRF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := newReq(t, http.MethodPost, "/safe", strings.NewReader("x=y"))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("bypass path should pass through")
	}
}

func TestCSRF_TrustedOriginsAccepted(t *testing.T) {
	if _, err := CSRF(CSRFOptions{TrustedOrigins: []string{testHTTPS}}); err != nil {
		t.Fatalf("CSRF: %v", err)
	}
}

func TestCSRF_RejectsBadOrigin(t *testing.T) {
	if _, err := CSRF(CSRFOptions{TrustedOrigins: []string{"not a url"}}); err == nil {
		t.Fatal("expected error for malformed trusted origin")
	}
}

// BenchmarkSecurityHeaders measures the per-request set of pre-computed headers.
func BenchmarkSecurityHeaders(b *testing.B) {
	handler := SecurityHeaders(&SecureHeadersConfig{
		HSTSMaxAge:         31536000,
		HSTSIncludeSubs:    true,
		ContentTypeNosniff: true,
		ReferrerPolicy:     testReferrerNone,
		FrameOptions:       testFrameDeny,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	rec := newNopWriter()
	b.ReportAllocs()

	for b.Loop() {
		rec.reset()
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMaxBytes measures the wrapper overhead on a small body.
func BenchmarkMaxBytes(b *testing.B) {
	handler := MaxBytes(1024)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	rec := newNopWriter()
	b.ReportAllocs()

	for b.Loop() {
		rec.reset()
		handler.ServeHTTP(rec, req)
	}
}
