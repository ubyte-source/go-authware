package authware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

// makeHS256Token creates a minimal valid HS256 JWT for benchmarks.
func makeHS256Token(b *testing.B, issuer, secret string) string {
	b.Helper()
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	cb := jsonfast.Acquire()
	cb.BeginObject()
	cb.AddStringField("sub", "bench-user")
	cb.AddStringField("iss", issuer)
	cb.AddStringField("aud", "bench")
	cb.AddStringField("scope", "read write")
	cb.AddInt64Field("iat", now.Unix())
	cb.AddInt64Field("nbf", now.Add(-time.Minute).Unix())
	cb.AddInt64Field("exp", now.Add(time.Hour).Unix())
	cb.EndObject()
	payload := base64.RawURLEncoding.EncodeToString(cb.Bytes())
	jsonfast.Release(cb)
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// BenchmarkBearer measures the hot path for static bearer token auth.
func BenchmarkBearer(b *testing.B) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "supersecrettoken"}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer supersecrettoken")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBearerFail measures the rejection path (wrong token).
func BenchmarkBearerFail(b *testing.B) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "supersecrettoken"}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer wrongtoken12345")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := auth.Authenticate(req); err == nil {
			b.Fatal("expected auth failure")
		}
	}
}

// BenchmarkAPIKey measures the hot path for static API key auth via custom header.
func BenchmarkAPIKey(b *testing.B) {
	apiVal := "bench-" + strings.Repeat("x", 32) // generated value: not a real credential
	auth, err := New(&Config{Mode: ModeAPIKey, APIKey: apiVal}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-API-Key", apiVal)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAPIKeyAuthorizationHeader measures API key via Authorization header.
func BenchmarkAPIKeyAuthorizationHeader(b *testing.B) {
	apiVal := "bench-" + strings.Repeat("x", 32) // generated value: not a real credential
	auth, err := New(&Config{Mode: ModeAPIKey, APIKey: apiVal}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "ApiKey "+apiVal)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNone measures the allow-all path (no auth).
func BenchmarkNone(b *testing.B) {
	auth, err := New(&Config{Mode: ModeNone}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOAuthHMAC_HS256 measures the JWT HMAC validation hot path.
// This is the most critical path for high-throughput log pipelines using pre-shared secrets.
func BenchmarkOAuthHMAC_HS256(b *testing.B) {
	const issuer = "https://issuer.example.com"
	const secret = "bench-secret-key"
	token := makeHS256Token(b, issuer, secret)

	auth, err := New(&Config{
		Mode:            ModeOAuth,
		OAuthIssuer:     issuer,
		OAuthAudience:   "bench",
		OAuthHMACSecret: secret,
	}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHasRequiredScopes measures the scope check.
func BenchmarkHasRequiredScopes(b *testing.B) {
	have := "admin mcp:read mcp:write read write"
	required := []string{"mcp:read", "read"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !hasRequiredScopes(have, required) {
			b.Fatal("unexpected false")
		}
	}
}

// BenchmarkSecureEqual measures constant-time string comparison.
func BenchmarkSecureEqual(b *testing.B) {
	a := strings.Repeat("x", 64)
	c := strings.Repeat("x", 64)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = secureEqual(a, c)
	}
}

// BenchmarkProxy_RegisterHandler measures the DCR shim handler throughput.
func BenchmarkProxy_RegisterHandler(b *testing.B) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "bench-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := p.RegisterHandler()
	body := `{"client_name":"bench"}`
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkProxy_ASMetadata measures AS metadata handler throughput (cached path).
func BenchmarkProxy_ASMetadata(b *testing.B) {
	fakeAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{` +
			`"issuer":"https://fake.example.com",` +
			`"authorization_endpoint":"https://fake.example.com/authorize",` +
			`"token_endpoint":"https://fake.example.com/token"}`)); err != nil {
			b.Errorf("write: %v", err)
		}
	}))
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "bench-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	handler := p.ASMetadataHandler()
	// Warm up the cache (sync.Once).
	warmup := httptest.NewRecorder()
	handler.ServeHTTP(warmup, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if warmup.Code != http.StatusOK {
		b.Fatalf("warmup failed: %d", warmup.Code)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	}
}

// BenchmarkProxy_TokenHandler measures the token proxy handler throughput.
func BenchmarkProxy_TokenHandler(b *testing.B) {
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"access_token":"t","token_type":"Bearer"}`)); err != nil {
			b.Errorf("write: %v", err)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "bench-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.upstreamTokenEndpoint = fakeToken.URL

	handler := p.TokenHandler()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader("grant_type=authorization_code&code=bench"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkMiddleware_Bearer measures the full middleware stack with bearer auth.
func BenchmarkMiddleware_Bearer(b *testing.B) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "tok"}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(auth)(inner)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
