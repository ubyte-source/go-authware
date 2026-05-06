package authware

import (
	"net/http"
	"strings"
	"testing"
)

func TestAPIKeyAuthenticator_HeaderMatch(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue, APIKeyHeader: "X-Test-Key"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "https://example.com/api", http.NoBody)
	req.Header.Set("X-Test-Key", apiKeyValue)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeAPIKey {
		t.Fatal("expected apikey identity")
	}
	if id.Subject != "static-apikey" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

func TestAPIKeyAuthenticator_AuthorizationScheme(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "ApiKey "+apiKeyValue)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeAPIKey {
		t.Fatalf("Method = %q", id.Method)
	}
}

func TestAPIKeyAuthenticator_WrongHeader(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Api-Key", "wrong")
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestAPIKeyAuthenticator_WrongAuthScheme(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "ApiKey wrong")
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestAPIKeyAuthenticator_Challenge(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := &authError{status: http.StatusUnauthorized, message: testFail, scheme: schemeBearer, code: "invalid_token"}
	status, _, msg := a.Challenge(aErr, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if msg != testFail {
		t.Fatalf("message = %q", msg)
	}
}

func TestAPIKeyAuthenticator_Metadata(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if md := a.Metadata(testHTTPS); md != nil {
		t.Fatalf("expected nil metadata, got %+v", md)
	}
}

// TestAPIKeyAuthenticator_FallsBackToAuthorization verifies that when the
// configured key header is present but wrong, the authenticator still tries
// the Authorization: ApiKey scheme as a fallback.
func TestAPIKeyAuthenticator_FallsBackToAuthorization(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Api-Key", "wrong-value")
	req.Header.Set("Authorization", "ApiKey "+apiKeyValue)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("expected success via Authorization fallback: %v", err)
	}
	if id.Method != ModeAPIKey {
		t.Fatalf("Method = %q", id.Method)
	}
}

func TestAPIKeyAuthenticator_BothWrong(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Api-Key", "wrong")
	req.Header.Set("Authorization", "ApiKey wrong")
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected auth failure when both headers have wrong value")
	}
}

func TestSecureEqual(t *testing.T) {
	if !secureEqual("abc", "abc") {
		t.Fatal("expected equal")
	}
	if secureEqual("abc", "xyz") {
		t.Fatal("expected not equal")
	}
	if secureEqual("abc", "ab") {
		t.Fatal("expected not equal for different lengths")
	}
	if secureEqual("", "a") {
		t.Fatal("expected not equal for empty vs non-empty")
	}
	if !secureEqual("", "") {
		t.Fatal("expected equal for both empty")
	}
}

// BenchmarkAPIKey measures the API key hot path via custom header.
func BenchmarkAPIKey(b *testing.B) {
	apiVal := "bench-" + strings.Repeat("x", 32)
	auth, err := New(&Config{Mode: ModeAPIKey, APIKey: apiVal}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Api-Key", apiVal)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAPIKeyAuthorizationHeader measures API key via Authorization header.
func BenchmarkAPIKeyAuthorizationHeader(b *testing.B) {
	apiVal := "bench-" + strings.Repeat("x", 32)
	auth, err := New(&Config{Mode: ModeAPIKey, APIKey: apiVal}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "ApiKey "+apiVal)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSecureEqual measures constant-time string comparison.
func BenchmarkSecureEqual(b *testing.B) {
	a := strings.Repeat("x", 64)
	c := strings.Repeat("x", 64)
	b.ReportAllocs()

	for b.Loop() {
		_ = secureEqual(a, c)
	}
}
