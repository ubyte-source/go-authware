package authware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthCheckHandler_Success(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "tok"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := AuthCheckHandler(auth)

	req := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("X-Auth-Subject") != "static-bearer" {
		t.Fatalf("X-Auth-Subject = %q", rec.Header().Get("X-Auth-Subject"))
	}
	if rec.Header().Get("X-Auth-Method") != ModeBearer {
		t.Fatalf("X-Auth-Method = %q", rec.Header().Get("X-Auth-Method"))
	}
}

func TestAuthCheckHandler_Unauthorized(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "tok"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := AuthCheckHandler(auth)

	req := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAuthCheckHandler_OAuth_WWWAuthenticate(t *testing.T) {
	auth, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://iss.example.com", OAuthHMACSecret: "s",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := AuthCheckHandler(auth)

	req := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestAuthCheckHandler_Scopes(t *testing.T) {
	mock := &mockAuthenticator{
		identity: Identity{Subject: "user", Method: ModeOAuth, Scopes: "read write"},
	}
	handler := AuthCheckHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("X-Auth-Scopes") != "read write" {
		t.Fatalf("X-Auth-Scopes = %q", rec.Header().Get("X-Auth-Scopes"))
	}
}

func TestAuthCheckHandler_NoScopes(t *testing.T) {
	mock := &mockAuthenticator{
		identity: Identity{Subject: "user", Method: ModeBearer},
	}
	handler := AuthCheckHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("X-Auth-Scopes") != "" {
		t.Fatalf("expected no X-Auth-Scopes header, got %q", rec.Header().Get("X-Auth-Scopes"))
	}
}

// mockAuthenticator is a test helper for handler tests.
type mockAuthenticator struct {
	err      error
	identity Identity
}

func (m *mockAuthenticator) Authenticate(_ *http.Request) (Identity, error) {
	return m.identity, m.err
}

func (m *mockAuthenticator) Challenge(err error, url string) (code int, scheme, params string) {
	return challengeFromError("test", err, url)
}

func (m *mockAuthenticator) Metadata(_ string) *ProtectedResourceMetadata {
	return nil
}
