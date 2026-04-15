package authware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewNilConfig(t *testing.T) {
	a, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeNone {
		t.Fatalf("Method = %q, want %q", id.Method, ModeNone)
	}
}

func TestInferMode(t *testing.T) {
	tests := []struct {
		name string
		want string
		cfg  Config
	}{
		{cfg: Config{Mode: "Bearer"}, name: "explicit mode", want: ModeBearer},
		{cfg: Config{OAuthIssuer: "iss", OAuthHMACSecret: "s"}, name: "infer oauth from issuer", want: ModeOAuth},
		{cfg: Config{OAuthJWKSURL: "url", OAuthIssuer: "iss"}, name: "infer oauth from jwks", want: ModeOAuth},
		{cfg: Config{OAuthHMACSecret: "s", OAuthIssuer: "iss"}, name: "infer oauth from hmac", want: ModeOAuth},
		{cfg: Config{APIKey: "key"}, name: "infer apikey", want: ModeAPIKey},
		{cfg: Config{BearerToken: "tok"}, name: "infer bearer", want: ModeBearer},
		{cfg: Config{}, name: "default none", want: ModeNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferMode(&tt.cfg)
			if strings.ToLower(strings.TrimSpace(got)) != tt.want {
				t.Fatalf("inferMode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewStaticAuthenticator_Errors(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"bearer no token", Config{Mode: ModeBearer}},
		{"apikey no key", Config{Mode: ModeAPIKey}},
		{"unsupported mode", Config{Mode: "magic"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(&tt.cfg, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCleanValues(t *testing.T) {
	got := cleanValues([]string{"b", " a ", "b", "", " c "})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("cleanValues = %v", got)
	}
	if result := cleanValues(nil); result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestMetadata_StaticReturnsNil(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	authenticators := []struct {
		cfg  *Config
		name string
	}{
		{cfg: &Config{Mode: ModeNone}, name: "none"},
		{cfg: &Config{Mode: ModeBearer, BearerToken: "tok"}, name: "bearer"},
		{cfg: &Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, name: "apikey"},
	}
	for _, tt := range authenticators {
		t.Run(tt.name, func(t *testing.T) {
			a, err := New(tt.cfg, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if md := a.Metadata("https://example.com"); md != nil {
				t.Fatalf("expected nil metadata for %s, got %+v", tt.name, md)
			}
		})
	}
}

func TestIdentityFromContext_Empty(t *testing.T) {
	if _, ok := IdentityFromContext(context.Background()); ok {
		t.Fatal("expected ok=false")
	}
}

func TestWithIdentity_Roundtrip(t *testing.T) {
	id := Identity{Subject: "user-1", Method: ModeBearer}
	ctx := WithIdentity(context.Background(), id)
	got, ok := IdentityFromContext(ctx)
	if !ok || got.Subject != "user-1" {
		t.Fatalf("roundtrip failed: %+v", got)
	}
}

func TestMiddleware_Success(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "tok"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := IdentityFromContext(r.Context())
		if !ok {
			t.Error("expected identity in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(auth)(inner)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMiddleware_Unauthorized(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	})

	handler := Middleware(auth)(inner)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_OAuth_SetsWWWAuthenticate(t *testing.T) {
	auth, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://iss.example.com", OAuthHMACSecret: "s",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	handler := Middleware(auth)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestRequireScopes_Allowed(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireScopes("read", "write")(inner)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		Subject: "u", Method: ModeOAuth, Scopes: "read write admin",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRequireScopes_Forbidden(t *testing.T) {
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	})

	handler := RequireScopes("admin")(inner)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		Subject: "u", Method: ModeOAuth, Scopes: "read",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireScopes_NoIdentity(t *testing.T) {
	handler := RequireScopes("read")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestDefaultAPIKeyHeader(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-API-Key", apiKeyValue)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeAPIKey {
		t.Fatalf("Method = %q", id.Method)
	}
}

func TestDefaultRealm(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: "tok"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := unauthorizedError("bad")
	_, header, _ := a.Challenge(aErr, "")
	if !strings.Contains(header, "restricted") {
		t.Fatalf("expected 'restricted' realm in header, got %q", header)
	}
}

func TestNormalizeConfig_OAuthIssuerTrailingSlash(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com/"}
	normalizeConfig(cfg)
	if cfg.OAuthIssuer != "https://issuer.example.com" {
		t.Fatalf("OAuthIssuer = %q, want no trailing slash", cfg.OAuthIssuer)
	}
}

func TestNormalizeConfig_OAuthIssuerMultipleTrailingSlashes(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com///"}
	normalizeConfig(cfg)
	if cfg.OAuthIssuer != "https://issuer.example.com" {
		t.Fatalf("OAuthIssuer = %q, want trailing slashes stripped", cfg.OAuthIssuer)
	}
}

func TestNormalizeConfig_OAuthIssuerNoTrailingSlash(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com"}
	normalizeConfig(cfg)
	if cfg.OAuthIssuer != "https://issuer.example.com" {
		t.Fatalf("OAuthIssuer = %q, want unchanged", cfg.OAuthIssuer)
	}
}
