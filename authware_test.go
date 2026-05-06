package authware

import (
	"net/http"
	"strings"
	"testing"
)

func TestNewNilConfig(t *testing.T) {
	a, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		want Mode
		cfg  Config
	}{
		{cfg: Config{Mode: schemeBearer}, name: "explicit mode", want: ModeBearer},
		{cfg: Config{OAuthIssuer: testClaimIss, OAuthHMACSecret: "s"}, name: "infer oauth from issuer", want: ModeOAuth},
		{cfg: Config{OAuthJWKSURL: "url", OAuthIssuer: testClaimIss}, name: "infer oauth from jwks", want: ModeOAuth},
		{cfg: Config{OAuthHMACSecret: "s", OAuthIssuer: testClaimIss}, name: "infer oauth from hmac", want: ModeOAuth},
		{cfg: Config{MTLSAllowedSubjects: []string{"CN=client"}}, name: "infer mtls from subjects", want: ModeMTLS},
		{cfg: Config{MTLSAllowedSPKIPins: [][]byte{make([]byte, 32)}}, name: "infer mtls from pins", want: ModeMTLS},
		{cfg: Config{APIKey: testKey}, name: "infer apikey", want: ModeAPIKey},
		{cfg: Config{BearerToken: testTok}, name: "infer bearer", want: ModeBearer},
		{cfg: Config{}, name: "default none", want: ModeNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferMode(&tt.cfg)
			if Mode(strings.ToLower(strings.TrimSpace(string(got)))) != tt.want {
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
		{"mtls no allowlist", Config{Mode: ModeMTLS}},
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
	// cleanValues preserves input order so callers like OAuthProxy can
	// rely on AuthorizationServers fail-over priority.
	got := cleanValues([]string{"b", " a ", "b", "", " c "})
	if len(got) != 3 || got[0] != "b" || got[1] != "a" || got[2] != "c" {
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
		{cfg: &Config{Mode: ModeBearer, BearerToken: testTok}, name: "bearer"},
		{cfg: &Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, name: "apikey"},
		{cfg: &Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{"client"}}, name: "mtls"},
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

func TestDefaultAPIKeyHeader(t *testing.T) {
	apiKeyValue := strings.Repeat("k", 12)
	a, err := New(&Config{Mode: ModeAPIKey, APIKey: apiKeyValue}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Api-Key", apiKeyValue)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeAPIKey {
		t.Fatalf("Method = %q", id.Method)
	}
}

func TestDefaultRealm(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := unauthorisedError("bad")
	_, header, _ := a.Challenge(aErr, "")
	if !strings.Contains(header, "restricted") {
		t.Fatalf("expected 'restricted' realm in header, got %q", header)
	}
}

func TestNormalizeConfig_OAuthIssuerTrailingSlash(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com/"}
	normaliseConfig(cfg)
	if cfg.OAuthIssuer != testIssuerURL {
		t.Fatalf("OAuthIssuer = %q, want no trailing slash", cfg.OAuthIssuer)
	}
}

func TestNormalizeConfig_OAuthIssuerMultipleTrailingSlashes(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com///"}
	normaliseConfig(cfg)
	if cfg.OAuthIssuer != testIssuerURL {
		t.Fatalf("OAuthIssuer = %q, want trailing slashes stripped", cfg.OAuthIssuer)
	}
}

func TestNormalizeConfig_OAuthIssuerNoTrailingSlash(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL}
	normaliseConfig(cfg)
	if cfg.OAuthIssuer != testIssuerURL {
		t.Fatalf("OAuthIssuer = %q, want unchanged", cfg.OAuthIssuer)
	}
}
