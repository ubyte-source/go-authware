package authware

import (
	"testing"
)

func testConfigFromEnvSetAll(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_MODE", "oauth")
	t.Setenv("AUTH_REALM", "test-realm")
	t.Setenv("AUTH_BEARER_TOKEN", "my-token")
	t.Setenv("AUTH_API_KEY", "my-key")
	t.Setenv("AUTH_API_KEY_HEADER", "X-Custom-Key")
	t.Setenv("AUTH_OAUTH_ISSUER", "https://issuer.example.com")
	t.Setenv("AUTH_OAUTH_AUDIENCE", "my-api")
	t.Setenv("AUTH_OAUTH_JWKS_URL", "https://issuer.example.com/jwks")
	t.Setenv("AUTH_OAUTH_HMAC_SECRET", "hmac-secret")
	t.Setenv("AUTH_OAUTH_REQUIRED_SCOPES", "read,write")
	t.Setenv("AUTH_OAUTH_RESOURCE", "https://api.example.com")
	t.Setenv("AUTH_OAUTH_RESOURCE_DOCUMENTATION", "https://docs.example.com")
	t.Setenv("AUTH_OAUTH_RESOURCE_NAME", "My API")
	t.Setenv("AUTH_OAUTH_AUTHORIZATION_SERVERS", "https://auth1.example.com,https://auth2.example.com")
}

func TestConfigFromEnv_General(t *testing.T) {
	testConfigFromEnvSetAll(t)
	cfg := ConfigFromEnv()
	if cfg.Mode != "oauth" {
		t.Fatalf("Mode = %q", cfg.Mode)
	}
	if cfg.Realm != "test-realm" {
		t.Fatalf("Realm = %q", cfg.Realm)
	}
	if cfg.BearerToken != "my-token" {
		t.Fatalf("BearerToken = %q", cfg.BearerToken)
	}
	if cfg.APIKey != "my-key" {
		t.Fatalf("APIKey = %q", cfg.APIKey)
	}
	if cfg.APIKeyHeader != "X-Custom-Key" {
		t.Fatalf("APIKeyHeader = %q", cfg.APIKeyHeader)
	}
}

func TestConfigFromEnv_OAuth(t *testing.T) {
	testConfigFromEnvSetAll(t)
	cfg := ConfigFromEnv()
	if cfg.OAuthIssuer != "https://issuer.example.com" {
		t.Fatalf("OAuthIssuer = %q", cfg.OAuthIssuer)
	}
	if cfg.OAuthAudience != "my-api" {
		t.Fatalf("OAuthAudience = %q", cfg.OAuthAudience)
	}
	if cfg.OAuthJWKSURL != "https://issuer.example.com/jwks" {
		t.Fatalf("OAuthJWKSURL = %q", cfg.OAuthJWKSURL)
	}
	if cfg.OAuthHMACSecret != "hmac-secret" {
		t.Fatalf("OAuthHMACSecret = %q", cfg.OAuthHMACSecret)
	}
	scopes := cfg.OAuthRequiredScopes
	if len(scopes) != 2 || scopes[0] != "read" || scopes[1] != "write" {
		t.Fatalf("OAuthRequiredScopes = %v", scopes)
	}
}

func TestConfigFromEnv_ResourceMetadata(t *testing.T) {
	testConfigFromEnvSetAll(t)
	cfg := ConfigFromEnv()
	if cfg.OAuthResource != "https://api.example.com" {
		t.Fatalf("OAuthResource = %q", cfg.OAuthResource)
	}
	if cfg.OAuthResourceDocumentation != "https://docs.example.com" {
		t.Fatalf("OAuthResourceDocumentation = %q", cfg.OAuthResourceDocumentation)
	}
	if cfg.OAuthResourceName != "My API" {
		t.Fatalf("OAuthResourceName = %q", cfg.OAuthResourceName)
	}
	if len(cfg.OAuthAuthorizationServers) != 2 {
		t.Fatalf("OAuthAuthorizationServers = %v", cfg.OAuthAuthorizationServers)
	}
}

func TestConfigFromEnv_Empty(t *testing.T) {
	cfg := ConfigFromEnv()
	if cfg.Mode != "" {
		t.Fatalf("Mode = %q", cfg.Mode)
	}
	if cfg.OAuthRequiredScopes != nil {
		t.Fatalf("OAuthRequiredScopes = %v", cfg.OAuthRequiredScopes)
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"a,b,c", 3},
		{" a , b , c ", 3},
		{",,,", 0},
		{"single", 1},
	}
	for _, tt := range tests {
		got := splitCSV(tt.input)
		if tt.want == 0 && got != nil {
			t.Fatalf("splitCSV(%q) = %v, want nil", tt.input, got)
		}
		if tt.want > 0 && len(got) != tt.want {
			t.Fatalf("splitCSV(%q) = %v, want len %d", tt.input, got, tt.want)
		}
	}
}
