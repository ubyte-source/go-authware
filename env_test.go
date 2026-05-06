package authware

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func testConfigFromEnvSetAll(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_MODE", "oauth")
	t.Setenv("AUTH_REALM", "test-realm")
	t.Setenv("AUTH_BEARER_TOKEN", "my-token")
	t.Setenv("AUTH_API_KEY", testMyKey)
	t.Setenv("AUTH_API_KEY_HEADER", "X-Custom-Key")
	t.Setenv("AUTH_OAUTH_ISSUER", testIssuerURL)
	t.Setenv("AUTH_OAUTH_AUDIENCE", "my-api")
	t.Setenv("AUTH_OAUTH_JWKS_URL", testJWKSURL)
	t.Setenv("AUTH_OAUTH_HMAC_SECRET", "hmac-secret")
	t.Setenv("AUTH_OAUTH_REQUIRED_SCOPES", "read,write")
	t.Setenv("AUTH_OAUTH_RESOURCE", "https://api.example.com")
	t.Setenv("AUTH_OAUTH_RESOURCE_DOCUMENTATION", "https://docs.example.com")
	t.Setenv("AUTH_OAUTH_RESOURCE_NAME", "My API")
	t.Setenv("AUTH_OAUTH_CLIENT_ID", "proxy-client-id")
	t.Setenv("AUTH_OAUTH_CLIENT_SECRET", "proxy-client-secret")
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
	if cfg.APIKey != testMyKey {
		t.Fatalf("APIKey = %q", cfg.APIKey)
	}
	if cfg.APIKeyHeader != "X-Custom-Key" {
		t.Fatalf("APIKeyHeader = %q", cfg.APIKeyHeader)
	}
}

func TestConfigFromEnv_OAuth(t *testing.T) {
	testConfigFromEnvSetAll(t)
	cfg := ConfigFromEnv()
	if cfg.OAuthIssuer != testIssuerURL {
		t.Fatalf("OAuthIssuer = %q", cfg.OAuthIssuer)
	}
	if cfg.OAuthAudience != "my-api" {
		t.Fatalf("OAuthAudience = %q", cfg.OAuthAudience)
	}
	if cfg.OAuthJWKSURL != testJWKSURL {
		t.Fatalf("OAuthJWKSURL = %q", cfg.OAuthJWKSURL)
	}
	if cfg.OAuthHMACSecret != "hmac-secret" {
		t.Fatalf("OAuthHMACSecret = %q", cfg.OAuthHMACSecret)
	}
	scopes := cfg.OAuthRequiredScopes
	if len(scopes) != 2 || scopes[0] != testRead || scopes[1] != testWrite {
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

func TestConfigFromEnv_Proxy(t *testing.T) {
	testConfigFromEnvSetAll(t)
	cfg := ConfigFromEnv()
	if cfg.OAuthClientID != "proxy-client-id" {
		t.Fatalf("OAuthClientID = %q", cfg.OAuthClientID)
	}
	if cfg.OAuthClientSecret != "proxy-client-secret" {
		t.Fatalf("OAuthClientSecret = %q", cfg.OAuthClientSecret)
	}
}

func TestConfigFromEnv_ProxyRoundTrip(t *testing.T) {
	testConfigFromEnvSetAll(t)
	cfg := ConfigFromEnv()
	p := NewOAuthProxy(cfg, nil)
	if p == nil {
		t.Fatal("NewOAuthProxy returned nil")
	}
	if p.clientID != "proxy-client-id" {
		t.Fatalf("proxy clientID = %q", p.clientID)
	}
	if p.clientSecret != "proxy-client-secret" {
		t.Fatalf("proxy clientSecret = %q", p.clientSecret)
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

func TestConfigFromEnv_MTLS(t *testing.T) {
	pin := make([]byte, 32)
	for i := range pin {
		pin[i] = byte(i)
	}
	t.Setenv("AUTH_MTLS_ALLOWED_SUBJECTS", "client-a,client-b")
	t.Setenv("AUTH_MTLS_SPKI_PINS", base64.StdEncoding.EncodeToString(pin))
	cfg := ConfigFromEnv()
	if len(cfg.MTLSAllowedSubjects) != 2 {
		t.Fatalf("MTLSAllowedSubjects = %v", cfg.MTLSAllowedSubjects)
	}
	if len(cfg.MTLSAllowedSPKIPins) != 1 {
		t.Fatalf("MTLSAllowedSPKIPins = %v", cfg.MTLSAllowedSPKIPins)
	}
	if !bytes.EqualFold(cfg.MTLSAllowedSPKIPins[0], pin) {
		t.Fatalf("decoded pin mismatch")
	}
}

func TestConfigFromEnv_Secure(t *testing.T) {
	setSecureEnv(t)
	cfg := ConfigFromEnv()
	checkSecureRequestLimits(t, cfg)
	checkSecureHeaders(t, cfg)
	checkSecureCSRF(t, cfg)
}

func setSecureEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_SECURE_MAX_BYTES", "1048576")
	t.Setenv("AUTH_SECURE_HSTS_MAX_AGE", "300")
	t.Setenv("AUTH_SECURE_HSTS_SUBS", "true")
	t.Setenv("AUTH_SECURE_HSTS_PRELOAD", "true")
	t.Setenv("AUTH_SECURE_CSP", "default-src 'self'")
	t.Setenv("AUTH_SECURE_FRAME_OPTIONS", testFrameDeny)
	t.Setenv("AUTH_SECURE_NOSNIFF", "true")
	t.Setenv("AUTH_SECURE_REFERRER_POLICY", testReferrerNone)
	t.Setenv("AUTH_SECURE_PERMISSIONS_POLICY", "geolocation=()")
	t.Setenv("AUTH_SECURE_XSS_PROTECTION", "0")
	t.Setenv("AUTH_SECURE_CSRF_TRUSTED", "https://a.example,https://b.example")
}

func checkSecureRequestLimits(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.SecureMaxRequestBytes != 1048576 {
		t.Fatalf("SecureMaxRequestBytes = %d", cfg.SecureMaxRequestBytes)
	}
}

func checkSecureHeaders(t *testing.T, cfg *Config) {
	t.Helper()
	want := SecureHeadersConfig{
		HSTSMaxAge:         300,
		HSTSIncludeSubs:    true,
		HSTSPreload:        true,
		CSP:                "default-src 'self'",
		FrameOptions:       testFrameDeny,
		ContentTypeNosniff: true,
		ReferrerPolicy:     testReferrerNone,
		PermissionsPolicy:  "geolocation=()",
		XSSProtection:      "0",
	}
	if cfg.SecureHeaders != want {
		t.Fatalf("SecureHeaders mismatch:\n got %+v\nwant %+v", cfg.SecureHeaders, want)
	}
}

func checkSecureCSRF(t *testing.T, cfg *Config) {
	t.Helper()
	if len(cfg.SecureCSRFTrusted) != 2 {
		t.Fatalf("SecureCSRFTrusted = %v", cfg.SecureCSRFTrusted)
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

func TestEnvHelpers(t *testing.T) {
	t.Setenv("BENCH_INT", "42")
	t.Setenv("BENCH_INT64", "1099511627776")
	t.Setenv("BENCH_BOOL", "true")
	t.Setenv("BENCH_BAD", "xx")
	if envInt("BENCH_INT") != 42 {
		t.Fatal("envInt")
	}
	if envInt("BENCH_BAD") != 0 {
		t.Fatal("envInt fallback")
	}
	if envInt("BENCH_MISSING") != 0 {
		t.Fatal("envInt missing")
	}
	if envInt64("BENCH_INT64") != 1099511627776 {
		t.Fatal("envInt64")
	}
	if envInt64("BENCH_BAD") != 0 {
		t.Fatal("envInt64 fallback")
	}
	if !envBool("BENCH_BOOL") {
		t.Fatal("envBool")
	}
	if envBool("BENCH_BAD") {
		t.Fatal("envBool fallback")
	}
	if envBool("BENCH_MISSING") {
		t.Fatal("envBool missing")
	}
}
