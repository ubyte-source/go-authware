package authware

import (
	"encoding/base64"
	"os"
	"strconv"
	"strings"
)

// ConfigFromEnv reads AUTH_* environment variables into a [Config].
//
// Recognized variables:
//
//	AUTH_MODE                            none|bearer|apikey|oauth|mtls
//	AUTH_REALM                           realm for WWW-Authenticate
//	AUTH_BEARER_TOKEN                    static bearer token
//	AUTH_API_KEY                         static API key
//	AUTH_API_KEY_HEADER                  custom header name (default X-Api-Key)
//	AUTH_OAUTH_ISSUER                    OAuth issuer URL
//	AUTH_OAUTH_AUDIENCE                  expected audience claim
//	AUTH_OAUTH_JWKS_URL                  JWKS endpoint (auto-discovered if empty)
//	AUTH_OAUTH_HMAC_SECRET               HMAC shared secret (testing only)
//	AUTH_OAUTH_REQUIRED_SCOPES           comma-separated required scopes
//	AUTH_OAUTH_RESOURCE                  protected resource identifier
//	AUTH_OAUTH_RESOURCE_DOCUMENTATION    resource documentation URL
//	AUTH_OAUTH_RESOURCE_NAME             human-readable resource name
//	AUTH_OAUTH_CLIENT_ID                 upstream client_id (proxy DCR shim)
//	AUTH_OAUTH_CLIENT_SECRET             upstream client_secret
//	AUTH_OAUTH_AUTHORIZATION_SERVERS     comma-separated AS URLs
//	AUTH_MTLS_ALLOWED_SUBJECTS           comma-separated CNs
//	AUTH_MTLS_SPKI_PINS                  comma-separated base64 SHA-256 pins
//	AUTH_SECURE_MAX_BYTES                int64 request body cap
//	AUTH_SECURE_HSTS_MAX_AGE             HSTS max-age (seconds)
//	AUTH_SECURE_HSTS_SUBS                bool, includeSubDomains
//	AUTH_SECURE_HSTS_PRELOAD             bool, preload
//	AUTH_SECURE_CSP                      Content-Security-Policy
//	AUTH_SECURE_FRAME_OPTIONS            DENY|SAMEORIGIN
//	AUTH_SECURE_NOSNIFF                  bool, X-Content-Type-Options
//	AUTH_SECURE_REFERRER_POLICY          Referrer-Policy
//	AUTH_SECURE_PERMISSIONS_POLICY       Permissions-Policy
//	AUTH_SECURE_XSS_PROTECTION           X-XSS-Protection
//	AUTH_SECURE_CSRF_TRUSTED             comma-separated trusted origins
func ConfigFromEnv() *Config {
	return &Config{
		Mode:                       Mode(os.Getenv("AUTH_MODE")),
		Realm:                      os.Getenv("AUTH_REALM"),
		BearerToken:                os.Getenv("AUTH_BEARER_TOKEN"),
		APIKey:                     os.Getenv("AUTH_API_KEY"),
		APIKeyHeader:               os.Getenv("AUTH_API_KEY_HEADER"),
		OAuthIssuer:                os.Getenv("AUTH_OAUTH_ISSUER"),
		OAuthAudience:              os.Getenv("AUTH_OAUTH_AUDIENCE"),
		OAuthJWKSURL:               os.Getenv("AUTH_OAUTH_JWKS_URL"),
		OAuthHMACSecret:            os.Getenv("AUTH_OAUTH_HMAC_SECRET"),
		OAuthResource:              os.Getenv("AUTH_OAUTH_RESOURCE"),
		OAuthResourceDocumentation: os.Getenv("AUTH_OAUTH_RESOURCE_DOCUMENTATION"),
		OAuthResourceName:          os.Getenv("AUTH_OAUTH_RESOURCE_NAME"),
		OAuthClientID:              os.Getenv("AUTH_OAUTH_CLIENT_ID"),
		OAuthClientSecret:          os.Getenv("AUTH_OAUTH_CLIENT_SECRET"),
		OAuthRequiredScopes:        splitCSV(os.Getenv("AUTH_OAUTH_REQUIRED_SCOPES")),
		OAuthAuthorizationServers:  splitCSV(os.Getenv("AUTH_OAUTH_AUTHORIZATION_SERVERS")),
		MTLSAllowedSubjects:        splitCSV(os.Getenv("AUTH_MTLS_ALLOWED_SUBJECTS")),
		MTLSAllowedSPKIPins:        decodePinsCSV(os.Getenv("AUTH_MTLS_SPKI_PINS")),
		SecureMaxRequestBytes:      envInt64("AUTH_SECURE_MAX_BYTES"),
		SecureHeaders: SecureHeadersConfig{
			HSTSMaxAge:         envInt("AUTH_SECURE_HSTS_MAX_AGE"),
			HSTSIncludeSubs:    envBool("AUTH_SECURE_HSTS_SUBS"),
			HSTSPreload:        envBool("AUTH_SECURE_HSTS_PRELOAD"),
			CSP:                os.Getenv("AUTH_SECURE_CSP"),
			FrameOptions:       os.Getenv("AUTH_SECURE_FRAME_OPTIONS"),
			ContentTypeNosniff: envBool("AUTH_SECURE_NOSNIFF"),
			ReferrerPolicy:     os.Getenv("AUTH_SECURE_REFERRER_POLICY"),
			PermissionsPolicy:  os.Getenv("AUTH_SECURE_PERMISSIONS_POLICY"),
			XSSProtection:      os.Getenv("AUTH_SECURE_XSS_PROTECTION"),
		},
		SecureCSRFTrusted: splitCSV(os.Getenv("AUTH_SECURE_CSRF_TRUSTED")),
	}
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	var result []string
	for part := range strings.SplitSeq(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func decodePinsCSV(value string) [][]byte {
	parts := splitCSV(value)
	if len(parts) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		raw, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			continue
		}
		out = append(out, raw)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func envInt(key string) int {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

func envInt64(key string) int64 {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func envBool(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}
