package authware

import (
	"os"
	"strings"
)

// ConfigFromEnv reads authentication configuration from environment
// variables. This is intended for building standalone auth-check servers
// or configuring authentication in containerized deployments.
//
// Environment variables:
//
//   - AUTH_MODE: none|bearer|apikey|oauth
//   - AUTH_REALM: realm for WWW-Authenticate header (default: restricted)
//   - AUTH_BEARER_TOKEN: static bearer token
//   - AUTH_API_KEY: static API key
//   - AUTH_API_KEY_HEADER: custom header name for API key (default: X-API-Key)
//   - AUTH_OAUTH_ISSUER: OAuth issuer URL
//   - AUTH_OAUTH_AUDIENCE: expected audience claim
//   - AUTH_OAUTH_JWKS_URL: JWKS endpoint (auto-discovered via OIDC if empty)
//   - AUTH_OAUTH_HMAC_SECRET: HMAC shared secret (testing only)
//   - AUTH_OAUTH_REQUIRED_SCOPES: comma-separated required scopes
//   - AUTH_OAUTH_RESOURCE: protected resource identifier (RFC 9728)
//   - AUTH_OAUTH_RESOURCE_DOCUMENTATION: resource documentation URL
//   - AUTH_OAUTH_RESOURCE_NAME: human-readable resource name
//   - AUTH_OAUTH_AUTHORIZATION_SERVERS: comma-separated authorization server URLs
func ConfigFromEnv() *Config {
	return &Config{
		Mode:                       os.Getenv("AUTH_MODE"),
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
		OAuthRequiredScopes:        splitCSV(os.Getenv("AUTH_OAUTH_REQUIRED_SCOPES")),
		OAuthAuthorizationServers:  splitCSV(os.Getenv("AUTH_OAUTH_AUTHORIZATION_SERVERS")),
	}
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
