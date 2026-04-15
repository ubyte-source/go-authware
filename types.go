package authware

import "net/http"

// Config defines the supported HTTP authentication modes.
type Config struct {
	// Mode is the authentication mode: "none", "bearer", "apikey", or "oauth".
	Mode string
	// Realm is the realm included in WWW-Authenticate challenges (default: "restricted").
	Realm string
	// BearerToken is the expected static bearer token (bearer mode only).
	BearerToken string
	// APIKey is the expected static API key value (apikey mode only).
	APIKey string
	// APIKeyHeader is the request header that carries the API key (default: "X-API-Key").
	APIKeyHeader string
	// OAuthIssuer is the token issuer URL; must match the "iss" claim (oauth mode).
	OAuthIssuer string
	// OAuthAudience is the required audience claim; empty means any audience is accepted.
	OAuthAudience string
	// OAuthJWKSURL overrides the JWKS endpoint; auto-discovered via OIDC if empty.
	OAuthJWKSURL string
	// OAuthHMACSecret enables HMAC (HS256/HS384/HS512) validation with a shared secret.
	// Intended for testing only; prefer asymmetric keys in production.
	OAuthHMACSecret string
	// OAuthResource is the protected resource URI served in RFC 9728 metadata.
	OAuthResource string
	// OAuthResourceDocumentation is the URL of the resource documentation,
	// included in RFC 9728 metadata when non-empty.
	OAuthResourceDocumentation string
	// OAuthResourceName is the human-readable resource name included in RFC 9728 metadata.
	OAuthResourceName string
	// OAuthClientID is the upstream IdP client_id returned by the built-in DCR shim.
	OAuthClientID string
	// OAuthClientSecret is the upstream IdP client_secret for confidential-client token exchange.
	OAuthClientSecret string
	// OAuthRequiredScopes lists the scopes every token must possess.
	OAuthRequiredScopes []string
	// OAuthAuthorizationServers lists the authorization server URLs advertised in
	// RFC 9728 metadata and used for OIDC discovery.
	OAuthAuthorizationServers []string
}

// Identity describes the authenticated caller.
type Identity struct {
	// Subject is the authenticated principal: the "sub" claim, or "client_id"/"azp" as fallback.
	Subject string
	// Method is the authentication mode that produced this identity (e.g. ModeOAuth, ModeBearer).
	Method string
	// Scopes is the space-separated list of OAuth scopes granted to this identity.
	Scopes string
}

// ProtectedResourceMetadata is served from RFC 9728 metadata discovery endpoints.
type ProtectedResourceMetadata struct {
	Resource              string   `json:"resource"`
	ResourceDocumentation string   `json:"resource_documentation,omitempty"`
	ResourceName          string   `json:"resource_name,omitempty"`
	AuthorizationServers  []string `json:"authorization_servers,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`

	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// Authenticator validates an inbound HTTP request.
type Authenticator interface {
	// Authenticate returns the authenticated identity or an error.
	Authenticate(r *http.Request) (Identity, error)
	// Challenge returns the HTTP status, WWW-Authenticate header, and error message.
	Challenge(err error, resourceMetadataURL string) (status int, header string, message string)
	// Metadata returns RFC 9728 Protected Resource Metadata, or nil if not applicable.
	Metadata(resource string) *ProtectedResourceMetadata
}

// contextKey is the context.Value key for storing Identity.
type contextKey struct{}

// authError carries structured error details for WWW-Authenticate challenge generation.
type authError struct {
	message string
	code    string
	scheme  string
	scope   string
	status  int
}

func (e *authError) Error() string {
	return e.message
}
