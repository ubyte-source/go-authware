package authware

import "net/http"

// Config defines the supported HTTP authentication modes.
type Config struct {
	Mode                       string
	Realm                      string
	BearerToken                string
	APIKey                     string
	APIKeyHeader               string
	OAuthIssuer                string
	OAuthAudience              string
	OAuthJWKSURL               string
	OAuthHMACSecret            string
	OAuthResource              string
	OAuthResourceDocumentation string
	OAuthResourceName          string
	OAuthClientID              string // upstream IdP client_id returned by the built-in DCR shim
	OAuthRequiredScopes        []string
	OAuthAuthorizationServers  []string
}

// Identity describes the authenticated caller.
type Identity struct {
	Subject string
	Method  string
	Scopes  string
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
