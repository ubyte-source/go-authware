package authware

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

// Mode names a supported HTTP authentication scheme.
type Mode string

// Supported authentication modes.
const (
	ModeNone   Mode = "none"
	ModeBearer Mode = "bearer"
	ModeAPIKey Mode = "apikey"
	ModeOAuth  Mode = "oauth"
	ModeMTLS   Mode = "mtls"
)

// Config selects the authentication mode and carries its parameters.
type Config struct {
	OAuthHTTPClient *http.Client

	OAuthJWKSURL               string
	OAuthHMACSecret            string
	OAuthClientSecret          string
	OAuthAudience              string
	Mode                       Mode
	Realm                      string
	OAuthResourceName          string
	APIKey                     string
	APIKeyHeader               string
	OAuthIssuer                string
	OAuthResourceDocumentation string
	BearerToken                string
	OAuthClientID              string
	OAuthResource              string

	OAuthRequiredScopes       []string
	OAuthAuthorizationServers []string
	MTLSAllowedSubjects       []string
	MTLSAllowedSPKIPins       [][]byte
	SecureCSRFTrusted         []string

	SecureHeaders SecureHeadersConfig

	OAuthClockSkewTolerance time.Duration
	OAuthJWKSCacheTTL       time.Duration
	SecureMaxRequestBytes   int64
	OAuthProxyFetchTimeout  time.Duration
}

// Identity describes the authenticated caller. Static modes return a
// shared singleton; OAuth and mTLS allocate per request. Identity must
// be treated as read-only.
type Identity struct {
	PeerCert  *x509.Certificate
	Subject   string
	Method    Mode
	claimsRaw string
	Scopes    []string
}

// Claim returns the named JWT claim decoded into a Go value: string,
// int64, float64, bool, nil, or the raw JSON for objects/arrays.
func (id *Identity) Claim(name string) (any, bool) {
	if id == nil || id.claimsRaw == "" {
		return nil, false
	}
	raw, ok := jsonfast.FindFieldString(id.claimsRaw, name)
	if !ok {
		return nil, false
	}
	return decodeClaimValue(raw), true
}

// ClaimString returns the named string claim.
func (id *Identity) ClaimString(name string) (string, bool) {
	raw, ok := id.rawField(name)
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	return jsonfast.DecodeString(raw)
}

// ClaimInt64 returns the named integer claim.
func (id *Identity) ClaimInt64(name string) (int64, bool) {
	raw, ok := id.rawField(name)
	if !ok {
		return 0, false
	}
	return jsonfast.DecodeInt64(raw)
}

// ClaimBool returns the named boolean claim.
func (id *Identity) ClaimBool(name string) (value, ok bool) {
	raw, found := id.rawField(name)
	if !found {
		return false, false
	}
	return jsonfast.DecodeBool(raw)
}

// ClaimFloat64 returns the named numeric claim as a float.
func (id *Identity) ClaimFloat64(name string) (float64, bool) {
	raw, ok := id.rawField(name)
	if !ok {
		return 0, false
	}
	return jsonfast.DecodeFloat64(raw)
}

func (id *Identity) rawField(name string) ([]byte, bool) {
	if id == nil || id.claimsRaw == "" {
		return nil, false
	}
	return jsonfast.FindFieldString(id.claimsRaw, name)
}

// RangeClaims iterates every top-level JWT claim. The name is valid only
// for the duration of the callback; clone via strings.Clone to retain.
func (id *Identity) RangeClaims(fn func(name string, value any) bool) bool {
	if id == nil || id.claimsRaw == "" {
		return true
	}
	return jsonfast.IterateFieldsString(id.claimsRaw, func(key, value []byte) bool {
		if len(key) < 2 || key[0] != '"' || key[len(key)-1] != '"' {
			return true
		}
		return fn(string(key[1:len(key)-1]), decodeClaimValue(value))
	})
}

// ProtectedResourceMetadata is the Protected Resource Metadata document
// served by [oauthAuthenticator.Metadata].
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// Authenticator validates an inbound HTTP request.
type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
	Challenge(err error, resourceMetadataURL string) (status int, header, message string)
	Metadata(resource string) *ProtectedResourceMetadata
}

// SecureHeadersConfig configures the [SecurityHeaders] middleware.
type SecureHeadersConfig struct {
	CSP                string
	FrameOptions       string
	ReferrerPolicy     string
	PermissionsPolicy  string
	XSSProtection      string
	HSTSMaxAge         int
	HSTSIncludeSubs    bool
	HSTSPreload        bool
	ContentTypeNosniff bool
}

type contextKey struct{}

type authError struct {
	message string
	code    string
	scheme  string
	scope   string
	status  int
}

func (e *authError) Error() string { return e.message }
