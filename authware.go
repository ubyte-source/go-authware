package authware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

var (
	errBearerTokenRequired = errors.New("auth bearer mode requires a token")
	errAPIKeyRequired      = errors.New("auth apikey mode requires a key")
	errUnsupportedAuthMode = errors.New("unsupported auth mode")
)

// Supported authentication modes.
const (
	ModeNone   = "none"
	ModeBearer = "bearer"
	ModeAPIKey = "apikey"
	ModeOAuth  = "oauth"

	defaultKeyHeaderName = "X-API-Key"
	defaultRealm         = "restricted"
)

// IdentityFromContext returns the authenticated identity from the request
// context. Returns the zero value and false if the request was not authenticated.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

// WithIdentity returns a copy of ctx carrying the given Identity.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// Middleware returns an HTTP middleware that authenticates every request.
// On success the Identity is stored in the request context; on failure
// the appropriate HTTP status and challenge header are returned.
func Middleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := auth.Authenticate(r)
			if err != nil {
				status, header, message := auth.Challenge(err, "")
				if header != "" {
					w.Header().Set("WWW-Authenticate", header)
				}
				http.Error(w, message, status)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}

// RequireScopes returns an HTTP middleware that verifies the authenticated
// identity (from context) possesses all the specified scopes.
// Must be applied after Middleware.
func RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	// Sort once at construction for deterministic error messages.
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	slices.Sort(sorted)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := IdentityFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !hasRequiredScopes(id.Scopes, sorted) {
				http.Error(w, "missing required scope", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// New creates an Authenticator from the provided configuration.
func New(cfg *Config, client *http.Client) (Authenticator, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	normalizeConfig(cfg)
	if cfg.Mode == ModeOAuth {
		return newOAuthAuthenticator(cfg, client)
	}
	return newStaticAuthenticator(cfg)
}

func newStaticAuthenticator(cfg *Config) (Authenticator, error) {
	switch cfg.Mode {
	case ModeNone:
		return allowAllAuthenticator{}, nil
	case ModeBearer:
		if cfg.BearerToken == "" {
			return nil, errBearerTokenRequired
		}
		return &bearerAuthenticator{
			realm: cfg.Realm,
			token: cfg.BearerToken,
		}, nil
	case ModeAPIKey:
		if cfg.APIKey == "" {
			return nil, errAPIKeyRequired
		}
		return &apiKeyAuthenticator{realm: cfg.Realm, header: cfg.APIKeyHeader, value: cfg.APIKey}, nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedAuthMode, cfg.Mode)
	}
}

func normalizeConfig(cfg *Config) {
	cfg.Mode = strings.ToLower(strings.TrimSpace(inferMode(cfg)))
	cfg.Realm = strings.TrimSpace(cfg.Realm)
	if cfg.Realm == "" {
		cfg.Realm = defaultRealm
	}
	cfg.APIKeyHeader = strings.TrimSpace(cfg.APIKeyHeader)
	if cfg.APIKeyHeader == "" {
		cfg.APIKeyHeader = defaultKeyHeaderName
	}
	cfg.APIKeyHeader = http.CanonicalHeaderKey(cfg.APIKeyHeader)
	cfg.OAuthRequiredScopes = cleanValues(cfg.OAuthRequiredScopes)
	cfg.OAuthAuthorizationServers = cleanValues(cfg.OAuthAuthorizationServers)
}

func inferMode(cfg *Config) string {
	if strings.TrimSpace(cfg.Mode) != "" {
		return cfg.Mode
	}
	switch {
	case cfg.OAuthIssuer != "" || cfg.OAuthJWKSURL != "" || cfg.OAuthHMACSecret != "":
		return ModeOAuth
	case cfg.APIKey != "":
		return ModeAPIKey
	case cfg.BearerToken != "":
		return ModeBearer
	default:
		return ModeNone
	}
}

func cleanValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	slices.Sort(cleaned)
	return cleaned
}
