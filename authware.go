package authware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	defaultKeyHeaderName = "X-Api-Key"
	defaultRealm         = "restricted"
)

var (
	errBearerTokenRequired = errors.New("auth bearer mode requires a token")
	errAPIKeyRequired      = errors.New("auth apikey mode requires a key")
	errMTLSConfigRequired  = errors.New("auth mtls mode requires MTLSAllowedSubjects or MTLSAllowedSPKIPins")
	errMTLSPinSize         = errors.New("auth mtls SPKI pin must be 32 bytes (SHA-256)")
	errUnsupportedAuthMode = errors.New("unsupported auth mode")
)

// New creates an [Authenticator] from the provided configuration.
// client is consulted by [ModeOAuth] for JWKS fetching; nil installs a
// default. New does not mutate the caller's Config: a shallow copy is
// taken before normalisation.
func New(cfg *Config, client *http.Client) (Authenticator, error) {
	var c Config
	if cfg != nil {
		c = *cfg
	}
	normaliseConfig(&c)
	switch c.Mode {
	case ModeNone:
		return allowAllAuthenticator{}, nil
	case ModeBearer:
		if c.BearerToken == "" {
			return nil, errBearerTokenRequired
		}
		return &bearerAuthenticator{realm: c.Realm, token: c.BearerToken}, nil
	case ModeAPIKey:
		if c.APIKey == "" {
			return nil, errAPIKeyRequired
		}
		return &apiKeyAuthenticator{realm: c.Realm, header: c.APIKeyHeader, value: c.APIKey}, nil
	case ModeOAuth:
		return newOAuthAuthenticator(&c, client)
	case ModeMTLS:
		return newMTLSAuthenticator(&c)
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedAuthMode, c.Mode)
	}
}

func normaliseConfig(cfg *Config) {
	cfg.Mode = normaliseMode(inferMode(cfg))
	cfg.Realm = strings.TrimSpace(cfg.Realm)
	if cfg.Realm == "" {
		cfg.Realm = defaultRealm
	}
	cfg.APIKeyHeader = strings.TrimSpace(cfg.APIKeyHeader)
	if cfg.APIKeyHeader == "" {
		cfg.APIKeyHeader = defaultKeyHeaderName
	}
	cfg.APIKeyHeader = http.CanonicalHeaderKey(cfg.APIKeyHeader)
	cfg.OAuthIssuer = strings.TrimRight(cfg.OAuthIssuer, "/")
	cfg.OAuthRequiredScopes = cleanValues(cfg.OAuthRequiredScopes)
	cfg.OAuthAuthorizationServers = cleanValues(cfg.OAuthAuthorizationServers)
	cfg.MTLSAllowedSubjects = cleanValues(cfg.MTLSAllowedSubjects)
}

// normaliseMode lowercases m without allocating when the string is
// already the canonical form of one of the supported modes.
func normaliseMode(m Mode) Mode {
	trimmed := strings.TrimSpace(string(m))
	switch trimmed {
	case "", string(ModeNone):
		return ModeNone
	case string(ModeBearer):
		return ModeBearer
	case string(ModeAPIKey):
		return ModeAPIKey
	case string(ModeOAuth):
		return ModeOAuth
	case string(ModeMTLS):
		return ModeMTLS
	}
	return Mode(strings.ToLower(trimmed))
}

func inferMode(cfg *Config) Mode {
	if m := Mode(strings.TrimSpace(string(cfg.Mode))); m != "" {
		return m
	}
	switch {
	case cfg.OAuthIssuer != "" || cfg.OAuthJWKSURL != "" || cfg.OAuthHMACSecret != "":
		return ModeOAuth
	case len(cfg.MTLSAllowedSubjects) > 0 || len(cfg.MTLSAllowedSPKIPins) > 0:
		return ModeMTLS
	case cfg.APIKey != "":
		return ModeAPIKey
	case cfg.BearerToken != "":
		return ModeBearer
	default:
		return ModeNone
	}
}

// cleanValues trims, drops empty, and de-duplicates values while
// preserving input order. Order matters for OAuthAuthorizationServers
// (probed in order).
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
	return cleaned
}
