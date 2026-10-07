package authware

import (
	"encoding/base64"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// envReader reads typed variables named prefix+key through lookup and
// records one problem per malformed one in p.
type envReader struct {
	lookup func(name string) string
	p      *problems.List
	prefix string
}

// ConfigFromEnv reads every Config field but HTTPClient and ErrorLog from its
// variable, preceded by prefix; in a list, a backslash keeps the next byte in
// the element. ErrInvalidConfig names each malformed variable, never its value.
func ConfigFromEnv(prefix string) (*Config, error) {
	e := envReader{lookup: os.Getenv, p: problems.New(ErrInvalidConfig), prefix: prefix}
	cfg := e.config()
	if err := e.p.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// EnvNames returns the name of the variable of every Config field but HTTPClient and
// ErrorLog, each preceded by prefix.
func EnvNames(prefix string) []string {
	var names []string
	record := func(name string) string {
		names = append(names, name)
		return ""
	}
	e := envReader{lookup: record, p: problems.New(ErrInvalidConfig), prefix: prefix}
	e.config()
	return names
}

// config builds the Config the variables describe, recording each malformed
// one.
func (e *envReader) config() *Config {
	return &Config{
		Mode:   Mode(e.str("AUTH_MODE")),
		Realm:  e.str("AUTH_REALM"),
		Bearer: BearerConfig{Token: e.secretValue("AUTH_BEARER_TOKEN")},
		APIKey: APIKeyConfig{Key: e.secretValue("AUTH_APIKEY"), Header: e.str("AUTH_APIKEY_HEADER")},
		OAuth:  e.oauth(),
		MTLS: MTLSConfig{
			AllowedSubjects: e.list("AUTH_MTLS_ALLOWED_SUBJECTS", ';'),
			AllowedSPKIPins: e.pins("AUTH_MTLS_SPKI_PINS"),
		},
	}
}

func (e *envReader) oauth() OAuthConfig {
	return OAuthConfig{
		Issuer:         e.str("AUTH_OAUTH_ISSUER"),
		Audience:       e.str("AUTH_OAUTH_AUDIENCE"),
		RequiredScopes: e.list("AUTH_OAUTH_REQUIRED_SCOPES", ','),
		JWKSURL:        e.str("AUTH_OAUTH_JWKS_URL"),
		HMACSecret:     e.secretValue("AUTH_OAUTH_HMAC_SECRET"),
		ClockSkew:      e.duration("AUTH_OAUTH_CLOCK_SKEW"),
		KeysCacheTTL:   e.duration("AUTH_OAUTH_KEYS_CACHE_TTL"),
		FetchTimeout:   e.duration("AUTH_OAUTH_FETCH_TIMEOUT"),
		PublicURL:      e.str("AUTH_OAUTH_PUBLIC_URL"),
		Resource: ResourceConfig{
			Identifier:           e.str("AUTH_OAUTH_RESOURCE"),
			Name:                 e.str("AUTH_OAUTH_RESOURCE_NAME"),
			Documentation:        e.str("AUTH_OAUTH_RESOURCE_DOCUMENTATION"),
			AuthorizationServers: e.list("AUTH_OAUTH_AUTHORIZATION_SERVERS", ','),
		},
		Facade: FacadeConfig{
			ClientID:         e.str("AUTH_OAUTH_FACADE_CLIENT_ID"),
			ClientSecret:     e.secretValue("AUTH_OAUTH_FACADE_CLIENT_SECRET"),
			ScopePrefix:      e.str("AUTH_OAUTH_FACADE_SCOPE_PREFIX"),
			UpstreamResource: e.str("AUTH_OAUTH_FACADE_UPSTREAM_RESOURCE"),
		},
		RequireAccessTokenType: e.flag("AUTH_OAUTH_REQUIRE_AT_JWT"),
		TrustForwardedProto:    e.flag("AUTH_OAUTH_TRUST_FORWARDED_PROTO"),
	}
}

// fail records that the variable of key is malformed, as reason says.
func (e *envReader) fail(key, reason string) {
	e.p.Addf("%s%s %s", e.prefix, key, reason)
}

func (e *envReader) str(key string) string { return e.lookup(e.prefix + key) }

func (e *envReader) secretValue(key string) secret.Value { return secret.New(e.str(key)) }

// list splits the value of key at each sep that no backslash escapes.
func (e *envReader) list(key string, sep byte) []string {
	v := e.str(key)
	if v == "" {
		return nil
	}
	parts := splitList(v, sep)
	switch {
	case slices.Contains(parts, ""):
		e.fail(key, "has an empty element")
		return nil
	case slices.ContainsFunc(parts, loneBackslash):
		e.fail(key, "has an element ending in a lone backslash")
		return nil
	}
	return parts
}

// splitList splits s at each unescaped sep and trims the unescaped spaces
// around every element; escape pairs stay as written.
func splitList(s string, sep byte) []string {
	var out []string
	from, to := 0, 0
	open, escaped := false, false
	for i := range len(s) {
		c := s[i]
		switch {
		case escaped:
			escaped, to = false, i+1
		case c == sep:
			out = append(out, s[from:to])
			from, to, open = i+1, i+1, false
		case c == ' ':
		default:
			if !open {
				from, open = i, true
			}
			escaped, to = c == '\\', i+1
		}
	}
	return append(out, s[from:to])
}

// loneBackslash reports whether s ends in a backslash that escapes nothing:
// the last of an odd run.
func loneBackslash(s string) bool {
	return len(s[len(strings.TrimRight(s, `\`)):])%2 == 1
}

// flag returns the value of key as a boolean, false when it is empty.
func (e *envReader) flag(key string) bool {
	v := e.str(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.fail(key, "is not a boolean")
	}
	return b
}

// duration returns the value of key as a duration, zero when it is empty.
func (e *envReader) duration(key string) time.Duration {
	v := e.str(key)
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.fail(key, "is not a duration")
	}
	return d
}

// pins decodes base64 SHA-256 pins, padded or not, standard or URL alphabet.
func (e *envReader) pins(key string) [][]byte {
	list := e.list(key, ',')
	out := make([][]byte, 0, len(list))
	for _, p := range list {
		raw := strings.TrimRight(p, "=")
		pin, err := base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			pin, err = base64.RawURLEncoding.DecodeString(raw)
		}
		if err != nil {
			e.fail(key, "holds a pin that is not base64")
			return nil
		}
		out = append(out, pin)
	}
	return out
}
