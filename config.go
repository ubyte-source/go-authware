package authware

import (
	"cmp"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// Mode names an authentication scheme.
type Mode string

// These are the modes a Gate enforces; Config.Mode selects exactly one.
const (
	ModeNone   Mode = "none"
	ModeBearer Mode = "bearer"
	ModeAPIKey Mode = "apikey"
	ModeOAuth  Mode = "oauth"
	ModeMTLS   Mode = "mtls"
)

// Config selects the mode and carries its settings; the sections of the
// other modes must stay empty.
type Config struct {
	// HTTPClient is the base of every outbound fetch; New uses a guarded copy.
	HTTPClient *http.Client
	// ErrorLog receives, at warn level, the cause of every failed fetch of the
	// keys or the issuer metadata and of every facade request the upstream fails,
	// and at debug level of a token relay canceled with its request; nil logs nothing.
	ErrorLog *slog.Logger
	// Mode (AUTH_MODE) is required; there is no inference.
	Mode Mode
	// Realm (AUTH_REALM) names the protection space in challenges; default
	// "restricted".
	Realm string
	// Bearer configures ModeBearer.
	Bearer BearerConfig
	// APIKey configures ModeAPIKey.
	APIKey APIKeyConfig
	// OAuth configures ModeOAuth.
	OAuth OAuthConfig
	// MTLS configures ModeMTLS.
	MTLS MTLSConfig
}

// Validate reports every configuration problem of c, a nil c included, joined, each
// wrapping ErrInvalidConfig; c itself is not modified.
func (c *Config) Validate() error {
	_, err := c.prepare()
	return err
}

// prepare returns a validated copy of c with defaults applied.
func (c *Config) prepare() (*Config, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil config", ErrInvalidConfig)
	}
	out := c.clone()
	p := problems.New(ErrInvalidConfig)
	out.refuseForeign(p)
	out.applyDefaults()
	out.validateMode(p)
	if err := p.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// clone copies c deeply enough that later edits by the caller are not seen.
func (c *Config) clone() *Config {
	out := *c
	out.OAuth.RequiredScopes = slices.Clone(c.OAuth.RequiredScopes)
	out.OAuth.Resource.AuthorizationServers = slices.Clone(c.OAuth.Resource.AuthorizationServers)
	out.MTLS.AllowedSubjects = slices.Clone(c.MTLS.AllowedSubjects)
	out.MTLS.AllowedSPKIPins = make([][]byte, len(c.MTLS.AllowedSPKIPins))
	for i, pin := range c.MTLS.AllowedSPKIPins {
		out.MTLS.AllowedSPKIPins[i] = slices.Clone(pin)
	}
	return &out
}

// refuseForeign refuses the settings of every section but the one of the
// selected mode, which nothing would read.
func (c *Config) refuseForeign(p *problems.List) {
	for _, section := range [...]struct {
		name  string
		mode  Mode
		inUse bool
	}{
		{"Bearer", ModeBearer, c.Bearer.inUse()},
		{"APIKey", ModeAPIKey, c.APIKey.inUse()},
		{"OAuth", ModeOAuth, c.OAuth.inUse()},
		{"MTLS", ModeMTLS, c.MTLS.inUse()},
	} {
		if section.inUse && section.mode != c.Mode {
			p.Addf("%s settings require mode %s", section.name, section.mode)
		}
	}
}

// applyDefaults gives the empty settings their defaults.
func (c *Config) applyDefaults() {
	c.Realm = cmp.Or(c.Realm, defaultRealm)
	c.APIKey.Header = http.CanonicalHeaderKey(cmp.Or(c.APIKey.Header, defaultKeyHeader))
	o := &c.OAuth
	o.ClockSkew = cmp.Or(o.ClockSkew, defaultClockSkew)
	o.KeysCacheTTL = cmp.Or(o.KeysCacheTTL, defaultKeysCacheTTL)
	o.FetchTimeout = cmp.Or(o.FetchTimeout, defaultFetchTimeout)
	if len(o.Resource.AuthorizationServers) == 0 && o.Facade.ClientID == "" && advertisable(o.Issuer) {
		o.Resource.AuthorizationServers = []string{o.Issuer}
	}
}

// validateMode checks the section of the selected mode.
func (c *Config) validateMode(p *problems.List) {
	switch c.Mode {
	case ModeNone:
	case ModeBearer:
		c.Bearer.validate(p)
	case ModeAPIKey:
		c.APIKey.validate(p)
	case ModeOAuth:
		c.OAuth.validate(p)
	case ModeMTLS:
		c.MTLS.validate(p)
	case "":
		p.Addf("mode is required")
	default:
		p.Addf("unknown mode %q", c.Mode)
	}
}

// advertisable reports whether an issuer can default the authorization
// servers; an issuer that is not a secure URL adds no URL requirement.
func advertisable(issuerURL string) bool {
	_, err := netguard.Check(issuerURL, ErrInsecureURL)
	return err == nil
}

// minSecretLen is the shortest static credential or HMAC key accepted, in bytes.
const minSecretLen = 32

// longEnough reports whether v, the named secret of a Config, holds at least
// minSecretLen bytes, recording the problem when it does not.
func longEnough(p *problems.List, name string, v secret.Value) bool {
	if v.Len() < minSecretLen {
		p.Addf("%s is shorter than %d bytes", name, minSecretLen)
		return false
	}
	return true
}
