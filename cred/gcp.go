package cred

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// gcpAccountPath is the path of the default service account below BaseURL.
const gcpAccountPath = "/computeMetadata/v1/instance/service-accounts/default/"

// GCPMetadataConfig configures NewGCPMetadata.
type GCPMetadataConfig struct {
	// HTTPClient is the base client; a copy that refuses redirects is used.
	HTTPClient *http.Client
	// BaseURL overrides http://metadata.google.internal; the service account
	// path is appended to its path, its query, which url.ParseQuery must accept,
	// is kept, and a parameter the source sets overrides one of the same name.
	BaseURL string
	// Audience selects ID tokens for that audience instead of access tokens.
	Audience string
	// Scopes are the access token scopes, scope tokens without a comma, none
	// repeated and not allowed with Audience; empty means cloud-platform.
	Scopes []string
	// Timeout bounds each exchange; zero means 10s.
	Timeout time.Duration
}

// Validate reports every problem NewGCPMetadata refuses c for, joined; each wraps
// ErrInvalidConfig, and an insecure metadata URL also wraps ErrInsecureTokenURL.
func (c *GCPMetadataConfig) Validate() error {
	if c == nil {
		return errNilConfig
	}
	_, err := c.target()
	return err
}

// target returns the metadata URL of the ID token or the access token that
// c selects, or the problems Validate reports.
func (c *GCPMetadataConfig) target() (*url.URL, error) {
	p := problems.New(ErrInvalidConfig)
	u, q := metadataURL(p, cmp.Or(c.BaseURL, defaultGCPMetadataURL))
	if c.Audience != "" && len(c.Scopes) > 0 {
		p.Addf("GCP scopes are not allowed with an audience")
	}
	p.Scopes(c.Scopes)
	for _, s := range c.Scopes {
		if strings.Contains(s, ",") {
			p.Addf("GCP scope %q holds a comma", s)
		}
	}
	p.NonNegative("timeout", c.Timeout)
	if err := p.Err(); err != nil {
		return nil, err
	}
	leaf := "token"
	if c.Audience != "" {
		leaf = "identity"
		q.Set(paramAudience, c.Audience)
		q.Set("format", "full")
	} else {
		q.Set("scopes", cmp.Or(strings.Join(c.Scopes, ","), defaultGCPScope))
	}
	u.Path = strings.TrimRight(u.Path, "/") + gcpAccountPath + leaf
	u.RawQuery = q.Encode()
	return &u, nil
}

// NewGCPMetadata returns a TokenSource backed by the Google Compute Engine
// metadata server of the default service account, or an error wrapping
// ErrInvalidConfig.
func NewGCPMetadata(cfg *GCPMetadataConfig) (TokenSource, error) {
	if cfg == nil {
		return nil, errNilConfig
	}
	u, err := cfg.target()
	if err != nil {
		return nil, err
	}
	parse := parseAccessToken
	if cfg.Audience != "" {
		parse = parseIDToken
	}
	return &metadataSource{
		client:  netguard.Client(cfg.HTTPClient, cmp.Or(cfg.Timeout, defaultTimeout)),
		parse:   parse,
		service: "gcp metadata",
		target:  u,
		header:  "Metadata-Flavor",
		value:   "Google",
	}, nil
}

// parseAccessToken reads the token endpoint answer of the metadata server.
func parseAccessToken(body string) (*Token, error) {
	resp, err := oauthwire.ParseTokenResponse(body, ErrInvalidTokenResponse, nil)
	if err != nil {
		return nil, err
	}
	return tokenFromResponse(&resp)
}

// claimExp is the expiry claim of an ID token.
const claimExp = "exp"

// Refusals, built once, of an ID token the metadata server answers.
var (
	errIDTokenNotJWT  = fmt.Errorf("%w: ID token is not a JWT", ErrInvalidTokenResponse)
	errIDTokenPayload = fmt.Errorf("%w: ID token payload is not base64url", ErrInvalidTokenResponse)
	errIDTokenNoExp   = fmt.Errorf("%w: ID token has no exp", ErrInvalidTokenResponse)
)

// parseIDToken reads the exp claim of an unverified JWT; the metadata server
// is trusted, the token is only forwarded.
func parseIDToken(body string) (*Token, error) {
	jwt := strings.TrimSpace(body)
	parts, ok := syntax.SplitJWS(jwt)
	if !ok {
		return nil, errIDTokenNotJWT
	}
	payload, ok := syntax.AppendSegment(nil, parts.Payload)
	if !ok {
		return nil, errIDTokenPayload
	}
	var exp time.Time
	err := jsonobj.Iterate(string(payload), ErrInvalidTokenResponse, epochMember(claimExp, errExpNotPositive, &exp))
	if err != nil {
		return nil, err
	}
	if exp.IsZero() {
		return nil, errIDTokenNoExp
	}
	tok := &Token{Value: secret.New(jwt), Expires: exp}
	if err := tok.check(ErrInvalidTokenResponse); err != nil {
		return nil, err
	}
	return tok, nil
}
