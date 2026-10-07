package cred

import (
	"cmp"
	"net/http"
	"net/url"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
)

// azureMSIAPIVersion is the version of the instance metadata token API.
const azureMSIAPIVersion = "2018-02-01"

// AzureMSIConfig configures NewAzureMSI.
type AzureMSIConfig struct {
	// HTTPClient is the base client; a copy that refuses redirects is used.
	HTTPClient *http.Client
	// Endpoint overrides the instance metadata token URL; its query, which
	// url.ParseQuery must accept, is kept, and a parameter the source sets
	// overrides one of the same name.
	Endpoint string
	// Resource is the application ID URI of the target; required.
	Resource string
	// ClientID selects a user-assigned identity when not empty.
	ClientID string
	// Timeout bounds each exchange; zero means 10s.
	Timeout time.Duration
}

// Validate reports every problem NewAzureMSI refuses c for, joined; each wraps
// ErrInvalidConfig, and an insecure metadata URL also wraps ErrInsecureTokenURL.
func (c *AzureMSIConfig) Validate() error {
	if c == nil {
		return errNilConfig
	}
	_, err := c.target()
	return err
}

// target returns the token URL of c with its query set, or the problems
// Validate reports.
func (c *AzureMSIConfig) target() (*url.URL, error) {
	p := problems.New(ErrInvalidConfig)
	u, q := metadataURL(p, cmp.Or(c.Endpoint, defaultAzureMSIEndpoint))
	if c.Resource == "" {
		p.Addf("missing Azure resource")
	}
	p.NonNegative("timeout", c.Timeout)
	if err := p.Err(); err != nil {
		return nil, err
	}
	q.Set("api-version", azureMSIAPIVersion)
	q.Set(oauthwire.ParamResource, c.Resource)
	if c.ClientID != "" {
		q.Set(oauthwire.ParamClientID, c.ClientID)
	}
	u.RawQuery = q.Encode()
	return &u, nil
}

// NewAzureMSI returns a TokenSource backed by the Azure instance metadata
// service of a managed identity, or an error wrapping ErrInvalidConfig.
func NewAzureMSI(cfg *AzureMSIConfig) (TokenSource, error) {
	if cfg == nil {
		return nil, errNilConfig
	}
	u, err := cfg.target()
	if err != nil {
		return nil, err
	}
	return &metadataSource{
		client:  netguard.Client(cfg.HTTPClient, cmp.Or(cfg.Timeout, defaultTimeout)),
		parse:   parseMSIResponse,
		service: "azure managed identity",
		target:  u,
		header:  "Metadata",
		value:   "true",
	}, nil
}

// msiExpiresOn is the member of a managed identity answer that carries the
// absolute expiry.
const msiExpiresOn = "expires_on"

// parseMSIResponse reads a managed identity answer in one walk; its absolute
// expires_on wins over the relative expires_in.
func parseMSIResponse(body string) (*Token, error) {
	var expiresOn time.Time
	resp, err := oauthwire.ParseTokenResponse(body, ErrInvalidTokenResponse,
		epochMember(msiExpiresOn, errExpiresOnNotPositive, &expiresOn))
	if err != nil {
		return nil, err
	}
	tok, err := tokenFromResponse(&resp)
	if err != nil {
		return nil, err
	}
	if !expiresOn.IsZero() {
		tok.Expires = expiresOn
	}
	return tok, nil
}
