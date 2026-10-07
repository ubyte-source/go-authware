package cred

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

// grantClientCredentials is the grant of a client acting on its own behalf.
const grantClientCredentials = "client_credentials"

// ClientCredentialsConfig configures NewClientCredentials.
type ClientCredentialsConfig struct {
	ClientConfig

	// Audience is sent as the audience parameter when not empty.
	Audience string
}

// Validate reports every problem NewClientCredentials refuses c for, joined; each
// wraps ErrInvalidConfig, and an insecure token URL also wraps ErrInsecureTokenURL.
func (c *ClientCredentialsConfig) Validate() error {
	if c == nil {
		return errNilConfig
	}
	return c.ClientConfig.Validate()
}

// clientCredentials requests a token of the client_credentials grant.
type clientCredentials struct {
	endpoint tokenEndpoint
	form     url.Values
}

// NewClientCredentials returns a TokenSource for the client_credentials
// grant, or an error wrapping ErrInvalidConfig. Every call requests a new
// token; wrap it with NewCachedSource.
func NewClientCredentials(cfg *ClientCredentialsConfig) (TokenSource, error) {
	if cfg == nil {
		return nil, errNilConfig
	}
	ep, err := cfg.endpoint()
	if err != nil {
		return nil, err
	}
	form := url.Values{oauthwire.ParamGrantType: {grantClientCredentials}}
	setScopes(form, cfg.Scopes)
	if cfg.Audience != "" {
		form.Set(paramAudience, cfg.Audience)
	}
	return &clientCredentials{endpoint: ep, form: form}, nil
}

// Token requests a new token.
func (c *clientCredentials) Token(ctx context.Context) (*Token, error) {
	tok, err := c.exchange(ctx)
	if err != nil {
		return nil, fmt.Errorf(errPrefix+"client credentials: %w", err)
	}
	return tok, nil
}

// exchange posts the grant and reads the token of the answer.
func (c *clientCredentials) exchange(ctx context.Context) (*Token, error) {
	resp, err := c.endpoint.post(ctx, c.form)
	if err != nil {
		return nil, err
	}
	return tokenFromResponse(&resp)
}
