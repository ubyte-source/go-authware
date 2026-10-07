package cred

import (
	"cmp"
	"context"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// OAuth2Error is an error answer of a token endpoint or a metadata service; its
// text starts with "oauth2:" because it reports the peer.
type OAuth2Error struct {
	// Status is the HTTP status code of the answer.
	Status int
	// Code is the OAuth error code, empty when the body carries none.
	Code string
	// Description is the error_description, or an excerpt of a body that is
	// not an OAuth error.
	Description string
}

// newOAuth2Error returns the *OAuth2Error of an answer that is not 2xx.
func newOAuth2Error(status int, code, description string) error {
	return &OAuth2Error{Status: status, Code: code, Description: description}
}

// Error renders the status, code and quoted description.
func (e *OAuth2Error) Error() string {
	var b strings.Builder
	b.WriteString("oauth2: status ")
	b.WriteString(strconv.Itoa(e.Status))
	if e.Code != "" {
		b.WriteString(" error ")
		b.WriteString(strconv.Quote(e.Code))
	}
	if e.Description != "" {
		b.WriteString(": ")
		b.WriteString(strconv.Quote(e.Description))
	}
	return b.String()
}

// serverErrorEnd ends the 5xx class of statuses.
const serverErrorEnd = 600

// Transient reports whether a later retry may succeed: a 5xx or 429 status,
// or the code temporarily_unavailable or slow_down.
func (e *OAuth2Error) Transient() bool {
	return e.Status >= http.StatusInternalServerError && e.Status < serverErrorEnd ||
		e.Status == http.StatusTooManyRequests ||
		e.Code == oauthwire.CodeTemporarilyUnavailable ||
		e.Code == "slow_down"
}

// AuthStyle selects how a confidential client authenticates; the zero value is
// AuthStyleHeader.
type AuthStyle uint8

const (
	// AuthStyleHeader sends form-urlencoded credentials as HTTP Basic.
	AuthStyleHeader AuthStyle = iota
	// AuthStyleParams sends client_id and client_secret in the form body.
	AuthStyleParams
)

// tokenEndpoint is a validated token URL with its client authentication.
type tokenEndpoint struct {
	client *http.Client
	url    *url.URL
	id     string
	secret secret.Value
	style  AuthStyle
}

// post sends a copy of form with the client authentication, as Basic credentials
// form-urlencoded first under AuthStyleHeader with a secret, else as form
// parameters, and decodes the answer.
func (e *tokenEndpoint) post(ctx context.Context, form url.Values) (oauthwire.TokenResponse, error) {
	clientSecret := e.secret.Reveal()
	basic := clientSecret != "" && e.style == AuthStyleHeader
	values := url.Values{}
	maps.Copy(values, form)
	if !basic {
		oauthwire.SetClientParams(values, e.id, clientSecret)
	}
	req := oauthwire.NewTokenRequest(ctx, e.url, values)
	if basic {
		req.SetBasicAuth(url.QueryEscape(e.id), url.QueryEscape(clientSecret))
	}
	body, err := oauthwire.Fetch(e.client, req, oauthwire.MaxTokenBody, ErrInvalidTokenResponse, newOAuth2Error)
	if err != nil {
		return oauthwire.TokenResponse{}, err
	}
	return oauthwire.ParseTokenResponse(body, ErrInvalidTokenResponse, nil)
}

// ClientConfig is the token endpoint and the client authentication that the
// OAuth grants share.
type ClientConfig struct {
	// HTTPClient is the base client; a copy that refuses redirects is used.
	HTTPClient *http.Client
	// TokenURL is the token endpoint.
	TokenURL string
	// ClientID identifies the client; required.
	ClientID string
	// ClientSecret authenticates the client; empty sends client_id only.
	ClientSecret secret.Value
	// AuthStyle selects how ClientSecret is sent.
	AuthStyle AuthStyle
	// Scopes are requested space-separated when not empty; each is a scope
	// token, none repeated.
	Scopes []string
	// Timeout bounds each exchange; zero means 10s.
	Timeout time.Duration
}

// Validate reports every problem of c that the grants refuse, joined; each wraps
// ErrInvalidConfig, and an insecure token URL also wraps ErrInsecureTokenURL.
func (c *ClientConfig) Validate() error {
	if c == nil {
		return errNilConfig
	}
	_, err := c.endpoint()
	return err
}

// endpoint returns the token endpoint of c, reached through a copy of its
// HTTPClient that refuses redirects, or the problems Validate reports.
func (c *ClientConfig) endpoint() (tokenEndpoint, error) {
	p := problems.New(ErrInvalidConfig)
	u, err := netguard.Check(c.TokenURL, ErrInsecureTokenURL)
	p.Add(err)
	if c.ClientID == "" {
		p.Addf("missing client ID")
	}
	if c.AuthStyle != AuthStyleHeader && c.AuthStyle != AuthStyleParams {
		p.Addf("unknown auth style %d", c.AuthStyle)
	}
	p.Scopes(c.Scopes)
	p.NonNegative("timeout", c.Timeout)
	if err := p.Err(); err != nil {
		return tokenEndpoint{}, err
	}
	return tokenEndpoint{
		client: netguard.Client(c.HTTPClient, cmp.Or(c.Timeout, defaultTimeout)),
		url:    u,
		id:     c.ClientID,
		secret: c.ClientSecret,
		style:  c.AuthStyle,
	}, nil
}

// setScopes requests scopes, space-separated, in the form of a token endpoint
// request, when there is any.
func setScopes(form url.Values, scopes []string) {
	if len(scopes) > 0 {
		form.Set(oauthwire.ParamScope, strings.Join(scopes, " "))
	}
}

// tokenFromResponse refuses a token that is not a clean header credential
// and stamps the relative lifetime, when there is one, on the local clock.
func tokenFromResponse(resp *oauthwire.TokenResponse) (*Token, error) {
	tok := &Token{Value: secret.New(resp.AccessToken), Type: resp.TokenType}
	if err := tok.check(ErrInvalidTokenResponse); err != nil {
		return nil, err
	}
	if resp.ExpiresIn > 0 {
		tok.Expires = time.Now().Add(resp.ExpiresIn)
	}
	return tok, nil
}
