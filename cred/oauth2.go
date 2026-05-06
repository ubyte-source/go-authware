package cred

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

const (
	defaultHTTPTimeout = 10 * time.Second
	maxTokenBodyBytes  = 1 << 20
	contentTypeForm    = "application/x-www-form-urlencoded"

	formGrantType    = "grant_type"
	formClientID     = "client_id"
	formScope        = "scope"
	formRefreshToken = "refresh_token"
)

// sharedHTTPClient is the package-wide default; reusing it lets
// connection pools amortize across providers.
var sharedHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}

// OAuth2Error carries the structured error payload returned by an
// OAuth2 token endpoint.
type OAuth2Error struct {
	Code        string
	Description string
	Status      int
}

func (e *OAuth2Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth2: %s: %s", e.Code, e.Description)
	}
	if e.Code != "" {
		return "oauth2: " + e.Code
	}
	return fmt.Sprintf("oauth2: HTTP %d", e.Status)
}

// ErrInvalidTokenResponse is returned when the token endpoint replies
// 2xx but the body cannot be parsed or carries no access_token.
var ErrInvalidTokenResponse = errors.New("oauth2: invalid token response")

// ClientCredentials implements the OAuth2 client_credentials grant.
// When ClientSecret is non-empty, HTTP Basic auth is used.
type ClientCredentials struct {
	Client       *http.Client
	TokenURL     string
	ClientID     string
	ClientSecret string
	Audience     string
	Scopes       []string
}

// Token requests a new access token from the token endpoint.
func (c *ClientCredentials) Token(ctx context.Context) (*Token, error) {
	form := url.Values{formGrantType: {"client_credentials"}}
	if len(c.Scopes) > 0 {
		form.Set(formScope, strings.Join(c.Scopes, " "))
	}
	if c.Audience != "" {
		form.Set("audience", c.Audience)
	}
	if c.ClientSecret == "" {
		form.Set(formClientID, c.ClientID)
	}
	resp, err := postFormToken(ctx, c.Client, c.TokenURL, form, c.ClientID, c.ClientSecret)
	if err != nil {
		return nil, err
	}
	return tokenFromResponse(resp), nil
}

// AuthorizationCode implements the OAuth2 refresh_token grant. On
// successful refresh, when the response carries a new refresh_token,
// the RefreshToken field is rotated in place.
type AuthorizationCode struct {
	Client       *http.Client
	TokenURL     string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scopes       []string
}

// Token exchanges the stored refresh_token for a fresh access_token.
func (a *AuthorizationCode) Token(ctx context.Context) (*Token, error) {
	if a.RefreshToken == "" {
		return nil, &OAuth2Error{Code: "invalid_request", Description: "missing refresh_token"}
	}
	form := url.Values{
		formGrantType:    {formRefreshToken},
		formRefreshToken: {a.RefreshToken},
	}
	if len(a.Scopes) > 0 {
		form.Set(formScope, strings.Join(a.Scopes, " "))
	}
	if a.ClientSecret == "" {
		form.Set(formClientID, a.ClientID)
	}
	resp, err := postFormToken(ctx, a.Client, a.TokenURL, form, a.ClientID, a.ClientSecret)
	if err != nil {
		return nil, err
	}
	if resp.RefreshToken != "" {
		a.RefreshToken = resp.RefreshToken
	}
	return tokenFromResponse(resp), nil
}

type tokenResponse struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int64
}

// tokenFromResponse converts a tokenResponse into a *Token. ExpiresIn
// == 0 leaves Expires as zero so a downstream Cache treats it as
// never stale.
func tokenFromResponse(r *tokenResponse) *Token {
	tok := &Token{
		Value: r.AccessToken,
		Type:  r.TokenType,
	}
	if r.ExpiresIn > 0 {
		tok.Expires = time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)
	}
	return tok
}

// postFormToken POSTs a form-encoded body to endpoint and parses the
// standard OAuth2 token response. basicID, when non-empty, sets HTTP
// Basic authentication.
func postFormToken(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	form url.Values,
	basicID, basicSecret string,
) (*tokenResponse, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: empty token URL", ErrInvalidTokenResponse)
	}
	req, err := buildTokenRequest(ctx, endpoint, form, basicID, basicSecret)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = sharedHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp.Body)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseOAuth2Error(resp.StatusCode, raw)
	}
	return decodeAndValidate(raw)
}

func buildTokenRequest(
	ctx context.Context,
	endpoint string,
	form url.Values,
	basicID, basicSecret string,
) (*http.Request, error) {
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentTypeForm)
	req.Header.Set("Accept", "application/json")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	return req, nil
}

func decodeAndValidate(raw []byte) (*tokenResponse, error) {
	out := parseTokenResponse(raw)
	if out.AccessToken == "" {
		return nil, fmt.Errorf("%w: missing access_token", ErrInvalidTokenResponse)
	}
	return out, nil
}

func closeBody(body io.Closer) {
	_ = body.Close() //nolint:errcheck // body fully read above.
}

func parseTokenResponse(body []byte) *tokenResponse {
	r := &tokenResponse{}
	jsonfast.IterateFields(body, func(key, value []byte) bool {
		switch unquoteKey(key) {
		case "access_token":
			r.AccessToken, _ = jsonfast.DecodeString(value)
		case "token_type":
			r.TokenType, _ = jsonfast.DecodeString(value)
		case formRefreshToken:
			r.RefreshToken, _ = jsonfast.DecodeString(value)
		case "expires_in":
			r.ExpiresIn, _ = jsonfast.DecodeInt64(value)
		}
		return true
	})
	return r
}

// parseOAuth2Error builds an *OAuth2Error from a non-2xx response body.
// When the body is not a recognized error document, Code falls back to
// "http_<status>".
func parseOAuth2Error(status int, body []byte) error {
	e := &OAuth2Error{Status: status}
	jsonfast.IterateFields(body, func(key, value []byte) bool {
		switch unquoteKey(key) {
		case "error":
			e.Code, _ = jsonfast.DecodeString(value)
		case "error_description":
			e.Description, _ = jsonfast.DecodeString(value)
		}
		return true
	})
	if e.Code == "" {
		e.Code = "http_" + strconv.Itoa(status)
	}
	return e
}

// unquoteKey strips the surrounding quotes from a raw JSON object key.
func unquoteKey(raw []byte) string {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return ""
	}
	return string(raw[1 : len(raw)-1])
}
