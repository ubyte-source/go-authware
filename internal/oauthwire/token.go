package oauthwire

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
)

// MaxTokenBody bounds a token endpoint response body in bytes.
const MaxTokenBody = 1 << 20

// FormContentType is the media type of token requests.
const FormContentType = "application/x-www-form-urlencoded"

// MaxLifetime caps a token lifetime, whether sent as expires_in or as an
// absolute expiry.
const MaxLifetime = 365 * 24 * time.Hour

// The parameters of token requests and responses that the credential
// sources, the facade and the log redactor name.
const (
	ParamGrantType    = "grant_type"
	ParamClientID     = "client_id"
	ParamClientSecret = "client_secret"
	ParamScope        = "scope"
	ParamResource     = "resource"
	ParamRefreshToken = "refresh_token"
	ParamAccessToken  = "access_token"
	ParamIDToken      = "id_token"
)

// The token response parameters that only ParseTokenResponse names.
const (
	paramTokenType = "token_type"
	paramExpiresIn = "expires_in"
)

// GrantRefreshToken is the grant type that exchanges a refresh token.
const GrantRefreshToken = "refresh_token"

// TokenResponse is a decoded token endpoint response, in which a null member
// counts as absent. Its zero value is the empty response; like any struct, it
// is safe for concurrent reads but not for a write concurrent with a use.
type TokenResponse struct {
	// AccessToken is the issued access token, never empty in a parsed response.
	AccessToken string
	// TokenType is the token_type, such as Bearer.
	TokenType string
	// ExpiresIn is expires_in, a positive number of seconds, quoted or not, as a
	// lifetime from a nanosecond to MaxLifetime; zero when absent.
	ExpiresIn time.Duration
	// RefreshToken is the refresh_token, empty when none was issued.
	RefreshToken string
}

// ParseTokenResponse decodes body, a UTF-8 JSON object nested at most 32 deep with
// unique names and an access_token, into copies, else fails with invalid; extra, unless
// nil, gets each other member, maybe before a failure, and its error returns as is.
func ParseTokenResponse(body string, invalid error, extra func(name, value string) error) (TokenResponse, error) {
	var r TokenResponse
	err := jsonobj.Iterate(body, invalid, func(name, value string) error {
		return r.set(name, value, invalid, extra)
	})
	if err != nil {
		return TokenResponse{}, err
	}
	if r.AccessToken == "" {
		return TokenResponse{}, fmt.Errorf("%w: missing access_token", invalid)
	}
	return r, nil
}

// set records one member of a token response, a fault wrapping invalid, or
// hands one the response does not define to extra when it is not nil.
func (r *TokenResponse) set(name, value string, invalid error, extra func(name, value string) error) error {
	var dst *string
	switch name {
	case ParamAccessToken:
		dst = &r.AccessToken
	case paramTokenType:
		dst = &r.TokenType
	case ParamRefreshToken:
		dst = &r.RefreshToken
	case paramExpiresIn:
		d, err := parseExpiresIn(value, invalid)
		r.ExpiresIn = d
		return err
	default:
		if extra == nil {
			return nil
		}
		return extra(name, value)
	}
	return jsonobj.CopyString(dst, name, value, invalid)
}

// NumberText returns the JSON number that value holds, as a number or as a
// string whose content is one, since some token servers quote their numbers; any
// other value gives "".
func NumberText(value string) string {
	if s, ok := jsonfast.DecodeString(value); ok {
		value = s
	}
	if !jsonfast.IsNumber(value) {
		return ""
	}
	return value
}

// parseExpiresIn reads a positive number of seconds, one beyond float64 or below
// its least magnitude included, as a lifetime from a nanosecond to MaxLifetime,
// or fails with invalid; null yields zero.
func parseExpiresIn(value string, invalid error) (time.Duration, error) {
	if jsonfast.KindOf(value) == jsonfast.KindNull {
		return 0, nil
	}
	text := NumberText(value)
	if text == "" || text[0] == '-' || zeroDigits(text) {
		return 0, fmt.Errorf("%w: expires_in is not a positive number", invalid)
	}
	secs, inRange := jsonfast.DecodeFloat64(text)
	if !inRange {
		return MaxLifetime, nil
	}
	secs = min(secs, MaxLifetime.Seconds())
	return max(time.Duration(secs*float64(time.Second)), time.Nanosecond), nil
}

// zeroDigits reports whether the JSON number text has no digit but 0 before
// its exponent.
func zeroDigits(text string) bool {
	rest := strings.TrimLeft(text, "0.")
	return rest == "" || rest[0] == 'e' || rest[0] == 'E'
}

// NewTokenRequest builds a replayable form POST of form to a copy of endpoint,
// which passed netguard.Check.
func NewTokenRequest(ctx context.Context, endpoint *url.URL, form url.Values) *http.Request {
	req := newRequest(ctx, http.MethodPost, endpoint)
	payload := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(payload))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(payload)), nil
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", FormContentType)
	req.Header.Set("Accept", JSONContentType)
	return req
}
