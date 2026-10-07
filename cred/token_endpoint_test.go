package cred

import (
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/secret"
)

const plainIDP = "http://idp.example/token"

// An AuthStyle no exchange knows, and the problems Validate joins for a config
// with it, a plain URL, repeated and empty scopes and a negative timeout.
const (
	unknownStyle      = 7
	badClientProblems = 8
)

// clientConfig returns a ClientConfig of the token endpoint at tokenURL.
func clientConfig(tokenURL string) ClientConfig {
	return ClientConfig{TokenURL: tokenURL, ClientID: testClientID, ClientSecret: secret.New("s")}
}

func TestClientConfigValidate(t *testing.T) {
	if err := (*ClientConfig)(nil).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Validate() = %v, want ErrInvalidConfig", err)
	}
	cfg := clientConfig(idpEndpoint)
	cfg.Scopes = []string{"read", "api://x/.default"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid Validate() = %v, want nil", err)
	}
	tests := []struct {
		name string
		edit func(c *ClientConfig)
		want error
	}{
		{"insecure URL", func(c *ClientConfig) { c.TokenURL = plainIDP }, ErrInsecureTokenURL},
		{"missing client ID", func(c *ClientConfig) { c.ClientID = "" }, ErrInvalidConfig},
		{"unknown style", func(c *ClientConfig) { c.AuthStyle = unknownStyle }, ErrInvalidConfig},
		{"empty scope", func(c *ClientConfig) { c.Scopes = []string{""} }, ErrInvalidConfig},
		{"spaced scope", func(c *ClientConfig) { c.Scopes = []string{"read write"} }, ErrInvalidConfig},
		{"negative timeout", func(c *ClientConfig) { c.Timeout = -time.Nanosecond }, ErrInvalidConfig},
	}
	for _, tc := range tests {
		c := clientConfig(idpEndpoint)
		tc.edit(&c)
		if err := c.Validate(); !errors.Is(err, tc.want) || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: Validate() = %v, want one problem matching %v", tc.name, err, tc.want)
		}
	}
	spaced := "read write"
	bad := ClientConfig{TokenURL: plainIDP, AuthStyle: unknownStyle, Scopes: []string{spaced, "", spaced},
		Timeout: -time.Second}
	if got := strings.Count(bad.Validate().Error(), "\n"); got != badClientProblems-1 {
		t.Fatalf("Validate() = %q, want eight joined problems", bad.Validate())
	}
}

func TestClientConfigEndpoint(t *testing.T) {
	base := &http.Client{Timeout: time.Minute}
	for timeout, want := range map[time.Duration]time.Duration{0: wantTimeout, time.Second: time.Second} {
		cfg := clientConfig(idpEndpoint)
		cfg.HTTPClient, cfg.AuthStyle, cfg.Timeout = base, AuthStyleParams, timeout
		ep, err := cfg.endpoint()
		if err != nil || ep.client.Timeout != want || ep.client.CheckRedirect == nil || ep.client == base {
			t.Fatalf("endpoint(Timeout %v) client = %+v, %v, want a copy refusing redirects within %v", timeout,
				ep.client, err, want)
		}
		if ep.url.String() != idpEndpoint || ep.id != testClientID || ep.secret.Reveal() != "s" ||
			ep.style != AuthStyleParams {
			t.Fatalf("endpoint = %+v, want the URL, client and style of the config", ep)
		}
	}
}

// mustEndpoint returns the token endpoint at tokenURL of a public client.
func mustEndpoint(t *testing.T, tokenURL string) tokenEndpoint {
	t.Helper()
	ep, err := (&ClientConfig{TokenURL: tokenURL, ClientID: testClientID}).endpoint()
	if err != nil {
		t.Fatalf("endpoint = %v, want a token endpoint", err)
	}
	return ep
}

func TestTokenEndpointPost(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK, okToken))
	ep := mustEndpoint(t, rec.srv.URL+"/token")
	form := url.Values{"k": {"v"}}
	resp, err := ep.post(t.Context(), form)
	if err != nil || resp.AccessToken != wantAccess {
		t.Fatalf("post = %+v, %v, want the token", resp, err)
	}
	if len(form) != 1 {
		t.Fatalf("form after post = %v, want the caller's form untouched", form)
	}
	got := rec.requests()[0]
	if got.method != http.MethodPost || got.path != "/token" || got.form.Get("k") != "v" {
		t.Fatalf("request = %+v, want a POST of the form to /token", got)
	}
	failing := newRecording(t, answer(http.StatusBadRequest, `{"error":"invalid_grant"}`))
	var oe *OAuth2Error
	refusing := mustEndpoint(t, failing.srv.URL)
	resp, err = refusing.post(t.Context(), form)
	if resp.AccessToken != "" || !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("refused post = %+v, %v, want no token and the invalid_grant answer", resp, err)
	}
}

// TestTokenEndpointPostBodyLimit reads an answer of exactly MaxTokenBody bytes
// and refuses one a byte longer.
func TestTokenEndpointPostBodyLimit(t *testing.T) {
	exact := strings.Repeat(" ", mib-len(okToken)) + okToken
	for body, want := range map[string]error{exact: nil, " " + exact: ErrInvalidTokenResponse} {
		rec := newRecording(t, answer(http.StatusOK, body))
		ep := mustEndpoint(t, rec.srv.URL)
		resp, err := ep.post(t.Context(), url.Values{})
		if !errors.Is(err, want) || (want == nil) != (resp.AccessToken == wantAccess) {
			t.Errorf("post(answer of %d bytes) = %+v, %v; want %v", len(body), resp, err, want)
		}
	}
}

// TestClientConfigEndpointRefusesInsecureURL names the policy's reason once,
// after the cred prefix, and never the userinfo.
func TestClientConfigEndpointRefusesInsecureURL(t *testing.T) {
	for raw, reason := range map[string]string{
		plainIDP:                            `scheme "http" to host "idp.example"`,
		"https://user:pw@idp.example/token": "userinfo not allowed",
		"::":                                "unparseable",
	} {
		ep, err := (&ClientConfig{TokenURL: raw, ClientID: testClientID}).endpoint()
		want := "cred: invalid config: insecure token URL: " + reason
		if ep.url != nil || !errors.Is(err, ErrInsecureTokenURL) || err.Error() != want {
			t.Errorf("endpoint(%q) = %v, %v; want ErrInsecureTokenURL reading %q", raw, ep.url, err, want)
		}
	}
}

// TestTokenEndpointPostReadsTheStatusFirst makes an error answer over 1 MiB
// an *OAuth2Error that keeps its status and so its retry class.
func TestTokenEndpointPostReadsTheStatusFirst(t *testing.T) {
	ep := mustEndpoint(t, hugeAnswer(t, http.StatusServiceUnavailable).URL)
	_, err := ep.post(t.Context(), url.Values{})
	var oe *OAuth2Error
	if !errors.As(err, &oe) || oe.Status != http.StatusServiceUnavailable || !oe.Transient() ||
		errors.Is(err, ErrInvalidTokenResponse) || errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("post(503 over 1 MiB) = %v, want a transient *OAuth2Error alone", err)
	}
}

// TestTokenEndpointPostAuthenticates sends a confidential client as Basic
// credentials, form-urlencoded first, or in the form, and a public one by
// client_id alone under either style.
func TestTokenEndpointPostAuthenticates(t *testing.T) {
	const id, confidential = "app:id é", "p@ss w+rd/%"
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("app%3Aid+%C3%A9:p%40ss+w%2Brd%2F%25"))
	const formKey, formValue = "k", "v"
	sent := url.Values{formKey: {formValue}}
	for _, tc := range []struct {
		style        AuthStyle
		clientSecret string
		header       string
		params       url.Values
	}{
		{AuthStyleHeader, confidential, basic, nil},
		{AuthStyleParams, confidential, "", url.Values{"client_id": {id}, "client_secret": {confidential}}},
		{AuthStyleHeader, "", "", url.Values{"client_id": {id}}},
		{AuthStyleParams, "", "", url.Values{"client_id": {id}}},
	} {
		rec := newRecording(t, answer(http.StatusOK, okToken))
		ep, err := (&ClientConfig{TokenURL: rec.srv.URL, ClientID: id, ClientSecret: secret.New(tc.clientSecret),
			AuthStyle: tc.style}).endpoint()
		if err != nil {
			t.Fatalf("endpoint = %v, want a token endpoint", err)
		}
		if _, err := ep.post(t.Context(), sent); err != nil || len(sent) != 1 {
			t.Fatalf("post = %v leaving the caller's form %v, want the token and the form untouched", err, sent)
		}
		want := url.Values{formKey: {formValue}}
		maps.Copy(want, tc.params)
		got := rec.requests()[0]
		if got.requestHeader.Get(authorization) != tc.header || got.form.Encode() != want.Encode() {
			t.Errorf("style %d, secret %q: Authorization %q and form %v, want %q and %v", tc.style, tc.clientSecret,
				got.requestHeader.Get(authorization), got.form, tc.header, want)
		}
	}
}

// TestTokenEndpointPostPassesTheContext sends the form under the context post
// gets.
func TestTokenEndpointPostPassesTheContext(t *testing.T) {
	transport := &markedTransport{}
	ep, err := (&ClientConfig{HTTPClient: &http.Client{Transport: transport}, TokenURL: idpEndpoint,
		ClientID: testClientID}).endpoint()
	if err != nil {
		t.Fatalf("endpoint = %v, want a token endpoint", err)
	}
	if _, err := ep.post(marked(t), url.Values{}); err != nil || transport.marked.Load() != 1 {
		t.Fatalf("post = %v after %d marked requests, want nil after 1", err, transport.marked.Load())
	}
}

func TestOAuth2ErrorError(t *testing.T) {
	cases := []struct {
		err  OAuth2Error
		want string
	}{
		{OAuth2Error{Status: http.StatusBadRequest, Code: "invalid_scope", Description: "bad\nscope"},
			`oauth2: status 400 error "invalid_scope": "bad\nscope"`},
		{OAuth2Error{Status: http.StatusBadGateway}, "oauth2: status 502"},
		{OAuth2Error{Status: http.StatusInternalServerError, Description: "down"}, `oauth2: status 500: "down"`},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Fatalf("Error() = %q, want %q", got, tc.want)
		}
	}
}

func TestOAuth2ErrorTransient(t *testing.T) {
	const lastClientError, lastServerError = 499, 599
	cases := []struct {
		err  OAuth2Error
		want bool
	}{
		{OAuth2Error{Status: http.StatusInternalServerError}, true},
		{OAuth2Error{Status: http.StatusServiceUnavailable}, true},
		{OAuth2Error{Status: http.StatusTooManyRequests}, true},
		{OAuth2Error{Status: http.StatusBadRequest, Code: "temporarily_unavailable"}, true},
		{OAuth2Error{Status: http.StatusBadRequest, Code: "slow_down"}, true},
		{OAuth2Error{Status: lastClientError}, false},
		{OAuth2Error{Status: lastServerError}, true},
		{OAuth2Error{Status: lastServerError + 1}, false},
		{OAuth2Error{Status: http.StatusBadRequest, Code: "access_denied"}, false},
		{OAuth2Error{Status: http.StatusUnauthorized, Code: "invalid_client"}, false},
		{OAuth2Error{Status: http.StatusTemporaryRedirect}, false},
	}
	for _, tc := range cases {
		if got := tc.err.Transient(); got != tc.want {
			t.Fatalf("%+v Transient = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestNewOAuth2Error(t *testing.T) {
	err := newOAuth2Error(http.StatusBadRequest, "invalid_grant", "expired")
	var oe *OAuth2Error
	if !errors.As(err, &oe) || *oe != (OAuth2Error{http.StatusBadRequest, "invalid_grant", "expired"}) {
		t.Fatalf("newOAuth2Error = %#v, want the *OAuth2Error of its arguments", err)
	}
}

func TestSetScopes(t *testing.T) {
	form := url.Values{}
	setScopes(form, nil)
	if form.Has("scope") {
		t.Fatalf("setScopes(nil) = %v, want no scope", form)
	}
	setScopes(form, []string{"a", "b"})
	if form.Get("scope") != "a b" {
		t.Fatalf("scope = %q, want %q", form.Get("scope"), "a b")
	}
}

func TestTokenFromResponse(t *testing.T) {
	tok, err := tokenFromResponse(&oauthwire.TokenResponse{AccessToken: wantAccess, TokenType: dpop})
	if err != nil || !tok.Expires.IsZero() || tok.Type != dpop || tok.Value.Reveal() != wantAccess {
		t.Fatalf("token = %+v, %v, want DPoP at without expiry", tok, err)
	}
	for _, lifetime := range []time.Duration{time.Minute, time.Second, time.Second / 2, time.Nanosecond} {
		before := time.Now()
		tok, err = tokenFromResponse(&oauthwire.TokenResponse{AccessToken: wantAccess, ExpiresIn: lifetime})
		if err != nil || tok.Expires.Before(before.Add(lifetime)) || tok.Expires.After(time.Now().Add(lifetime)) {
			t.Errorf("token = %+v, %v, want it expiring %v from now", tok, err, lifetime)
		}
	}
}

func TestTokenFromResponseRejects(t *testing.T) {
	for _, resp := range []oauthwire.TokenResponse{
		{AccessToken: "a\nb"}, {AccessToken: " at"}, {AccessToken: wantAccess, TokenType: spacedScheme},
	} {
		if tok, err := tokenFromResponse(&resp); tok != nil || !errors.Is(err, ErrInvalidTokenResponse) {
			t.Errorf("tokenFromResponse(%+v) = %v, %v, want ErrInvalidTokenResponse", resp, tok, err)
		}
	}
}
