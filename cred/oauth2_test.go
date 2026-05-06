package cred

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

// writeJSONBody writes body as a JSON response and reports failures via tb.
func writeJSONBody(tb testing.TB, w http.ResponseWriter, body string) {
	tb.Helper()
	if _, err := io.WriteString(w, body); err != nil {
		tb.Errorf("write: %v", err)
	}
}

// fakeTokenServer returns an httptest.Server scripted by responder. Each
// request body is parsed as form-encoded and passed to responder; responder
// writes the response body and returns the desired status code.
type tokenServerResponder func(form url.Values, w http.ResponseWriter) int

func fakeTokenServer(t *testing.T, responder tokenServerResponder) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != contentTypeForm {
			t.Errorf("Content-Type = %q, want %q", got, contentTypeForm)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := responder(form, w)
		w.WriteHeader(status)
	}))
}

func TestClientCredentials_Success(t *testing.T) {
	srv := fakeTokenServer(t, func(form url.Values, w http.ResponseWriter) int {
		if got := form.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := form.Get("scope"); got != "read write" {
			t.Errorf("scope = %q", got)
		}
		writeJSONBody(t, w, `{"access_token":"abc","token_type":"Bearer","expires_in":3600}`)
		return http.StatusOK
	})
	defer srv.Close()

	c := &ClientCredentials{
		Client:       srv.Client(),
		TokenURL:     srv.URL,
		ClientID:     testID,
		ClientSecret: "secret",
		Scopes:       []string{"read", "write"},
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.Value != "abc" {
		t.Fatalf("Value = %q", tok.Value)
	}
	if tok.Type != "Bearer" {
		t.Fatalf("Type = %q", tok.Type)
	}
	if time.Until(tok.Expires) < time.Hour-time.Minute {
		t.Fatalf("Expires too close: %v", tok.Expires)
	}
}

func TestClientCredentials_BasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != testID || pass != "secret" {
			t.Errorf("basic auth = (%q, %q, %v)", user, pass, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"access_token":"x","token_type":"Bearer"}`)
	}))
	defer srv.Close()

	c := &ClientCredentials{Client: srv.Client(), TokenURL: srv.URL, ClientID: testID, ClientSecret: "secret"}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientCredentials_PublicClient(t *testing.T) {
	srv := fakeTokenServer(t, func(form url.Values, w http.ResponseWriter) int {
		if got := form.Get("client_id"); got != "public" {
			t.Errorf("client_id = %q", got)
		}
		writeJSONBody(t, w, `{"access_token":"x","token_type":"Bearer"}`)
		return http.StatusOK
	})
	defer srv.Close()

	c := &ClientCredentials{Client: srv.Client(), TokenURL: srv.URL, ClientID: "public"}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientCredentials_Audience(t *testing.T) {
	srv := fakeTokenServer(t, func(form url.Values, w http.ResponseWriter) int {
		if got := form.Get("audience"); got != "https://api.example" {
			t.Errorf("audience = %q", got)
		}
		writeJSONBody(t, w, `{"access_token":"x","token_type":"Bearer"}`)
		return http.StatusOK
	})
	defer srv.Close()

	c := &ClientCredentials{
		Client:   srv.Client(),
		TokenURL: srv.URL,
		ClientID: testID,
		Audience: "https://api.example",
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientCredentials_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		writeJSONBody(t, w, `{"error":"invalid_client","error_description":"bad creds"}`)
	}))
	defer srv.Close()

	c := &ClientCredentials{Client: srv.Client(), TokenURL: srv.URL, ClientID: testID, ClientSecret: "s"}
	_, err := c.Token(context.Background())
	var oe *OAuth2Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v, want *OAuth2Error", err)
	}
	if oe.Code != "invalid_client" {
		t.Fatalf("Code = %q", oe.Code)
	}
	if oe.Status != http.StatusUnauthorized {
		t.Fatalf("Status = %d", oe.Status)
	}
}

func TestClientCredentials_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &ClientCredentials{Client: srv.Client(), TokenURL: srv.URL, ClientID: testID}
	_, err := c.Token(context.Background())
	var oe *OAuth2Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v, want *OAuth2Error", err)
	}
	if oe.Status != http.StatusInternalServerError {
		t.Fatalf("Status = %d", oe.Status)
	}
}

func TestClientCredentials_NoExpiryWhenAbsent(t *testing.T) {
	srv := fakeTokenServer(t, func(_ url.Values, w http.ResponseWriter) int {
		writeJSONBody(t, w, `{"access_token":"x","token_type":"Bearer"}`)
		return http.StatusOK
	})
	defer srv.Close()

	c := &ClientCredentials{Client: srv.Client(), TokenURL: srv.URL, ClientID: testID}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Expires.IsZero() {
		t.Fatalf("Expires should be zero, got %v", tok.Expires)
	}
}

func TestClientCredentials_MissingAccessToken(t *testing.T) {
	srv := fakeTokenServer(t, func(_ url.Values, w http.ResponseWriter) int {
		writeJSONBody(t, w, `{"token_type":"Bearer"}`)
		return http.StatusOK
	})
	defer srv.Close()

	c := &ClientCredentials{Client: srv.Client(), TokenURL: srv.URL, ClientID: testID}
	_, err := c.Token(context.Background())
	if !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v, want ErrInvalidTokenResponse", err)
	}
}

func TestClientCredentials_EmptyTokenURL(t *testing.T) {
	c := &ClientCredentials{ClientID: testID}
	_, err := c.Token(context.Background())
	if !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthorizationCode_Refresh(t *testing.T) {
	srv := fakeTokenServer(t, func(form url.Values, w http.ResponseWriter) int {
		if got := form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q", got)
		}
		if got := form.Get("refresh_token"); got != "rt-1" {
			t.Errorf("refresh_token = %q", got)
		}
		writeJSONBody(t, w,
			`{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-2"}`)
		return http.StatusOK
	})
	defer srv.Close()

	a := &AuthorizationCode{
		Client:       srv.Client(),
		TokenURL:     srv.URL,
		ClientID:     testID,
		ClientSecret: "sec",
		RefreshToken: "rt-1",
	}
	tok, err := a.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.Value != "at" {
		t.Fatalf("Value = %q", tok.Value)
	}
	if a.RefreshToken != "rt-2" {
		t.Fatalf("rotation failed: RefreshToken = %q", a.RefreshToken)
	}
}

func TestAuthorizationCode_KeepsRefreshTokenWhenAbsent(t *testing.T) {
	srv := fakeTokenServer(t, func(_ url.Values, w http.ResponseWriter) int {
		writeJSONBody(t, w, `{"access_token":"at","token_type":"Bearer","expires_in":60}`)
		return http.StatusOK
	})
	defer srv.Close()

	a := &AuthorizationCode{
		Client:       srv.Client(),
		TokenURL:     srv.URL,
		ClientID:     testID,
		RefreshToken: "rt-keep",
	}
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.RefreshToken != "rt-keep" {
		t.Fatalf("RefreshToken changed: %q", a.RefreshToken)
	}
}

func TestAuthorizationCode_MissingRefreshToken(t *testing.T) {
	//nolint:gosec // G101: literal URL, not a credential.
	a := &AuthorizationCode{ClientID: testID, TokenURL: "https://example.invalid/token"}
	_, err := a.Token(context.Background())
	var oe *OAuth2Error
	if !errors.As(err, &oe) || oe.Code != "invalid_request" {
		t.Fatalf("err = %v", err)
	}
}

func TestOAuth2Error_String(t *testing.T) {
	cases := []struct {
		err  *OAuth2Error
		want string
	}{
		{&OAuth2Error{Code: "invalid_grant", Description: "expired"}, "oauth2: invalid_grant: expired"},
		{&OAuth2Error{Code: "invalid_client"}, "oauth2: invalid_client"},
		{&OAuth2Error{Status: 502}, "oauth2: HTTP 502"},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

func TestParseInt64(t *testing.T) {
	if got, _ := jsonfast.DecodeInt64([]byte("42")); got != 42 {
		t.Fatalf("got %d", got)
	}
	if _, ok := jsonfast.DecodeInt64([]byte("xx")); ok {
		t.Fatal("expected ok=false for non-digit")
	}
	if _, ok := jsonfast.DecodeInt64(nil); ok {
		t.Fatal("expected ok=false for nil")
	}
}

func TestUnquoteKey(t *testing.T) {
	if got := unquoteKey([]byte(`"x"`)); got != "x" {
		t.Fatalf("got %q", got)
	}
	if got := unquoteKey([]byte(`x`)); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := unquoteKey([]byte(``)); got != "" {
		t.Fatalf("got %q", got)
	}
}

// BenchmarkParseTokenResponse measures the JSON parsing hot path.
func BenchmarkParseTokenResponse(b *testing.B) {
	body := []byte(
		`{"access_token":"AAAAAAA","token_type":"Bearer","expires_in":3600,"refresh_token":"RRRRR"}`)
	b.ReportAllocs()

	for b.Loop() {
		_ = parseTokenResponse(body)
	}
}

// BenchmarkClientCredentials measures the full grant flow against an
// in-process httptest server, including HTTP and JSON parsing.
func BenchmarkClientCredentials(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(b, w, `{"access_token":"x","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()

	c := &ClientCredentials{Client: srv.Client(), TokenURL: srv.URL, ClientID: testID, ClientSecret: "s"}
	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		tok, err := c.Token(ctx)
		if err != nil {
			b.Fatal(err)
		}
		_ = tok
	}
}
