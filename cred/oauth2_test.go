package cred

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// clientCredentialsProblems is the number of problems an empty config joins.
const (
	clientCredentialsProblems = 4
)

func clientCredentialsFor(t *testing.T, tokenURL string, mutate func(*ClientCredentialsConfig)) TokenSource {
	t.Helper()
	cfg := &ClientCredentialsConfig{ClientConfig: ClientConfig{
		TokenURL: tokenURL, ClientID: testClientID, ClientSecret: secret.New("s"),
	}}
	if mutate != nil {
		mutate(cfg)
	}
	src, err := NewClientCredentials(cfg)
	if err != nil {
		t.Fatalf("NewClientCredentials = %v, want a source", err)
	}
	return src
}

func TestNewClientCredentials(t *testing.T) {
	if _, err := NewClientCredentials(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewClientCredentials(nil) = %v, want ErrInvalidConfig", err)
	}
	plain := strings.Replace(idpEndpoint, "https", "http", 1)
	_, err := NewClientCredentials(&ClientCredentialsConfig{ClientConfig: ClientConfig{
		TokenURL: plain, AuthStyle: 7, Timeout: -time.Second,
	}})
	for _, want := range []error{ErrInsecureTokenURL, ErrInvalidConfig} {
		if !errors.Is(err, want) {
			t.Errorf("err = %v, want %v", err, want)
		}
	}
	if strings.Count(err.Error(), newline) != clientCredentialsProblems-1 {
		t.Errorf("err = %q, want four joined problems", err)
	}
}

func TestClientCredentialsConfigValidate(t *testing.T) {
	if err := (*ClientCredentialsConfig)(nil).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Validate() = %v, want ErrInvalidConfig", err)
	}
	cfg := &ClientCredentialsConfig{ClientConfig: ClientConfig{
		TokenURL: idpEndpoint, ClientID: testClientID, Scopes: []string{"read"},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	cfg.Scopes = []string{"read write"}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), `"read write"`) {
		t.Fatalf("spaced scope Validate() = %v, want ErrInvalidConfig naming the scope", err)
	}
	if _, err := NewClientCredentials(cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewClientCredentials err = %v, want the Validate problem", err)
	}
}

func TestClientCredentialsToken(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK, okToken))
	src := clientCredentialsFor(t, rec.srv.URL, func(c *ClientCredentialsConfig) {
		c.ClientID, c.ClientSecret = "tenant:app", secret.New("p+s%&w")
		c.Scopes, c.Audience = []string{"read", "write"}, "api"
	})
	before := time.Now()
	tok := nextToken(t, src)
	after := time.Now()
	if tok.Value.Reveal() != wantAccess || tok.Type != "Bearer" {
		t.Fatalf("token = %q %q, want Bearer %s", tok.Type, tok.Value.Reveal(), wantAccess)
	}
	if tok.Expires.Before(before.Add(time.Hour)) || tok.Expires.After(after.Add(time.Hour)) {
		t.Fatalf("Expires = %v, want an hour after a time in [%v, %v]", tok.Expires, before, after)
	}
	got := rec.requests()[0]
	want := "audience=api&grant_type=client_credentials&scope=read+write"
	if got.form.Encode() != want {
		t.Fatalf("form = %v, want %v", got.form, want)
	}
	r := &http.Request{Header: got.requestHeader}
	user, pass, ok := r.BasicAuth()
	if !ok || user != url.QueryEscape("tenant:app") || pass != url.QueryEscape("p+s%&w") {
		t.Fatalf("BasicAuth = %q, %q, %v, want the form-escaped client ID and secret", user, pass, ok)
	}
}

// TestClientCredentialsTokenPassesTheContext posts the grant under the context
// Token gets.
func TestClientCredentialsTokenPassesTheContext(t *testing.T) {
	transport := &markedTransport{}
	src, err := NewClientCredentials(&ClientCredentialsConfig{ClientConfig: ClientConfig{
		HTTPClient: &http.Client{Transport: transport}, TokenURL: idpEndpoint, ClientID: testClientID,
	}})
	if err != nil {
		t.Fatalf("NewClientCredentials = %v, want a source", err)
	}
	if _, err := src.Token(marked(t)); err != nil || transport.marked.Load() != 1 {
		t.Fatalf("Token = %v after %d marked requests, want nil after 1", err, transport.marked.Load())
	}
}

func TestClientCredentialsTokenAuthStyles(t *testing.T) {
	tests := []struct {
		name     string
		style    AuthStyle
		secret   secret.Value
		wantForm string
	}{
		{"params", AuthStyleParams, secret.New("s"),
			"client_id=client-id&client_secret=s&grant_type=client_credentials"},
		{"public", AuthStyleHeader, secret.Value{}, "client_id=client-id&grant_type=client_credentials"},
	}
	for _, tt := range tests {
		rec := newRecording(t, answer(http.StatusOK, okToken))
		src := clientCredentialsFor(t, rec.srv.URL, func(c *ClientCredentialsConfig) {
			c.ClientSecret, c.AuthStyle = tt.secret, tt.style
		})
		if _, err := src.Token(t.Context()); err != nil {
			t.Fatalf("Token = %v, want a token", err)
		}
		got := rec.requests()[0]
		if got.form.Encode() != tt.wantForm || got.requestHeader.Get(authorization) != "" {
			t.Errorf("%s: form %v, Authorization %q, want %s and none", tt.name, got.form,
				got.requestHeader.Get(authorization),
				tt.wantForm)
		}
	}
}

func TestClientCredentialsTokenErrors(t *testing.T) {
	tests := []struct {
		status    int
		body      string
		want      error
		transient bool
	}{
		{http.StatusUnauthorized, `{"error":"invalid_client"}`, nil, false},
		{http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, nil, true},
		{http.StatusOK, `{"token_type":"Bearer"}`, ErrInvalidTokenResponse, false},
		{http.StatusOK, okToken + `{}`, ErrInvalidTokenResponse, false},
		{http.StatusOK, `{"access_token":"at","token_type":"Be arer"}`, ErrInvalidTokenResponse, false},
	}
	for _, tt := range tests {
		rec := newRecording(t, answer(tt.status, tt.body))
		_, err := clientCredentialsFor(t, rec.srv.URL, nil).Token(t.Context())
		if tt.want != nil {
			if !errors.Is(err, tt.want) || !strings.HasPrefix(err.Error(), "cred: client credentials: ") {
				t.Errorf("%s: err = %v, want %v named after the grant", tt.body, err, tt.want)
			}
			continue
		}
		var oe *OAuth2Error
		if !errors.As(err, &oe) || oe.Status != tt.status || oe.Transient() != tt.transient {
			t.Errorf("%s: Token = %v, want an *OAuth2Error of status %d, transient %t", tt.body, err, tt.status,
				tt.transient)
		}
	}
}

func TestClientCredentialsTokenRefusesRedirect(t *testing.T) {
	sink := newRecording(t, answer(http.StatusOK, okToken))
	redirect := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.srv.URL, http.StatusTemporaryRedirect)
	})
	_, err := clientCredentialsFor(t, redirect.URL, nil).Token(t.Context())
	var oe *OAuth2Error
	if !errors.As(err, &oe) || oe.Status != http.StatusTemporaryRedirect {
		t.Fatalf("Token(redirect) = %v, want an *OAuth2Error of status 307", err)
	}
	if n := len(sink.requests()); n != 0 {
		t.Fatalf("redirect target requests = %d, want 0", n)
	}
}

// ExampleNewClientCredentials fetches a token with the client credentials
// grant, caches it, and sends it on every request of an http.Client.
func ExampleNewClientCredentials() {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`); err != nil {
			log.Print(err)
		}
	}))
	api := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header.Get("Authorization"))
	}))
	clientSecret := secret.New("the client secret of orders-sync")
	src, err := NewClientCredentials(&ClientCredentialsConfig{
		ClientConfig: ClientConfig{
			TokenURL:     idp.URL + "/oauth2/token",
			ClientID:     "orders-sync",
			ClientSecret: clientSecret,
			Scopes:       []string{"orders.read"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	cached, err := NewCachedSource(src)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: NewTransport(nil, AsSigner(cached))}
	defer idp.Close()
	defer api.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, api.URL, http.NoBody)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := resp.Body.Close(); err != nil {
		fmt.Println(err)
	}
	// Output: Bearer at-1
}

// ExampleNewClientCredentials_azure gets the token of an Azure service principal
// from its tenant's v2.0 endpoint, the client secret sent in the form.
func ExampleNewClientCredentials_azure() {
	login := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
		fmt.Println(r.PostFormValue("client_id"), r.PostFormValue("scope"))
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`); err != nil {
			log.Print(err)
		}
	}))
	defer login.Close()
	client, loginHost := login.Client(), login.URL
	tenantID, resource := "contoso.onmicrosoft.com", "https://graph.microsoft.com"
	clientSecret := secret.New("the client secret of orders-sync")
	src, err := NewClientCredentials(&ClientCredentialsConfig{
		ClientConfig: ClientConfig{
			HTTPClient:   client,
			TokenURL:     loginHost + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token",
			ClientID:     "orders-sync",
			ClientSecret: clientSecret,
			Scopes:       []string{resource + "/.default"},
			AuthStyle:    AuthStyleParams,
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	tok, err := src.Token(context.Background())
	if err != nil || tok == nil {
		fmt.Println(tok, err)
		return
	}
	fmt.Println(tok.Value.Reveal())
	// Output: /contoso.onmicrosoft.com/oauth2/v2.0/token
	// orders-sync https://graph.microsoft.com/.default
	// at-1
}
