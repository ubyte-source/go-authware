package cred

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGCPMetadata_AccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Metadata-Flavor"); got != gcpMetadataFlavor {
			t.Errorf("Metadata-Flavor = %q", got)
		}
		if !strings.HasSuffix(r.URL.Path, gcpTokenPath) {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("scopes"); got != "https://www.googleapis.com/auth/cloud-platform" {
			t.Errorf("scopes = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"access_token":"gcp-tok","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()

	g := &GCPMetadata{Client: srv.Client(), Endpoint: srv.URL}
	tok, err := g.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.Value != "gcp-tok" {
		t.Fatalf("Value = %q", tok.Value)
	}
	if time.Until(tok.Expires) < time.Hour-time.Minute {
		t.Fatalf("Expires too close: %v", tok.Expires)
	}
}

func TestGCPMetadata_CustomScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("scopes"); got != "scope.a,scope.b" {
			t.Errorf("scopes = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"access_token":"x","token_type":"Bearer"}`)
	}))
	defer srv.Close()

	g := &GCPMetadata{
		Client:   srv.Client(),
		Endpoint: srv.URL,
		Scopes:   []string{"scope.a", "scope.b"},
	}
	if _, err := g.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGCPMetadata_IDToken(t *testing.T) {
	const fakeJWT = "header.payload.sig"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, gcpIdentityPath) {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("audience"); got != "https://peer.example" {
			t.Errorf("audience = %q", got)
		}
		if got := r.URL.Query().Get("format"); got != "full" {
			t.Errorf("format = %q", got)
		}
		writeJSONBody(t, w, fakeJWT+"\n")
	}))
	defer srv.Close()

	g := &GCPMetadata{Client: srv.Client(), Endpoint: srv.URL, Audience: "https://peer.example"}
	tok, err := g.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.Value != fakeJWT {
		t.Fatalf("Value = %q", tok.Value)
	}
	if !tok.Expires.IsZero() {
		t.Fatalf("Expires should be zero for ID token, got %v", tok.Expires)
	}
}

func TestGCPMetadata_IDTokenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	g := &GCPMetadata{Client: srv.Client(), Endpoint: srv.URL, Audience: "x"}
	if _, err := g.Token(context.Background()); !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestGCPMetadata_AccessTokenMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	g := &GCPMetadata{Client: srv.Client(), Endpoint: srv.URL}
	if _, err := g.Token(context.Background()); !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestGCPMetadata_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSONBody(t, w, "metadata service overloaded")
	}))
	defer srv.Close()

	g := &GCPMetadata{Client: srv.Client(), Endpoint: srv.URL}
	_, err := g.Token(context.Background())
	var oe *OAuth2Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v, want *OAuth2Error", err)
	}
	if oe.Status != http.StatusServiceUnavailable {
		t.Fatalf("Status = %d", oe.Status)
	}
}
