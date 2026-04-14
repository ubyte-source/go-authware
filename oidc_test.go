package authware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverOIDC_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(map[string]any{
			"issuer":   "https://issuer.example.com",
			"jwks_uri": "https://issuer.example.com/jwks",
		}); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	}))
	defer srv.Close()

	cfg, err := discoverOIDC(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("discoverOIDC: %v", err)
	}
	if cfg.JWKSURI != "https://issuer.example.com/jwks" {
		t.Fatalf("JWKSURI = %q", cfg.JWKSURI)
	}
	if cfg.Issuer != "https://issuer.example.com" {
		t.Fatalf("Issuer = %q", cfg.Issuer)
	}
}

func TestDiscoverOIDC_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := discoverOIDC(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error for server error")
	}
}

func TestDiscoverOIDC_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, wErr := w.Write([]byte("not json{{{")); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer srv.Close()

	if _, err := discoverOIDC(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDiscoverOIDC_MissingJWKSURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(map[string]any{
			"issuer": "https://issuer.example.com",
		}); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	}))
	defer srv.Close()

	if _, err := discoverOIDC(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error for missing jwks_uri")
	}
}

func TestDiscoverOIDC_InvalidURL(t *testing.T) {
	if _, err := discoverOIDC(context.Background(), http.DefaultClient, "http://\x01"); err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestDiscoverOIDC_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discoverOIDC(ctx, http.DefaultClient, "http://localhost:1"); err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestDiscoverOIDC_TrailingSlash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(map[string]any{
			"issuer":   "https://issuer.example.com",
			"jwks_uri": "https://issuer.example.com/jwks",
		}); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	}))
	defer srv.Close()

	cfg, err := discoverOIDC(context.Background(), srv.Client(), srv.URL+"/")
	if err != nil {
		t.Fatalf("discoverOIDC with trailing slash: %v", err)
	}
	if cfg.JWKSURI != "https://issuer.example.com/jwks" {
		t.Fatalf("JWKSURI = %q", cfg.JWKSURI)
	}
}

// closeErrOIDCBody wraps an io.Reader with a Close that always errors.
type closeErrOIDCBody struct{ io.Reader }

func (b *closeErrOIDCBody) Close() error { return errors.New("close error") }

type closeErrOIDCTransport struct{ body string }

func (t *closeErrOIDCTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       &closeErrOIDCBody{Reader: strings.NewReader(t.body)},
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func TestDiscoverOIDC_CloseError(t *testing.T) {
	validJSON, mErr := json.Marshal(map[string]any{
		"issuer":   "https://issuer.example.com",
		"jwks_uri": "https://issuer.example.com/jwks",
	})
	if mErr != nil {
		t.Fatalf("marshal: %v", mErr)
	}
	client := &http.Client{Transport: &closeErrOIDCTransport{body: string(validJSON)}}
	_, err := discoverOIDC(context.Background(), client, "https://issuer.example.com")
	if err == nil {
		t.Fatal("expected error from Body.Close")
	}
	if !strings.Contains(err.Error(), "close error") {
		t.Fatalf("unexpected error: %v", err)
	}
}
