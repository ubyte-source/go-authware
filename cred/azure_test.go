package cred

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAzureMSI_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Metadata"); got != "true" {
			t.Errorf("Metadata header = %q", got)
		}
		if got := r.URL.Query().Get("resource"); got != testAPIBaseURL {
			t.Errorf("resource = %q", got)
		}
		if got := r.URL.Query().Get("api-version"); got != azureMSIAPIVersion {
			t.Errorf("api-version = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		exp := fmt.Sprintf(`{"access_token":"msi-tok","token_type":"Bearer","expires_on":"%d"}`,
			time.Now().Add(time.Hour).Unix())
		writeJSONBody(t, w, exp)
	}))
	defer srv.Close()

	m := &AzureMSI{Client: srv.Client(), Endpoint: srv.URL, Resource: testAPIBaseURL}
	tok, err := m.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.Value != "msi-tok" {
		t.Fatalf("Value = %q", tok.Value)
	}
	if time.Until(tok.Expires) < time.Hour-time.Minute {
		t.Fatalf("Expires too close: %v", tok.Expires)
	}
}

func TestAzureMSI_ExpiresInFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"access_token":"x","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()

	m := &AzureMSI{Client: srv.Client(), Endpoint: srv.URL, Resource: testAPIBaseURL}
	tok, err := m.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(tok.Expires) < time.Hour-time.Minute {
		t.Fatalf("Expires too close: %v", tok.Expires)
	}
}

func TestAzureMSI_RejectsEmptyResource(t *testing.T) {
	if _, err := (&AzureMSI{}).Token(context.Background()); !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestAzureMSI_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		writeJSONBody(t, w, `{"error":"forbidden"}`)
	}))
	defer srv.Close()

	m := &AzureMSI{Client: srv.Client(), Endpoint: srv.URL, Resource: "x"}
	_, err := m.Token(context.Background())
	var oe *OAuth2Error
	if !errors.As(err, &oe) || oe.Status != http.StatusForbidden {
		t.Fatalf("err = %v", err)
	}
}

func TestAzureMSI_MissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	m := &AzureMSI{Client: srv.Client(), Endpoint: srv.URL, Resource: "x"}
	if _, err := m.Token(context.Background()); !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestAzureSPN_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/tenant-x/oauth2/v2.0/token") {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"access_token":"spn","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()

	s := &AzureSPN{
		Client:       srv.Client(),
		LoginHost:    srv.URL,
		TenantID:     "tenant-x",
		ClientID:     testID,
		ClientSecret: "sec",
		Resource:     "https://api.example",
	}
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.Value != "spn" {
		t.Fatalf("Value = %q", tok.Value)
	}
}

func TestAzureSPN_DefaultScope(t *testing.T) {
	var seenScope string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		seenScope = r.FormValue("scope")
		w.Header().Set("Content-Type", "application/json")
		writeJSONBody(t, w, `{"access_token":"x","token_type":"Bearer"}`)
	}))
	defer srv.Close()

	s := &AzureSPN{
		Client:    srv.Client(),
		LoginHost: srv.URL,
		TenantID:  "tenant-x",
		ClientID:  testID,
		Resource:  testAPIBaseURL,
	}
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seenScope != "https://api.example/.default" {
		t.Fatalf("scope = %q", seenScope)
	}
}

func TestAzureSPN_RejectsEmptyTenant(t *testing.T) {
	_, err := (&AzureSPN{ClientID: testID, Resource: "x"}).Token(context.Background())
	if !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestAzureSPN_RejectsEmptyClient(t *testing.T) {
	_, err := (&AzureSPN{TenantID: "t", Resource: "x"}).Token(context.Background())
	if !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestAzureSPN_RejectsMissingScope(t *testing.T) {
	_, err := (&AzureSPN{TenantID: "t", ClientID: testID}).Token(context.Background())
	if !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseInt64Quoted(t *testing.T) {
	cases := []struct {
		raw  []byte
		want int64
	}{
		{[]byte(`"1234"`), 1234},
		{[]byte(`5678`), 5678},
		{[]byte(`"bad"`), 0},
		{nil, 0},
		{[]byte{}, 0},
	}
	for _, tc := range cases {
		if got := parseInt64Quoted(tc.raw); got != tc.want {
			t.Errorf("parseInt64Quoted(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}
