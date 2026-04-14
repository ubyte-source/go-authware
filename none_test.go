package authware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowAllAuthenticator(t *testing.T) {
	a, err := New(&Config{Mode: ModeNone}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeNone {
		t.Fatalf("Method = %q", id.Method)
	}
}

func TestAllowAllAuthenticator_Challenge(t *testing.T) {
	a, err := New(&Config{Mode: ModeNone}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := &authError{status: http.StatusUnauthorized, message: "fail", scheme: "Bearer", code: "invalid_token"}
	status, header, msg := a.Challenge(aErr, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if header == "" {
		t.Fatal("expected WWW-Authenticate header for Bearer scheme")
	}
	if msg != "fail" {
		t.Fatalf("message = %q", msg)
	}
}

func TestAllowAllAuthenticator_Metadata(t *testing.T) {
	a, err := New(&Config{Mode: ModeNone}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if md := a.Metadata("https://example.com"); md != nil {
		t.Fatalf("expected nil metadata, got %+v", md)
	}
}
