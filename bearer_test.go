package authware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuthenticator_Success(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api", http.NoBody)
	req.Header.Set("Authorization", "Bearer secret")
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeBearer {
		t.Fatal("expected bearer identity")
	}
	if id.Subject != "static-bearer" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

func TestBearerAuthenticator_WrongToken(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: "right"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer wrong")
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestBearerAuthenticator_MissingHeader(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: "right"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestBearerAuthenticator_Challenge(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: "tok"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := &authError{status: http.StatusUnauthorized, message: "fail", scheme: "Bearer", code: "invalid_token"}
	status, header, msg := a.Challenge(aErr, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(header, "Bearer") {
		t.Fatalf("header = %q", header)
	}
	if msg != "fail" {
		t.Fatalf("message = %q", msg)
	}
}

func TestBearerAuthenticator_Metadata(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: "tok"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if md := a.Metadata("https://example.com"); md != nil {
		t.Fatalf("expected nil metadata, got %+v", md)
	}
}
