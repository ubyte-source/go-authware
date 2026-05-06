package authware

import (
	"net/http"
	"strings"
	"testing"
)

func TestBearerAuthenticator_Success(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "https://example.com/api", http.NoBody)
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
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestBearerAuthenticator_Challenge(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := &authError{status: http.StatusUnauthorized, message: testFail, scheme: schemeBearer, code: "invalid_token"}
	status, header, msg := a.Challenge(aErr, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(header, schemeBearer) {
		t.Fatalf("header = %q", header)
	}
	if msg != testFail {
		t.Fatalf("message = %q", msg)
	}
}

func TestBearerAuthenticator_Metadata(t *testing.T) {
	a, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if md := a.Metadata(testHTTPS); md != nil {
		t.Fatalf("expected nil metadata, got %+v", md)
	}
}

// BenchmarkBearer measures the static bearer hot path on success.
func BenchmarkBearer(b *testing.B) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "supersecrettoken"}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer supersecrettoken")
	b.ReportAllocs()

	for b.Loop() {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBearerFail measures the rejection path.
func BenchmarkBearerFail(b *testing.B) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: "supersecrettoken"}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer wrongtoken12345")
	b.ReportAllocs()

	for b.Loop() {
		if _, err := auth.Authenticate(req); err == nil {
			b.Fatal("expected auth failure")
		}
	}
}
