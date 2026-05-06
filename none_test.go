package authware

import (
	"net/http"
	"testing"
)

func TestAllowAllAuthenticator(t *testing.T) {
	a, err := New(&Config{Mode: ModeNone}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
	aErr := &authError{status: http.StatusUnauthorized, message: testFail, scheme: "Bearer", code: "invalid_token"}
	status, header, msg := a.Challenge(aErr, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if header == "" {
		t.Fatal("expected WWW-Authenticate header for Bearer scheme")
	}
	if msg != testFail {
		t.Fatalf("message = %q", msg)
	}
}

func TestAllowAllAuthenticator_Metadata(t *testing.T) {
	a, err := New(&Config{Mode: ModeNone}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if md := a.Metadata(testHTTPS); md != nil {
		t.Fatalf("expected nil metadata, got %+v", md)
	}
}

// BenchmarkNone measures the allow-all path.
func BenchmarkNone(b *testing.B) {
	auth, err := New(&Config{Mode: ModeNone}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}
