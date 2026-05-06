package authware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthCheckHandler_Success(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := AuthCheckHandler(auth)
	req := newReq(t, http.MethodGet, "/check", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("X-Auth-Subject") != "static-bearer" {
		t.Fatalf("X-Auth-Subject = %q", rec.Header().Get("X-Auth-Subject"))
	}
	if rec.Header().Get("X-Auth-Method") != string(ModeBearer) {
		t.Fatalf("X-Auth-Method = %q", rec.Header().Get("X-Auth-Method"))
	}
}

func TestAuthCheckHandler_Unauthorized(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := AuthCheckHandler(auth)
	req := newReq(t, http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAuthCheckHandler_OAuth_WWWAuthenticate(t *testing.T) {
	auth, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://iss.example.com", OAuthHMACSecret: "s",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := AuthCheckHandler(auth)
	req := newReq(t, http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestAuthCheckHandler_Scopes(t *testing.T) {
	mock := &mockAuthenticator{
		identity: Identity{Subject: testUser, Method: ModeOAuth, Scopes: []string{testRead, testWrite}},
	}
	handler := AuthCheckHandler(mock)
	req := newReq(t, http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("X-Auth-Scopes"); got != testReadW {
		t.Fatalf("X-Auth-Scopes = %q", got)
	}
}

func TestAuthCheckHandler_NoScopes(t *testing.T) {
	mock := &mockAuthenticator{
		identity: Identity{Subject: testUser, Method: ModeBearer},
	}
	handler := AuthCheckHandler(mock)
	req := newReq(t, http.MethodGet, "/check", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("X-Auth-Scopes"); got != "" {
		t.Fatalf("expected no X-Auth-Scopes header, got %q", got)
	}
}

// mockAuthenticator is a test helper used by handler tests.
type mockAuthenticator struct {
	err      error
	identity Identity
}

func (m *mockAuthenticator) Authenticate(_ *http.Request) (*Identity, error) {
	if m.err != nil {
		return nil, m.err
	}
	id := m.identity
	return &id, nil
}

func (m *mockAuthenticator) Challenge(err error, url string) (code int, scheme, params string) {
	return challengeFromError("test", err, url)
}

func (m *mockAuthenticator) Metadata(_ string) *ProtectedResourceMetadata {
	return nil
}

// BenchmarkAuthCheckHandler_Success measures the handler hot path on success.
func BenchmarkAuthCheckHandler_Success(b *testing.B) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	handler := AuthCheckHandler(auth)
	req := newReq(b, http.MethodGet, "/check", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	rec := newNopWriter()
	b.ReportAllocs()

	for b.Loop() {
		rec.reset()
		handler.ServeHTTP(rec, req)
	}
}

func TestSanitizeHeaderValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "clean ASCII", in: "alice@example.com", want: "alice@example.com"},
		{name: "unicode allowed", in: "ünïcödé", want: "ünïcödé"},
		{name: "CR replaced", in: "value\rinjected", want: "value injected"},
		{name: "LF replaced", in: "value\ninjected", want: "value injected"},
		{name: "CRLF replaced", in: "value\r\ninjected", want: "value  injected"},
		{name: "tab replaced", in: "value\tnext", want: "value next"},
		{name: "DEL replaced", in: "value\x7Fnext", want: "value next"},
		{name: "null replaced", in: "value\x00next", want: "value next"},
		{name: "empty", in: "", want: ""},
		{name: "all controls", in: "\r\n\t\x00", want: "    "},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitiseHeaderValue(tt.in)
			if got != tt.want {
				t.Fatalf("sanitiseHeaderValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
			for i := range len(got) {
				c := got[i]
				if c < 0x20 || c == 0x7F {
					t.Fatalf("control byte %#x at index %d in result %q", c, i, got)
				}
			}
		})
	}
}

func TestSanitizeHeaderValue_DefendsAgainstClassicCRLFInjection(t *testing.T) {
	t.Parallel()
	attack := "victim\r\nSet-Cookie: session=evil"
	got := sanitiseHeaderValue(attack)
	if strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("CR/LF leaked through sanitiser: %q", got)
	}
}
