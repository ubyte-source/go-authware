package authware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestIdentityFromContext_Empty(t *testing.T) {
	if _, ok := IdentityFromContext(context.Background()); ok {
		t.Fatal("expected ok=false")
	}
}

func TestWithIdentity_Roundtrip(t *testing.T) {
	id := &Identity{Subject: testUser1, Method: ModeBearer}
	ctx := WithIdentity(context.Background(), id)
	got, ok := IdentityFromContext(ctx)
	if !ok || got.Subject != testUser1 {
		t.Fatalf("roundtrip failed: %+v", got)
	}
}

func TestMiddleware_Success(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := IdentityFromContext(r.Context()); !ok {
			t.Error("expected identity in context")
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(auth)(inner)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMiddleware_Unauthorized(t *testing.T) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	})
	handler := Middleware(auth)(inner)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_OAuth_SetsWWWAuthenticate(t *testing.T) {
	auth, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://iss.example.com", OAuthHMACSecret: "s",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := Middleware(auth)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestRequireScopes_Allowed(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireScopes(testRead, testWrite)(inner)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req = req.WithContext(WithIdentity(req.Context(), &Identity{
		Subject: "u", Method: ModeOAuth, Scopes: []string{testRead, testWrite, testAdmin},
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRequireScopes_Forbidden(t *testing.T) {
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	})
	handler := RequireScopes(testAdmin)(inner)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req = req.WithContext(WithIdentity(req.Context(), &Identity{
		Subject: "u", Method: ModeOAuth, Scopes: []string{testRead},
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireScopes_NoIdentity(t *testing.T) {
	handler := RequireScopes(testRead)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireCapability_NoChecks(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })
	handler := RequireCapability()(inner)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("expected pass-through with no checks")
	}
}

func TestRequireCapability_Composition(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := RequireCapability(
		HasMethod(ModeOAuth),
		HasAnyScope(testRead, testAdmin),
		HasClaim(testClaimIss, testIssuerURL),
	)(inner)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req = req.WithContext(WithIdentity(req.Context(), &Identity{
		Subject: "u", Method: ModeOAuth,
		Scopes:    []string{testAdmin},
		claimsRaw: `{"iss":"https://issuer.example.com"}`,
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRequireCapability_FailingCheck(t *testing.T) {
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Error("inner called") })
	handler := RequireCapability(HasSubject(testAdmin))(inner)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req = req.WithContext(WithIdentity(req.Context(), &Identity{Subject: testUser, Method: ModeBearer}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireCapability_Unauthenticated(t *testing.T) {
	handler := RequireCapability(HasMethod(ModeBearer))(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newReq(t, http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestCapabilityPredicates(t *testing.T) {
	id := &Identity{
		Subject:   testUser1,
		Method:    ModeOAuth,
		Scopes:    []string{testRead, testWrite},
		claimsRaw: `{"role":"admin","lvl":3}`,
	}
	cases := []struct {
		c    Capability
		name string
		want bool
	}{
		{c: HasScope(testRead), name: "HasScope hit", want: true},
		{c: HasScope("delete"), name: "HasScope miss", want: false},
		{c: HasAnyScope("delete", testWrite), name: "HasAnyScope hit", want: true},
		{c: HasAnyScope("delete"), name: "HasAnyScope miss", want: false},
		{c: HasAnyScope(), name: "HasAnyScope empty", want: false},
		{c: HasAllScopes(testRead, testWrite), name: "HasAllScopes hit", want: true},
		{c: HasAllScopes(testRead, "delete"), name: "HasAllScopes miss", want: false},
		{c: HasAllScopes(), name: "HasAllScopes empty", want: true},
		{c: HasClaim("role", testAdmin), name: "HasClaim hit", want: true},
		{c: HasClaim("role", testUser), name: "HasClaim miss value", want: false},
		{c: HasClaim("absent", "x"), name: "HasClaim missing key", want: false},
		{c: HasClaim("lvl", int64(3)), name: "HasClaim int64 hit", want: true},
		{c: HasMethod(ModeOAuth), name: "HasMethod hit", want: true},
		{c: HasMethod(ModeBearer), name: "HasMethod miss", want: false},
		{c: HasSubject(testUser1), name: "HasSubject hit", want: true},
		{c: HasSubject("other"), name: "HasSubject miss", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c(id); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSlicesContains(t *testing.T) {
	if !slices.Contains([]string{"a", "b", "c"}, "b") {
		t.Fatal("expected hit")
	}
	if slices.Contains([]string{"a", "b"}, "z") {
		t.Fatal("expected miss")
	}
	if slices.Contains([]string(nil), "a") {
		t.Fatal("expected miss on nil")
	}
}

// BenchmarkMiddleware_Bearer measures the full middleware stack with bearer auth.
func BenchmarkMiddleware_Bearer(b *testing.B) {
	auth, err := New(&Config{Mode: ModeBearer, BearerToken: testTok}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(auth)(inner)
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	rec := newNopWriter()
	b.ReportAllocs()

	for b.Loop() {
		rec.reset()
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkRequireCapability_AllScopes measures the post-auth capability gate.
func BenchmarkRequireCapability_AllScopes(b *testing.B) {
	handler := RequireCapability(HasAllScopes(testRead, testWrite))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	req = req.WithContext(WithIdentity(req.Context(), &Identity{
		Subject: "u", Method: ModeOAuth, Scopes: []string{testRead, testWrite, testAdmin},
	}))
	rec := newNopWriter()
	b.ReportAllocs()

	for b.Loop() {
		rec.reset()
		handler.ServeHTTP(rec, req)
	}
}

// nopWriter is a zero-allocation http.ResponseWriter for benchmarks.
type nopWriter struct {
	header http.Header
	status int
}

func newNopWriter() *nopWriter           { return &nopWriter{header: http.Header{}} }
func (n *nopWriter) Header() http.Header { return n.header }
func (n *nopWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
func (n *nopWriter) WriteHeader(code int) { n.status = code }
func (n *nopWriter) reset() {
	for k := range n.header {
		delete(n.header, k)
	}
	n.status = 0
}
