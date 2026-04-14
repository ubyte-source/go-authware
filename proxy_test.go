package authware

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewOAuthProxy_NilOnEmptyConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if p := NewOAuthProxy(&Config{}, log); p != nil {
		t.Fatal("expected nil for empty config")
	}
}

func TestNewOAuthProxy_NilOnMissingClientID(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
	}, log)
	if p != nil {
		t.Fatal("expected nil when OAuthClientID is empty")
	}
}

func TestNewOAuthProxy_NilOnMissingServers(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewOAuthProxy(&Config{
		OAuthClientID: "client-id",
	}, log)
	if p != nil {
		t.Fatal("expected nil when OAuthAuthorizationServers is empty")
	}
}

func TestNewOAuthProxy_Valid(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "client-id",
	}, log)
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.clientID != "client-id" {
		t.Fatalf("clientID = %q", p.clientID)
	}
}

func TestNewOAuthProxy_NilLogger(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "client-id",
	}, nil)
	if p == nil {
		t.Fatal("expected non-nil proxy with nil logger")
	}
	if p.log == nil {
		t.Fatal("expected default logger to be set")
	}
}

func TestNewOAuthProxy_CopiesServers(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	servers := []string{"https://a.com", "https://b.com"}
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: servers,
		OAuthClientID:             "id",
	}, log)
	// Mutate original slice — proxy should not be affected.
	servers[0] = "https://mutated.com"
	if p.authorizationServers[0] != "https://a.com" {
		t.Fatal("proxy should have its own copy of servers")
	}
}

// ── ASMetadataHandler ───────────────────────────────────────

func fakeUpstreamAS(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(body)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
}

func validUpstreamJSON() string {
	return `{` +
		`"issuer":"https://fake-issuer.example.com",` +
		`"authorization_endpoint":"https://fake-issuer.example.com/authorize",` +
		`"token_endpoint":"https://fake-issuer.example.com/token",` +
		`"response_types_supported":["code"],` +
		`"code_challenge_methods_supported":["S256"]` +
		`}`
}

// assertMetaString checks that meta[key] equals want.
func assertMetaString(t *testing.T, meta map[string]any, key, want string) {
	t.Helper()
	if meta[key] != want {
		t.Fatalf("%s = %v, want %q", key, meta[key], want)
	}
}

// assertMetaArray checks that meta[key] is a non-empty []any with first == want.
func assertMetaArray(t *testing.T, meta map[string]any, key, wantFirst string) {
	t.Helper()
	arr, ok := meta[key].([]any)
	if !ok || len(arr) == 0 || arr[0] != wantFirst {
		t.Fatalf("%s = %v", key, meta[key])
	}
}

func TestASMetadataHandler_Success(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON())
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "my-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", http.NoBody)
	p.ASMetadataHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", cc)
	}

	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertMetaString(t, meta, "issuer", "http://example.com")
	assertMetaString(t, meta, "authorization_endpoint", "http://example.com/authorize")
	assertMetaString(t, meta, "token_endpoint", "http://example.com/token")
	assertMetaString(t, meta, "registration_endpoint", "http://example.com/register")
	assertMetaArray(t, meta, "response_types_supported", "code")
	assertMetaArray(t, meta, "token_endpoint_auth_methods_supported", "none")
	assertMetaArray(t, meta, "code_challenge_methods_supported", "S256")

	gt, ok := meta["grant_types_supported"].([]any)
	if !ok || len(gt) < 2 {
		t.Fatalf("grant_types_supported = %v", meta["grant_types_supported"])
	}
}

func TestASMetadataHandler_StoresUpstreamEndpoints(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON())
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if p.upstreamTokenEndpoint != "https://fake-issuer.example.com/token" {
		t.Fatalf("upstreamTokenEndpoint = %q", p.upstreamTokenEndpoint)
	}
	if p.upstreamAuthzEndpoint != "https://fake-issuer.example.com/authorize" {
		t.Fatalf("upstreamAuthzEndpoint = %q", p.upstreamAuthzEndpoint)
	}
}

func TestASMetadataHandler_UpstreamUnavailable(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"http://127.0.0.1:1"}, // connection refused
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestASMetadataHandler_Caching(t *testing.T) {
	var hits int32
	fakeAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(validUpstreamJSON())); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	handler := p.ASMetadataHandler()
	for range 5 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 upstream fetch (sync.Once), got %d", got)
	}
}

func TestASMetadataHandler_InvalidJSON(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, `not-json`)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestASMetadataHandler_MissingIssuer(t *testing.T) {
	body := `{"authorization_endpoint":"https://example.com/authorize",` +
		`"token_endpoint":"https://example.com/token"}`
	fakeAS := fakeUpstreamAS(t, body)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for missing issuer, got %d", w.Code)
	}
}

func TestASMetadataHandler_MissingAuthorizationEndpoint(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, `{"issuer":"https://example.com","token_endpoint":"https://example.com/token"}`)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for missing authorization_endpoint, got %d", w.Code)
	}
}

func TestASMetadataHandler_UpstreamHTTPError(t *testing.T) {
	fakeAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestASMetadataHandler_FallbackToOAuthASURL(t *testing.T) {
	// Upstream only responds on /.well-known/oauth-authorization-server, not openid-configuration.
	var hits int32
	fakeAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if strings.Contains(r.URL.Path, "openid-configuration") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(validUpstreamJSON())); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fallback URL), got %d", w.Code)
	}
	// Should have tried both URLs.
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 hits (openid-config + oauth-as), got %d", got)
	}
}

func TestASMetadataHandler_TrailingSlashTrimmed(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON())
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL + "///"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with trailing slashes trimmed, got %d", w.Code)
	}
}

// ── RegisterHandler ─────────────────────────────────────────

// assertMapHasKey checks that a key exists in the map.
func assertMapHasKey(t *testing.T, m map[string]any, key string) {
	t.Helper()
	if _, ok := m[key]; !ok {
		t.Fatalf("missing key %q", key)
	}
}

func TestRegisterHandler_ReturnsClientID(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "my-azure-client-id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	body := `{"client_name":"test","redirect_uris":["https://app.example.com/callback"]}`
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	p.RegisterHandler().ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertMetaString(t, resp, "client_id", "my-azure-client-id")
	assertMetaString(t, resp, "token_endpoint_auth_method", "none")
	assertMapHasKey(t, resp, "client_id_issued_at")
	assertMetaArray(t, resp, "response_types", "code")

	gt, ok := resp["grant_types"].([]any)
	if !ok || len(gt) < 2 {
		t.Fatalf("grant_types = %v", resp["grant_types"])
	}
}

func TestRegisterHandler_EmptyBody(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", http.NoBody)
	p.RegisterHandler().ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 even with empty body, got %d", w.Code)
	}
}

// ── TokenHandler ────────────────────────────────────────────

func TestTokenHandler_ProxiesToUpstream(t *testing.T) {
	// Fake upstream token endpoint.
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request was proxied correctly.
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		if !strings.Contains(string(body), "grant_type=authorization_code") {
			t.Errorf("body = %q, missing grant_type", body)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(`{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Manually set upstream token endpoint (normally set by ASMetadataHandler).
	p.upstreamTokenEndpoint = fakeToken.URL

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc123&redirect_uri=https://app.example.com/callback"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["access_token"] != "tok-123" {
		t.Fatalf("access_token = %v", resp["access_token"])
	}
}

func TestTokenHandler_NoUpstreamEndpoint(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// upstreamTokenEndpoint is empty — not yet fetched.

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc"))
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestTokenHandler_UpstreamError(t *testing.T) {
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if _, wErr := w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.upstreamTokenEndpoint = fakeToken.URL

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=expired"))
	p.TokenHandler().ServeHTTP(w, r)

	// Should pass through the upstream error status.
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("body = %q, missing error", w.Body.String())
	}
}

func TestTokenHandler_UpstreamUnavailable(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.upstreamTokenEndpoint = "http://127.0.0.1:1" // connection refused

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc"))
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestTokenHandler_ForwardsHeaders(t *testing.T) {
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(`{"access_token":"t"}`)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.upstreamTokenEndpoint = fakeToken.URL

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc"))
	p.TokenHandler().ServeHTTP(w, r)

	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("Pragma = %q", w.Header().Get("Pragma"))
	}
}

// ── AuthorizeHandler ────────────────────────────────────────

func TestAuthorizeHandler_Redirect(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON())
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Trigger upstream fetch so upstreamAuthzEndpoint is populated.
	w0 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w0, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if w0.Code != http.StatusOK {
		t.Fatalf("metadata: expected 200, got %d", w0.Code)
	}

	// AuthorizeHandler should 302-redirect to the upstream authorize endpoint.
	w := httptest.NewRecorder()
	authzURL := "/authorize?" +
		"response_type=code&client_id=cid" +
		"&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback" +
		"&code_challenge=abc&code_challenge_method=S256&state=xyz"
	r := httptest.NewRequest(http.MethodGet, authzURL, http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://fake-issuer.example.com/authorize?") {
		t.Fatalf("Location = %q, expected upstream authorize URL", loc)
	}
	if !strings.Contains(loc, "code_challenge=abc") {
		t.Fatalf("Location missing code_challenge: %q", loc)
	}
	if !strings.Contains(loc, "state=xyz") {
		t.Fatalf("Location missing state: %q", loc)
	}
}

func TestAuthorizeHandler_NoQueryParams(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON())
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w0 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w0, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/authorize", http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://fake-issuer.example.com/authorize" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestAuthorizeHandler_NoUpstreamEndpoint(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"https://example.com"},
		OAuthClientID:             "id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// upstreamAuthzEndpoint is empty — not yet fetched.

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/authorize?state=abc", http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

// ── End-to-end: metadata → register → authorize → token ────

// newE2EProxy creates a proxy pointing at the given fake IDP for E2E testing.
func newE2EProxy(t *testing.T, fakeIDPURL string) *OAuthProxy {
	t.Helper()
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeIDPURL},
		OAuthClientID:             "e2e-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	return p
}

// fakeIDPServer creates an httptest server that serves both well-known metadata
// and token endpoint responses, emulating an upstream IdP.
func fakeIDPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ".well-known"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, wErr := w.Write([]byte(validUpstreamJSON())); wErr != nil {
				t.Errorf("write: %v", wErr)
			}
		case strings.HasSuffix(r.URL.Path, "/token"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, wErr := w.Write([]byte(`{"access_token":"real-token","token_type":"Bearer"}`)); wErr != nil {
				t.Errorf("write: %v", wErr)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestOAuthProxy_EndToEnd(t *testing.T) {
	fakeIDP := fakeIDPServer(t)
	defer fakeIDP.Close()

	p := newE2EProxy(t, fakeIDP.URL)

	t.Run("metadata", func(t *testing.T) {
		w := httptest.NewRecorder()
		p.ASMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("register", func(t *testing.T) {
		w := httptest.NewRecorder()
		p.RegisterHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/oauth/register",
			strings.NewReader(`{"client_name":"e2e"}`)))
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", w.Code)
		}
		var reg map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
			t.Fatalf("decode: %v", err)
		}
		assertMetaString(t, reg, "client_id", "e2e-client")
	})

	t.Run("token", func(t *testing.T) {
		p.upstreamTokenEndpoint = fakeIDP.URL + "/token"
		w := httptest.NewRecorder()
		p.TokenHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader("grant_type=authorization_code&code=test-code")))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var tok map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil {
			t.Fatalf("decode: %v", err)
		}
		assertMetaString(t, tok, "access_token", "real-token")
	})
}
