package authware

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		OAuthAuthorizationServers: []string{testHTTPS},
	}, log)
	if p != nil {
		t.Fatal("expected nil when OAuthClientID is empty")
	}
}

func TestNewOAuthProxy_NilOnMissingServers(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewOAuthProxy(&Config{
		OAuthClientID: testClientID,
	}, log)
	if p != nil {
		t.Fatal("expected nil when OAuthAuthorizationServers is empty")
	}
}

func TestNewOAuthProxy_Valid(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testClientID,
	}, log)
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.clientID != testClientID {
		t.Fatalf("clientID = %q", p.clientID)
	}
}

func TestNewOAuthProxy_NilLogger(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testClientID,
	}, nil)
	if p == nil {
		t.Fatal("expected non-nil proxy with nil logger")
	}
	if p.log == nil {
		t.Fatal("expected default logger to be set")
	}
}

func TestNewOAuthProxy_CopiesRequiredScopes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	scopes := []string{"api://app/.default", testScopeOpenID}
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
		OAuthRequiredScopes:       scopes,
	}, log)
	// Mutate original slice — proxy should not be affected.
	scopes[0] = "mutated"
	if p.requiredScopes[0] != "api://app/.default" {
		t.Fatal("proxy should have its own copy of requiredScopes")
	}
}

func TestNewOAuthProxy_CopiesServers(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	servers := []string{"https://a.com", "https://b.com"}
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: servers,
		OAuthClientID:             testID,
	}, log)
	// Mutate original slice — proxy should not be affected.
	servers[0] = "https://mutated.com"
	if p.authorizationServers[0] != "https://a.com" {
		t.Fatal("proxy should have its own copy of servers")
	}
}

// fakeUpstreamAS builds a mock OIDC AS server. body is invoked with the
// running server URL so the metadata document can publish a self-consistent
// issuer (the production validator binds endpoints to the issuer host).
func fakeUpstreamAS(t *testing.T, body func(serverURL string) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(body(srv.URL))); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	})
	srv.Start()
	return srv
}

// validUpstreamJSON returns a complete AS metadata document anchored at issuer.
func validUpstreamJSON(issuer string) string {
	return `{` +
		`"issuer":"` + issuer + `",` +
		`"authorization_endpoint":"` + issuer + `/authorize",` +
		`"token_endpoint":"` + issuer + `/token",` +
		`"response_types_supported":["code"],` +
		`"code_challenge_methods_supported":["S256"]` +
		`}`
}

// staticUpstreamBody returns a body builder that ignores the server URL.
func staticUpstreamBody(s string) func(string) string {
	return func(string) string { return s }
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
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testClient,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodGet, "/.well-known/oauth-authorization-server", http.NoBody)
	p.ASMetadataHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != testTypeJSON {
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

func TestASMetadataHandler_ScopesSupportedIncludesRequiredScopes(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
		OAuthRequiredScopes:       []string{"api://00000000-0000-0000-0000-000000000001/.default"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}

	arr, ok := meta["scopes_supported"].([]any)
	if !ok {
		t.Fatalf("scopes_supported not an array: %v", meta["scopes_supported"])
	}

	// Must contain the OIDC base scopes plus the API scope.
	found := make(map[string]bool, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("scopes_supported element not a string: %v", v)
		}
		found[s] = true
	}
	wantScopes := []string{testScopeOpenID, "profile", "email", "offline_access",
		"api://00000000-0000-0000-0000-000000000001/.default"}
	for _, want := range wantScopes {
		if !found[want] {
			t.Fatalf("scopes_supported missing %q, got %v", want, arr)
		}
	}
}

func TestASMetadataHandler_ScopesSupportedNoDuplicates(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	// testScopeOpenID is already a base OIDC scope — should not be duplicated.
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
		OAuthRequiredScopes:       []string{testScopeOpenID, "custom"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr, ok := meta["scopes_supported"].([]any)
	if !ok {
		t.Fatalf("scopes_supported not an array: %v", meta["scopes_supported"])
	}
	count := 0
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("scopes_supported element not a string: %v", v)
		}
		if s == testScopeOpenID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("openid appears %d times, want 1; scopes = %v", count, arr)
	}
}

func TestASMetadataHandler_ScopesSupportedNoExtraScopes(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	// No extra required scopes — should have just the OIDC base scopes.
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr, ok := meta["scopes_supported"].([]any)
	if !ok {
		t.Fatalf("scopes_supported not an array: %v", meta["scopes_supported"])
	}
	// Base scopes only.
	if len(arr) != 4 {
		t.Fatalf("expected 4 base scopes, got %d: %v", len(arr), arr)
	}
}

func TestASMetadataHandler_StoresUpstreamEndpoints(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	st := p.loadState()
	if st == nil {
		t.Fatal("upstream state nil after fetch")
	}
	if st.tokenEndpoint != fakeAS.URL+"/token" {
		t.Fatalf("tokenEndpoint = %q", st.tokenEndpoint)
	}
	if st.authzEndpoint != fakeAS.URL+"/authorize" {
		t.Fatalf("authzEndpoint = %q", st.authzEndpoint)
	}
}

func TestASMetadataHandler_UpstreamUnavailable(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"http://127.0.0.1:1"}, // connection refused
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestASMetadataHandler_Caching(t *testing.T) {
	var hits atomic.Int32
	fakeAS := httptest.NewUnstartedServer(nil)
	fakeAS.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(validUpstreamJSON(fakeAS.URL))); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	})
	fakeAS.Start()
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	handler := p.ASMetadataHandler()
	for range 5 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 upstream fetch (sync.Once), got %d", got)
	}
}

func TestASMetadataHandler_InvalidJSON(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, staticUpstreamBody(`not-json`))
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestASMetadataHandler_MissingIssuer(t *testing.T) {
	body := `{"authorization_endpoint":"https://example.com/authorize",` +
		`"token_endpoint":"https://example.com/token"}`
	fakeAS := fakeUpstreamAS(t, staticUpstreamBody(body))
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for missing issuer, got %d", w.Code)
	}
}

func TestASMetadataHandler_MissingAuthorizationEndpoint(t *testing.T) {
	body := `{"issuer":"https://example.com","token_endpoint":"https://example.com/token"}`
	fakeAS := fakeUpstreamAS(t, staticUpstreamBody(body))
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

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
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestASMetadataHandler_FallbackToOAuthASURL(t *testing.T) {
	// Upstream only responds on /.well-known/oauth-authorization-server, not openid-configuration.
	var hits atomic.Int32
	fakeAS := httptest.NewUnstartedServer(nil)
	fakeAS.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.URL.Path, "openid-configuration") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(validUpstreamJSON(fakeAS.URL))); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	})
	fakeAS.Start()
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fallback URL), got %d", w.Code)
	}
	// Should have tried both URLs.
	if got := hits.Load(); got != 2 {
		t.Fatalf("expected 2 hits (openid-config + oauth-as), got %d", got)
	}
}

func TestASMetadataHandler_TrailingSlashTrimmed(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL + "///"},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with trailing slashes trimmed, got %d", w.Code)
	}
}

// assertMapHasKey checks that a key exists in the map.
func assertMapHasKey(t *testing.T, m map[string]any, key string) {
	t.Helper()
	if _, ok := m[key]; !ok {
		t.Fatalf("missing key %q", key)
	}
}

func TestRegisterHandler_ReturnsClientID(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             "my-azure-client-id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	body := `{"client_name":"test","redirect_uris":["https://app.example.com/callback"]}`
	r := newReq(t, http.MethodPost, "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", testTypeJSON)
	p.RegisterHandler().ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != testTypeJSON {
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

	// redirect_uris must be echoed back from the request.
	assertMetaArray(t, resp, "redirect_uris", "https://app.example.com/callback")
}

func TestRegisterHandler_EchosRedirectURIs(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             "azure-id",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	body := `{"redirect_uris":["https://claude.ai/api/mcp/auth_callback","https://app.example.com/cb"]}`
	r := newReq(t, http.MethodPost, "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", testTypeJSON)
	w := httptest.NewRecorder()
	p.RegisterHandler().ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	uris, ok := resp["redirect_uris"].([]any)
	if !ok {
		t.Fatalf("redirect_uris missing or wrong type: %v", resp["redirect_uris"])
	}
	if len(uris) != 2 {
		t.Fatalf("expected 2 redirect_uris, got %v", uris)
	}
	if uris[0] != "https://claude.ai/api/mcp/auth_callback" {
		t.Errorf("redirect_uris[0] = %v", uris[0])
	}
	if uris[1] != "https://app.example.com/cb" {
		t.Errorf("redirect_uris[1] = %v", uris[1])
	}
}

func TestRegisterHandler_EmptyBody(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/register", http.NoBody)
	p.RegisterHandler().ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 even with empty body, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// No redirect_uris in request → response must return an empty array.
	uris, ok := resp["redirect_uris"].([]any)
	if !ok || len(uris) != 0 {
		t.Fatalf("expected redirect_uris:[], got %v", resp["redirect_uris"])
	}
}

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

		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(`{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Manually set upstream token endpoint (normally set by ASMetadataHandler).
	p.setStateForTest(fakeToken.URL, "")

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc123&redirect_uri=https://app.example.com/callback"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != testTypeJSON {
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
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// upstreamTokenEndpoint is empty — not yet fetched.

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestTokenHandler_UpstreamError(t *testing.T) {
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		if _, wErr := w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(fakeToken.URL, "")

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=expired"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest("http://127.0.0.1:1", "") // connection refused

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestTokenHandler_ForwardsHeaders(t *testing.T) {
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testTypeJSON)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(`{"access_token":"t"}`)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(fakeToken.URL, "")

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w, r)

	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("Pragma = %q", w.Header().Get("Pragma"))
	}
}

func TestAuthorizeHandler_Redirect(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Trigger upstream fetch so upstreamAuthzEndpoint is populated.
	w0 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w0, newReq(t, http.MethodGet, "/", http.NoBody))
	if w0.Code != http.StatusOK {
		t.Fatalf("metadata: expected 200, got %d", w0.Code)
	}

	// AuthorizeHandler should 302-redirect to the upstream authorize endpoint.
	w := httptest.NewRecorder()
	authzURL := "/authorize?" +
		"response_type=code&client_id=cid" +
		"&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback" +
		"&code_challenge=abc&code_challenge_method=S256&state=xyz"
	r := newReq(t, http.MethodGet, authzURL, http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, fakeAS.URL+"/authorize?") {
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
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w0 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w0, newReq(t, http.MethodGet, "/", http.NoBody))

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodGet, "/authorize", http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != fakeAS.URL+"/authorize" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestBuildUpstreamScopeStr(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		want     string
		scopes   []string
	}{
		{
			name:     "no scopes returns empty",
			resource: testResourceAPI,
			scopes:   nil,
			want:     "",
		},
		{
			name:     "qualifies bare scope with resource",
			resource: "api://00000000-0000-0000-0000-000000000001",
			scopes:   []string{testResourceMyAPI},
			want:     "openid offline_access api://00000000-0000-0000-0000-000000000001/myapi",
		},
		{
			name:     "strips trailing slash from resource",
			resource: "api://abc/",
			scopes:   []string{testRead},
			want:     "openid offline_access api://abc/read",
		},
		{
			name:     "already-qualified scope not double-qualified",
			resource: testResourceAPI,
			scopes:   []string{"api://abc/myapi"},
			want:     "openid offline_access api://abc/myapi",
		},
		{
			name:     "no resource passes scope as-is",
			resource: "",
			scopes:   []string{testResourceMyAPI},
			want:     "openid offline_access myapi",
		},
		{
			name:     "deduplicates openid and offline_access if in scopes",
			resource: testResourceAPI,
			scopes:   []string{testScopeOpenID, testResourceMyAPI},
			want:     "openid offline_access api://abc/myapi",
		},
		{
			name:     "multiple scopes all qualified",
			resource: testResourceAPI,
			scopes:   []string{testRead, testWrite},
			want:     "openid offline_access api://abc/read api://abc/write",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildUpstreamScopeStr(tc.resource, tc.scopes)
			if got != tc.want {
				t.Fatalf("buildUpstreamScopeStr(%q, %v) = %q, want %q",
					tc.resource, tc.scopes, got, tc.want)
			}
		})
	}
}

func TestAuthorizeHandler_RewritesScopeForAzureAD(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	// Simulate Azure AD setup: short scope name in OAuthRequiredScopes,
	// full resource URI in OAuthResource. The handler must qualify the scope
	// before forwarding to the upstream IdP.
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "fake-client-id",
		OAuthRequiredScopes:       []string{testResourceMyAPI},
		OAuthResource:             "api://00000000-0000-0000-0000-000000000001",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w0 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w0, newReq(t, http.MethodGet, "/", http.NoBody))

	// MCP client sends the short scope (stripped prefix) — the proxy must fix it.
	w := httptest.NewRecorder()
	q := "response_type=code&client_id=fake-client-id&scope=openid+offline_access+myapi&state=xyz"
	r := newReq(t, http.MethodGet, "/authorize?"+q, http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	gotScope := parsed.Query().Get("scope")
	wantScope := "openid offline_access api://00000000-0000-0000-0000-000000000001/myapi"
	if gotScope != wantScope {
		t.Fatalf("scope in redirect = %q, want %q", gotScope, wantScope)
	}
	// Other params must be preserved.
	if parsed.Query().Get("state") != "xyz" {
		t.Fatalf("state missing from redirect: %q", loc)
	}
}

func TestAuthorizeHandler_NoScopeRewriteWhenNoResource(t *testing.T) {
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	// No OAuthResource configured: scope is not resource-qualified.
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             testID,
		OAuthRequiredScopes:       []string{testResourceMyAPI},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w0 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w0, newReq(t, http.MethodGet, "/", http.NoBody))

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodGet, "/authorize?scope=myapi&state=s1", http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	// upstreamScopeStr = "openid offline_access myapi" (no resource → no prefix)
	gotScope := parsed.Query().Get("scope")
	if !strings.Contains(gotScope, testResourceMyAPI) {
		t.Fatalf("scope %q should contain myapi", gotScope)
	}
	if strings.Contains(gotScope, "api://") {
		t.Fatalf("scope %q should not contain api:// when no resource configured", gotScope)
	}
}

func TestTokenHandler_RejectsWrongContentType(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(testTokenURL, "")

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader(`{"grant_type":"authorization_code"}`))
	r.Header.Set("Content-Type", testTypeJSON)
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong Content-Type, got %d", w.Code)
	}
}

func TestTokenHandler_RejectsMissingContentType(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(testTokenURL, "")

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=abc"))
	// No Content-Type header set.
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing Content-Type, got %d", w.Code)
	}
}

func TestTokenHandler_RejectsUnsupportedGrantType(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(testTokenURL, "")

	for _, gt := range []string{"client_credentials", "password", "urn:ietf:params:oauth:grant-type:jwt-bearer"} {
		w := httptest.NewRecorder()
		r := newReq(t, http.MethodPost, "/oauth/token",
			strings.NewReader("grant_type="+gt+"&client_id=x"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		p.TokenHandler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("grant_type=%q: expected 400, got %d", gt, w.Code)
		}
	}
}

func TestTokenHandler_AcceptsRefreshToken(t *testing.T) {
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		if _, wErr := w.Write([]byte(`{"access_token":"new-tok","token_type":"Bearer"}`)); wErr != nil {
			t.Errorf("write: %v", wErr)
		}
	}))
	defer fakeToken.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(fakeToken.URL, "")

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=refresh_token&refresh_token=rt-abc"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for refresh_token grant, got %d", w.Code)
	}
}

func TestASMetadataHandler_MultiServerFailover(t *testing.T) {
	// First server is unreachable; second is valid.
	fakeAS := fakeUpstreamAS(t, validUpstreamJSON)
	defer fakeAS.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{"http://127.0.0.1:1", fakeAS.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with fallback server, got %d", w.Code)
	}
	st := p.loadState()
	if st == nil || st.tokenEndpoint != fakeAS.URL+"/token" {
		t.Fatalf("tokenEndpoint = %#v", st)
	}
}

func TestAuthorizeHandler_NoUpstreamEndpoint(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// upstreamAuthzEndpoint is empty — not yet fetched.

	w := httptest.NewRecorder()
	r := newReq(t, http.MethodGet, "/authorize?state=abc", http.NoBody)
	p.AuthorizeHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

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
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ".well-known"):
			w.Header().Set("Content-Type", testTypeJSON)
			w.WriteHeader(http.StatusOK)
			if _, wErr := w.Write([]byte(validUpstreamJSON(srv.URL))); wErr != nil {
				t.Errorf("write: %v", wErr)
			}
		case strings.HasSuffix(r.URL.Path, "/token"):
			w.Header().Set("Content-Type", testTypeJSON)
			w.WriteHeader(http.StatusOK)
			if _, wErr := w.Write([]byte(`{"access_token":"real-token","token_type":"Bearer"}`)); wErr != nil {
				t.Errorf("write: %v", wErr)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv.Start()
	return srv
}

func TestOAuthProxy_EndToEnd(t *testing.T) {
	fakeIDP := fakeIDPServer(t)
	defer fakeIDP.Close()

	p := newE2EProxy(t, fakeIDP.URL)

	t.Run("metadata", func(t *testing.T) {
		w := httptest.NewRecorder()
		p.ASMetadataHandler().ServeHTTP(w, newReq(t, http.MethodGet, "/", http.NoBody))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("register", func(t *testing.T) {
		w := httptest.NewRecorder()
		p.RegisterHandler().ServeHTTP(w, newReq(t, http.MethodPost, "/oauth/register",
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
		p.setStateForTest(fakeIDP.URL+"/token", "")
		w := httptest.NewRecorder()
		req := newReq(t, http.MethodPost, "/oauth/token",
			strings.NewReader("grant_type=authorization_code&code=test-code"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		p.TokenHandler().ServeHTTP(w, req)
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

func TestFormValue(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		field string
		want  []byte // nil = not found; []byte{} = found with empty value
	}{
		{"field at start", "key=val", testKey, []byte("val")},
		{"field in middle", "a=1&key=val&b=2", testKey, []byte("val")},
		{"field at end no amp", "a=1&key=val", testKey, []byte("val")},
		{"empty value at start", "key=&b=2", testKey, []byte("")},
		{"empty value at end", "a=1&key=", testKey, []byte("")},
		{"not found", "other=value&more=stuff", testKey, nil},
		{"empty body", "", testKey, nil},
		// Suffix prevention: "xkey=bad" must NOT match field testKey.
		{"suffix prevention", "xkey=bad&key=good", testKey, []byte("good")},
		// First of duplicates is returned.
		{"first duplicate", "key=first&key=second", testKey, []byte("first")},
		// Field with & in next param.
		{"value ends before amp", "key=hello&other=x", testKey, []byte("hello")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formValue([]byte(tc.body), tc.field)
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("formValue(%q, %q): nil mismatch — got nil=%v, want nil=%v",
					tc.body, tc.field, got == nil, tc.want == nil)
			}
			if tc.want != nil && !bytes.Equal(got, tc.want) {
				t.Fatalf("formValue(%q, %q) = %q, want %q",
					tc.body, tc.field, got, tc.want)
			}
		})
	}
}

func TestInjectClientCredentials(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testClient,
		OAuthClientSecret:         "my-secret",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if p == nil {
		t.Fatal("NewOAuthProxy returned nil")
	}

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			"appends to empty body",
			"",
			"client_id=my-client&client_secret=my-secret",
		},
		{
			"appends to existing params",
			"grant_type=authorization_code&code=abc",
			"grant_type=authorization_code&code=abc&client_id=my-client&client_secret=my-secret",
		},
		{
			"replaces existing client_id",
			"client_id=old&grant_type=code",
			"grant_type=code&client_id=my-client&client_secret=my-secret",
		},
		{
			"replaces existing client_secret",
			"client_secret=old&grant_type=code",
			"grant_type=code&client_id=my-client&client_secret=my-secret",
		},
		{
			"replaces both",
			"client_id=old&client_secret=old&grant_type=code",
			"grant_type=code&client_id=my-client&client_secret=my-secret",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(p.injectClientCredentials([]byte(tc.body)))
			if got != tc.want {
				t.Fatalf("injectClientCredentials(%q)\n  got  %q\n  want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestTokenHandler_InjectsClientCredentials verifies the full end-to-end path:
// the proxy strips existing client_id from the MCP client body and injects
// the preconfigured confidential-client credentials before forwarding.
func TestTokenHandler_InjectsClientCredentials(t *testing.T) {
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("upstream read: %v", readErr)
		}
		gotBody = string(b)
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`{"access_token":"t","token_type":"Bearer"}`)); writeErr != nil {
			t.Errorf("upstream write: %v", writeErr)
		}
	}))
	defer upstream.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             "proxy-client",
		OAuthClientSecret:         "proxy-secret",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(upstream.URL, "")

	// MCP client sends its own (wrong) client_id — proxy must replace it.
	body := "grant_type=authorization_code&code=xyz&client_id=mcp-client"
	r := newReq(t, http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Parse what the upstream received.
	vals := make(map[string]string)
	for pair := range strings.SplitSeq(gotBody, "&") {
		k, v, found := strings.Cut(pair, "=")
		if found {
			vals[k] = v
		}
	}
	if vals["client_id"] != "proxy-client" {
		t.Errorf("client_id forwarded = %q, want %q", vals["client_id"], "proxy-client")
	}
	if vals["client_secret"] != "proxy-secret" {
		t.Errorf("client_secret forwarded = %q, want %q", vals["client_secret"], "proxy-secret")
	}
	if vals["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %q", vals["grant_type"])
	}
	// Original mcp-client must be gone.
	if strings.Contains(gotBody, "mcp-client") {
		t.Errorf("upstream body still contains mcp-client: %s", gotBody)
	}
}

// TestTokenHandler_BodyReadError verifies the read-error path in readTokenBody.
func TestTokenHandler_BodyReadError(t *testing.T) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(testTokenURL, "")

	r := newReq(t, http.MethodPost, "/token", &errBody{})
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on body read error, got %d", w.Code)
	}
}

type errBody struct{}

func (e *errBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (e *errBody) Close() error             { return nil }

// BenchmarkProxy_RegisterHandler measures the DCR shim handler throughput.
func BenchmarkProxy_RegisterHandler(b *testing.B) {
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             "bench-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := p.RegisterHandler()
	body := `{"client_name":"bench"}`
	b.ReportAllocs()

	for b.Loop() {
		rec := httptest.NewRecorder()
		req := newReq(b, http.MethodPost, "/oauth/register", strings.NewReader(body))
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkProxy_ASMetadata measures the cached AS metadata response path.
func BenchmarkProxy_ASMetadata(b *testing.B) {
	fakeAS := httptest.NewUnstartedServer(nil)
	fakeAS.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		body := `{"issuer":"` + fakeAS.URL + `",` +
			`"authorization_endpoint":"` + fakeAS.URL + `/authorize",` +
			`"token_endpoint":"` + fakeAS.URL + `/token"}`
		if _, err := w.Write([]byte(body)); err != nil {
			b.Errorf("write: %v", err)
		}
	})
	fakeAS.Start()
	defer fakeAS.Close()
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{fakeAS.URL},
		OAuthClientID:             "bench-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := p.ASMetadataHandler()
	warmup := httptest.NewRecorder()
	handler.ServeHTTP(warmup, newReq(b, http.MethodGet, "/", http.NoBody))
	if warmup.Code != http.StatusOK {
		b.Fatalf("warmup failed: %d", warmup.Code)
	}
	b.ReportAllocs()

	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newReq(b, http.MethodGet, "/", http.NoBody))
	}
}

// BenchmarkProxy_TokenHandler measures the token proxy handler throughput.
func BenchmarkProxy_TokenHandler(b *testing.B) {
	fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"access_token":"t","token_type":"Bearer"}`)); err != nil {
			b.Errorf("write: %v", err)
		}
	}))
	defer fakeToken.Close()
	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{testHTTPS},
		OAuthClientID:             "bench-client",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setStateForTest(fakeToken.URL, "")
	handler := p.TokenHandler()
	b.ReportAllocs()

	for b.Loop() {
		rec := httptest.NewRecorder()
		req := newReq(b, http.MethodPost, "/oauth/token",
			strings.NewReader("grant_type=authorization_code&code=bench"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(rec, req)
	}
}

// TestOAuthProxy_RetriesAfterUpstreamFailure pins the architectural
// invariant that a transient failure on upstream AS metadata fetch does
// not wedge the proxy permanently. Before this regression test, the
// implementation used sync.Once and would never re-attempt.
func TestOAuthProxy_RetriesAfterUpstreamFailure(t *testing.T) {
	t.Parallel()
	var mode atomic.Int32 // 0 = fail, 1 = succeed

	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if mode.Load() == 0 {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body := `{"issuer":"` + srv.URL + `",` +
			`"authorization_endpoint":"` + srv.URL + `/auth",` +
			`"token_endpoint":"` + srv.URL + `/token"}`
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	srv.Start()
	defer srv.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{srv.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// First call: upstream fails — must surface 502.
	w1 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w1, newReq(t, http.MethodGet, "/", http.NoBody))
	if w1.Code != http.StatusBadGateway {
		t.Fatalf("first call: expected 502, got %d", w1.Code)
	}

	// Upstream recovers.
	mode.Store(1)

	// Second call: must retry and succeed.
	w2 := httptest.NewRecorder()
	p.ASMetadataHandler().ServeHTTP(w2, newReq(t, http.MethodGet, "/", http.NoBody))
	if w2.Code != http.StatusOK {
		t.Fatalf("second call after upstream recovery: expected 200, got %d (body=%s)", w2.Code, w2.Body.String())
	}
}

// TestOAuthProxy_TokenEndpoint_RetriesAfterFailure verifies the same
// retry behavior reaches the TokenHandler path.
func TestOAuthProxy_TokenEndpoint_RetriesAfterFailure(t *testing.T) {
	t.Parallel()
	var asMode atomic.Int32

	// Combined AS + token server so issuer-host validation
	// host validation accepts the published endpoints.
	asSrv := httptest.NewUnstartedServer(nil)
	asSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/token" {
			w.Header().Set("Content-Type", testTypeJSON)
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, `{"access_token":"x","token_type":"Bearer"}`); err != nil {
				t.Errorf("write: %v", err)
			}
			return
		}
		if asMode.Load() == 0 {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", testTypeJSON)
		w.WriteHeader(http.StatusOK)
		body := `{"issuer":"` + asSrv.URL + `",` +
			`"authorization_endpoint":"` + asSrv.URL + `/auth",` +
			`"token_endpoint":"` + asSrv.URL + `/token"}`
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	asSrv.Start()
	defer asSrv.Close()

	p := NewOAuthProxy(&Config{
		OAuthAuthorizationServers: []string{asSrv.URL},
		OAuthClientID:             testID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// First TokenHandler call fails because upstream metadata not ready.
	w1 := httptest.NewRecorder()
	r1 := newReq(t, http.MethodPost, "/token", http.NoBody)
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w1, r1)
	if w1.Code != http.StatusBadGateway {
		t.Fatalf("first call: expected 502, got %d", w1.Code)
	}

	asMode.Store(1)

	// Second call: ensure_TokenEndpoint retries and the upstream request fires.
	w2 := httptest.NewRecorder()
	r2 := newReq(t, http.MethodPost, "/token",
		strings.NewReader("grant_type=authorization_code&code=x"))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.TokenHandler().ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second call after AS recovery: expected 200, got %d", w2.Code)
	}
}
