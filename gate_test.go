package authware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// Literals of the gate tests: check headers, the endpoint mounted, the resource
// member, a byte that spoils a credential, the allocations of refusals and of a
// decoded token's text, and a token whose header is no base64url.
const (
	headerSubject      = "X-Auth-Subject"
	headerMethod       = "X-Auth-Method"
	headerCacheControl = "Cache-Control"
	testEndpoint       = "/mcp"
	memberResource     = "resource"
	wrongByte          = "x"
	denyAllocs         = 2
	oauthDenyAllocs    = 3
	decodedTextAllocs  = 1
	malformedJWT       = "a.b.c"
)

// testBearerMethod is the documented bearer token transport.
const testBearerMethod = "header"

// oauthToken signs a token of testUser accepted by validOAuth, granting scope.
func oauthToken(tb testing.TB, scope string) string {
	tb.Helper()
	claims := claimsWith(map[string]any{claimExp: time.Now().Add(time.Hour).Unix(), claimScope: scope})
	return signToken(tb, algHS256, []byte(testLongSecret), "", claims)
}

func staticConfigs() map[Mode]*Config {
	long := secret.New(testLongSecret)
	return map[Mode]*Config{
		ModeNone:   {Mode: ModeNone},
		ModeBearer: {Mode: ModeBearer, Bearer: BearerConfig{Token: long}},
		ModeAPIKey: {Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: long}},
		ModeMTLS:   {Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSubjects: []string{testCN}}},
		ModeOAuth:  validOAuth(),
	}
}

func TestNew(t *testing.T) {
	for mode, cfg := range staticConfigs() {
		if g := mustGate(t, cfg); g.Mode() != mode {
			t.Errorf("Mode() = %q, want %q", g.Mode(), mode)
		}
	}
	if _, err := New(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(nil) = %v, want ErrInvalidConfig", err)
	}
	if _, err := New(&Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(empty) = %v, want ErrInvalidConfig", err)
	}
}

func TestNewDoesNotAliasConfig(t *testing.T) {
	cfg := validOAuth()
	cfg.OAuth.RequiredScopes = []string{testRead}
	g := mustGate(t, cfg)
	cfg.OAuth.RequiredScopes[0] = testAdmin
	if oauth, ok := g.auth.(*oauthAuthenticator); !ok || !slices.Equal(oauth.required, []string{testRead}) {
		t.Fatalf("required scopes = %+v, want [%s] after the caller edits its slice", g.auth, testRead)
	}
}

func TestGateAuthenticate(t *testing.T) {
	g := mustGate(t, staticConfigs()[ModeBearer])
	r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+testLongSecret)
	id, err := g.Authenticate(r)
	if err != nil || id.Mode() != ModeBearer {
		t.Fatalf("Authenticate = %v, %v, want a bearer identity", id, err)
	}
	r.Header.Set(headerAuthorization, "Bearer wrong")
	if id, err = g.Authenticate(r); !errors.Is(err, ErrInvalidCredentials) || id != nil {
		t.Fatalf("Authenticate(wrong token) = %v, %v, want ErrInvalidCredentials", id, err)
	}
}

func TestGateMiddlewareChallenges(t *testing.T) {
	meta := "http://api.example/.well-known/oauth-protected-resource/mcp%22x"
	tests := []struct {
		mode   Mode
		status int
		want   string
	}{
		{ModeBearer, http.StatusUnauthorized, `Bearer realm="restricted"`},
		{ModeAPIKey, http.StatusUnauthorized, `ApiKey realm="restricted"`},
		{ModeOAuth, http.StatusUnauthorized, `Bearer realm="restricted", resource_metadata="` + meta + `"`},
		{ModeMTLS, http.StatusForbidden, ""},
	}
	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			h := mustGate(t, staticConfigs()[tc.mode]).Middleware(http.HandlerFunc(func(http.ResponseWriter,
				*http.Request) {
				t.Fatal("next reached without credentials, want the challenge")
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, newReq(t, http.MethodGet, "http://api.example/mcp%22x", http.NoBody))
			got, body := w.Header().Values(headerChallenge), strings.ToLower(http.StatusText(tc.status))+"\n"
			if w.Code != tc.status || strings.Join(got, "|") != tc.want || (tc.want == "") != (got == nil) ||
				w.Body.String() != body {
				t.Fatalf("Middleware = %d %q %q, want %d %q %q", w.Code, got, w.Body.String(), tc.status, tc.want, body)
			}
		})
	}
}

// TestGateMiddlewareKeepsTheContext serves next under a child of the context
// of the request.
func TestGateMiddlewareKeepsTheContext(t *testing.T) {
	kept := false
	h := mustGate(t, &Config{Mode: ModeNone}).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, stored := IdentityFromContext(r.Context())
		kept = stored && isMarked(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), newReq(t, http.MethodGet, pathRoot, http.NoBody).WithContext(marked(t)))
	if !kept {
		t.Fatal("Middleware served a context without the caller's values, want them and the identity")
	}
}

// TestOriginalPathAllocs reads a request without X-Original-URI without
// allocating.
func TestOriginalPathAllocs(t *testing.T) {
	r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	assertAllocs(t, 0, func() {
		if got := originalPath(r); got != "" {
			t.Fatalf("originalPath = %q, want empty", got)
		}
	})
}

func TestGateMiddlewareStoresIdentity(t *testing.T) {
	g := mustGate(t, validOAuth())
	var got *Identity
	h := g.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = IdentityFromContext(r.Context())
	}))
	r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+oauthToken(t, testRead))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || got.Subject() != testUser || !got.HasScope(testRead) {
		t.Fatalf("Middleware = %d with identity %+v, want 200 with %s granted %s", w.Code, got, testUser, testRead)
	}
	r.Header.Set(headerAuthorization, "Bearer "+oauthToken(t, testRead)+wrongByte)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	want := `Bearer realm="restricted", error="invalid_token", error_description="invalid JWT signature", ` +
		`resource_metadata="http://example.com/.well-known/oauth-protected-resource"`
	if w.Code != http.StatusUnauthorized || w.Header().Get(headerChallenge) != want {
		t.Fatalf("Middleware = %d %q, want 401 %q", w.Code, w.Header().Get(headerChallenge), want)
	}
}

// TestGateKeysUnavailable answers, from Middleware and CheckHandler, 503 with
// Retry-After and without a challenge while the keys are unavailable.
func TestGateKeysUnavailable(t *testing.T) {
	g := mustGate(t, unavailableKeys(t))
	r := bearerRequest(t, signToken(t, algRS256, []byte(testLongSecret), "k", testClaims()))
	if _, err := g.Authenticate(r); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("Authenticate = %v, want ErrKeysUnavailable", err)
	}
	for name, h := range map[string]http.Handler{
		"Middleware": g.Middleware(http.NotFoundHandler()), "CheckHandler": g.CheckHandler(),
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" ||
			w.Header().Get(headerChallenge) != "" || w.Body.String() != "service unavailable\n" {
			t.Fatalf("%s = %d %v %q, want 503 with Retry-After 30 and no challenge", name, w.Code, w.Header(),
				w.Body.String())
		}
	}
}

// TestGateMiddlewareKeyRefetchFails answers 503 with Retry-After to a token
// whose key is missing when the refetch it forces fails, and while that
// failure backs off.
func TestGateMiddlewareKeyRefetchFails(t *testing.T) {
	key := testRSAKey()
	srv := newJWKSServer(t, jwksDocument(t, publicJWK(t, key, map[string]any{memberKid: "a"})))
	h := mustGate(t, &Config{Mode: ModeOAuth, OAuth: OAuthConfig{Issuer: testIssuerURL, Audience: "a",
		JWKSURL: srv.URL}}).Middleware(http.NotFoundHandler())
	claims := map[string]any{claimIss: testIssuerURL, claimAud: "a", claimExp: time.Now().Add(time.Hour).Unix()}
	for _, st := range []struct {
		kid   string
		code  int
		retry string
	}{{"a", http.StatusNotFound, ""}, {"b", http.StatusServiceUnavailable, "30"},
		{"b", http.StatusServiceUnavailable, "30"}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, bearerRequest(t, signToken(t, algRS256, key, st.kid, claims)))
		if w.Code != st.code || w.Header().Get("Retry-After") != st.retry {
			t.Fatalf("Middleware(kid %s) = %d with Retry-After %q, want %d with %q", st.kid, w.Code,
				w.Header().Get("Retry-After"), st.code, st.retry)
		}
		srv.set(http.StatusServiceUnavailable, nil)
	}
	if n := srv.hits.Load(); n != 2 {
		t.Fatalf("JWKS requests = %d, want 2: the first fetch and the one forced refetch", n)
	}
}

func TestGateMiddlewarePublicURL(t *testing.T) {
	cfg := validOAuth()
	cfg.OAuth.PublicURL = testPublicURL
	h := mustGate(t, cfg).Middleware(http.NotFoundHandler())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(t, http.MethodGet, "http://internal:8080/mcp", http.NoBody))
	want := `resource_metadata="https://public.example/.well-known/oauth-protected-resource/mcp"`
	if !strings.HasSuffix(w.Header().Get(headerChallenge), want) {
		t.Fatalf("challenge = %q, want the suffix %q", w.Header().Get(headerChallenge), want)
	}
}

// serveRequire runs Require(checks...) for a request carrying id.
func serveRequire(t *testing.T, g *Gate, id *Identity, checks ...Capability) *httptest.ResponseRecorder {
	t.Helper()
	h := g.Require(checks...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := newReq(t, http.MethodGet, "http://api.example/tool", http.NoBody)
	if id != nil {
		r = r.WithContext(WithIdentity(r.Context(), id))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestGateRequire(t *testing.T) {
	g := mustGate(t, validOAuth())
	meta := `resource_metadata="http://api.example/.well-known/oauth-protected-resource/tool"`
	unauthorized := `Bearer realm="restricted", ` + meta
	id := scoped(testRead)
	tests := []struct {
		name   string
		id     *Identity
		checks []Capability
		status int
		header string
	}{
		{"no identity", nil, nil, http.StatusUnauthorized, unauthorized},
		{"no identity with checks", nil, []Capability{HasAllScopes()}, http.StatusUnauthorized, unauthorized},
		{"zero checks", id, nil, http.StatusNoContent, ""},
		{"passing", id, []Capability{HasAllScopes(testRead), HasSubject(testUser)}, http.StatusNoContent, ""},
		{"scope", id, []Capability{HasAllScopes(testRead), HasAllScopes(testRead, testWrite)}, http.StatusForbidden,
			`Bearer realm="restricted", error="insufficient_scope", error_description="missing required scope", ` +
				`scope="read write", ` + meta},
		{"empty scope", id, []Capability{HasAllScopes("")}, http.StatusForbidden,
			`Bearer realm="restricted", error="insufficient_scope", error_description="missing required scope", ` +
				meta},
		{"other", id, []Capability{HasSubject(testAdmin)}, http.StatusForbidden, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := serveRequire(t, g, tc.id, tc.checks...)
			if w.Code != tc.status || w.Header().Get(headerChallenge) != tc.header {
				t.Fatalf("Require = %d %q, want %d %q", w.Code, w.Header().Get(headerChallenge), tc.status,
					tc.header)
			}
		})
	}
}

// TestGateRequireDenyAllocs denies with the refusals Require builds once: what
// remains is the header, and in ModeOAuth the metadata URL of the request and
// the challenge naming it, X-Forwarded-Proto read in any case without a copy.
func TestGateRequireDenyAllocs(t *testing.T) {
	bare := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	identified := bare.WithContext(WithIdentity(bare.Context(), &Identity{mode: ModeBearer}))
	upper := bare.Clone(bare.Context())
	upper.Header.Set("X-Forwarded-Proto", "HTTPS")
	trusting := validOAuth()
	trusting.OAuth.TrustForwardedProto = true
	w := newBenchWriter()
	for _, tc := range []struct {
		cfg    *Config
		r      *http.Request
		status int
		allocs float64
		what   string
	}{
		{staticConfigs()[ModeBearer], bare, http.StatusUnauthorized, 1, "missing identity"},
		{staticConfigs()[ModeBearer], identified, http.StatusForbidden, 1, "failed check"},
		{validOAuth(), identified, http.StatusForbidden, 1, "failed OAuth check"},
		{validOAuth(), bare, http.StatusUnauthorized, oauthDenyAllocs, "missing OAuth identity"},
		{trusting, upper, http.StatusUnauthorized, oauthDenyAllocs, "forwarded HTTPS"},
	} {
		h := mustGate(t, tc.cfg).Require(HasMode(ModeAPIKey))(http.NotFoundHandler())
		t.Run(tc.what, func(t *testing.T) {
			assertAllocs(t, tc.allocs, func() {
				w.reset()
				h.ServeHTTP(w, tc.r)
				if w.status != tc.status {
					t.Fatalf("Require(%s) = %d, want %d", tc.what, w.status, tc.status)
				}
			})
		})
	}
}

func TestGateRequireCopiesChecks(t *testing.T) {
	g := mustGate(t, validOAuth())
	checks := []Capability{HasAllScopes(testRead)}
	mw := g.Require(checks...)
	checks[0] = HasAllScopes(testAdmin)
	h := mw(http.NotFoundHandler())
	r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), scoped(testRead))))
	if w.Code != http.StatusNotFound {
		t.Fatalf("Require = %d, want 404 from next: the checks were copied", w.Code)
	}
}

func TestGateRequireStaticModes(t *testing.T) {
	g := mustGate(t, staticConfigs()[ModeBearer])
	h := g.Require(HasAllScopes(testWrite))(http.NotFoundHandler())
	r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), scoped(testRead))))
	want := `Bearer realm="restricted", error="insufficient_scope", ` +
		`error_description="missing required scope", scope="write"`
	if w.Code != http.StatusForbidden || w.Header().Get(headerChallenge) != want ||
		w.Body.String() != "forbidden\n" {
		t.Fatalf("Require = %d %q %q, want 403 %q", w.Code, w.Header().Get(headerChallenge), w.Body.String(), want)
	}
	for _, mode := range []Mode{ModeNone, ModeMTLS} {
		h := mustGate(t, staticConfigs()[mode]).Require()(http.NotFoundHandler())
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newReq(t, http.MethodGet, pathRoot, http.NoBody))
		if w.Code != http.StatusForbidden || w.Header().Values(headerChallenge) != nil {
			t.Errorf("Require without an identity in %s = %d %v, want 403 without a challenge", mode, w.Code,
				w.Header())
		}
	}
}

func TestGateCheckHandler(t *testing.T) {
	g := mustGate(t, &Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSubjects: []string{"evil\r\nSet-Cookie: x"}}})
	h := g.CheckHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, verifiedMTLSRequest(t, testCert("evil\r\nSet-Cookie: x")))
	hd := w.Header()
	if w.Code != http.StatusOK || hd.Get(headerCacheControl) != "no-store" ||
		hd.Get(headerSubject) != "evil  Set-Cookie: x" || hd.Get(headerMethod) != "mtls" ||
		hd.Values("X-Auth-Scopes") != nil {
		t.Fatalf("CheckHandler = %d %v, want 200 no-store with the blanked subject and no scopes", w.Code, hd)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, newReq(t, http.MethodGet, pathRoot, http.NoBody))
	hd = w.Header()
	if w.Code != http.StatusForbidden || hd.Get(headerCacheControl) != "no-store" || hd.Get(headerSubject) != "" {
		t.Fatalf("CheckHandler = %d %v, want 403 no-store without a subject", w.Code, w.Header())
	}
}

// TestGateCheckHandlerModes names the mode of each authenticated caller in
// X-Auth-Method.
func TestGateCheckHandlerModes(t *testing.T) {
	for mode, header := range map[Mode][2]string{
		ModeBearer: {headerAuthorization, "Bearer " + testLongSecret},
		ModeAPIKey: {defaultKeyHeader, testLongSecret},
		ModeOAuth:  {headerAuthorization, "Bearer " + oauthToken(t, testRead)},
	} {
		r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
		r.Header.Set(header[0], header[1])
		w := httptest.NewRecorder()
		mustGate(t, staticConfigs()[mode]).CheckHandler().ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Header().Get(headerMethod) != string(mode) {
			t.Errorf("CheckHandler(%s) = %d %v, want 200 with X-Auth-Method %s", mode, w.Code, w.Header(), mode)
		}
	}
}

// TestGateCheckHandlerChallengePaths checks every OAuth challenge of the
// check endpoint points at a metadata document that Mount serves.
func TestGateCheckHandlerChallengePaths(t *testing.T) {
	g := mustGate(t, validOAuth())
	const mcp = testEndpoint
	for original, resource := range map[string]string{
		"":                          mcp,
		mcp:                         mcp,
		mcp + "/tools/list?x=%22":   mcp + "/tools/list",
		mcp + "/a%20b":              mcp + "/a%20b",
		"http://evil.example" + mcp: mcp,
		"not a request URI":         mcp,
		pathRoot:                    mcp,
	} {
		r := newReq(t, http.MethodGet, testAPIOrigin+"/auth/check", http.NoBody)
		if original != "" {
			r.Header.Set("X-Original-Uri", original)
		}
		w := httptest.NewRecorder()
		g.CheckHandler().ServeHTTP(w, r)
		_, meta, _ := strings.Cut(w.Header().Get(headerChallenge), `resource_metadata="`)
		meta = strings.TrimSuffix(meta, `"`)
		got, doc := serveMux(t, g, newReq(t, http.MethodGet, meta, http.NoBody), mcp)
		if w.Code != http.StatusUnauthorized || got.Code != http.StatusOK ||
			doc[memberResource] != testAPIOrigin+resource {
			t.Errorf("CheckHandler with X-Original-URI %q = %d, GET %s = %d %v; want 401, 200 naming %s",
				original, w.Code, meta, got.Code, doc, testAPIOrigin+resource)
		}
	}
}

// unavailableKeys returns an OAuth Config whose JWKS endpoint answers 500.
func unavailableKeys(tb testing.TB) *Config {
	tb.Helper()
	down := newJWKSServer(tb, nil)
	down.set(http.StatusInternalServerError, nil)
	return &Config{Mode: ModeOAuth, OAuth: OAuthConfig{Issuer: testIssuerURL, Audience: testMCPServer,
		JWKSURL: down.URL}}
}

// TestGateCheckHandlerDenyAllocs refuses a static bearer token without
// reading X-Original-URI, which only an OAuth challenge names.
func TestGateCheckHandlerDenyAllocs(t *testing.T) {
	h := mustGate(t, staticConfigs()[ModeBearer]).CheckHandler()
	r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+testLongSecret[1:]+wrongByte)
	r.Header.Set(headerOriginalURI, "/mcp/tools")
	w := newBenchWriter()
	assertAllocs(t, denyAllocs, func() {
		w.reset()
		h.ServeHTTP(w, r)
		if w.status != http.StatusUnauthorized {
			t.Fatalf("CheckHandler = %d, want 401", w.status)
		}
	})
}

func TestGateCheckHandlerScopes(t *testing.T) {
	h := mustGate(t, validOAuth()).CheckHandler()
	for scope, want := range map[string]string{testReadW: testReadW, "read\r\nSet-Cookie:x": "read  Set-Cookie:x"} {
		r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
		r.Header.Set(headerAuthorization, "Bearer "+oauthToken(t, scope))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		hd := w.Header()
		if w.Code != http.StatusOK || hd.Get("X-Auth-Scopes") != want || hd.Get(headerSubject) != testUser ||
			hd.Get(headerMethod) != string(ModeOAuth) || hd.Values("Set-Cookie") != nil {
			t.Fatalf("CheckHandler(scope %q) = %d %v, want 200 with scopes %q", scope, w.Code, hd, want)
		}
		checkOwnValues(t, hd, headerCacheControl, headerSubject, headerMethod, "X-Auth-Scopes")
	}
}

// checkOwnValues adds a value to each named header of h in turn and requires
// every header to keep its own values.
func checkOwnValues(t *testing.T, h http.Header, names ...string) {
	t.Helper()
	answered := h.Clone()
	for _, name := range names {
		h.Add(name, wrongByte)
	}
	for _, name := range names {
		if got := h.Values(name); len(got) != 2 || got[0] != answered.Get(name) || got[1] != wrongByte {
			t.Fatalf("%s after an Add to each header = %q, want [%s x]", name, got, answered.Get(name))
		}
	}
}

// serveMux answers r through a mux on which g mounted endpoints.
func serveMux(t *testing.T, g *Gate, r *http.Request, endpoints ...string) (
	w *httptest.ResponseRecorder, doc map[string]any,
) {
	t.Helper()
	mux := http.NewServeMux()
	g.Mount(mux, endpoints...)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("Unmarshal(%q) = %v, want a JSON document", w.Body.String(), err)
		}
	}
	return w, doc
}

func TestGateMount(t *testing.T) {
	cfg := validOAuth()
	cfg.OAuth.RequiredScopes = []string{testRead}
	cfg.OAuth.Resource = ResourceConfig{Name: "API", Documentation: "https://docs.example"}
	g := mustGate(t, cfg)
	for path, resource := range map[string]string{
		pathResourceMetadata:                "http://api.example/mcp",
		pathResourceMetadata + testEndpoint: "http://api.example/mcp",
		pathResourceMetadata + "/v2":        "http://api.example/v2",
		pathResourceMetadata + "/v2/":       "http://api.example/v2/",
		pathResourceMetadata + "/mcp/tools": "http://api.example/mcp/tools",
	} {
		r := newReq(t, http.MethodGet, testAPIOrigin+path, http.NoBody)
		w, doc := serveMux(t, g, r, testEndpoint, "v2", testEndpoint, "/v2/")
		want := fmt.Sprint(map[string]any{
			memberResource: resource, "authorization_servers": []any{testIssuerURL},
			"scopes_supported":         []any{testRead},
			"bearer_methods_supported": []any{testBearerMethod}, "resource_name": "API",
			"resource_documentation": "https://docs.example",
		})
		if w.Code != http.StatusOK || fmt.Sprint(doc) != want ||
			w.Header().Get(headerCacheControl) != "private, max-age=300" {
			t.Fatalf("GET %s = %d %v, want 200 %s", path, w.Code, doc, want)
		}
	}
	w, _ := serveMux(t, g, newReq(t, http.MethodGet, testAPIOrigin+testServerMetadata, http.NoBody), testEndpoint)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET server metadata without a facade = %d, want 404", w.Code)
	}
}

// TestGateMountEscapedPrefix checks that a request escaping bytes of the metadata
// prefix, which ServeMux decodes, gets the document of that request unescaped.
func TestGateMountEscapedPrefix(t *testing.T) {
	g := mustGate(t, validOAuth())
	for path, resource := range map[string]string{
		"/.well-known/oauth%2Dprotected-resource":           testAPIOrigin + testEndpoint,
		"/%2Ewell-known/oauth-protected-resource/mcp/tools": testAPIOrigin + testEndpoint + "/tools",
	} {
		w, doc := serveMux(t, g, newReq(t, http.MethodGet, testAPIOrigin+path, http.NoBody), testEndpoint)
		if doc[memberResource] != resource {
			t.Errorf("GET %s = %d %v, want resource %s", path, w.Code, doc, resource)
		}
	}
}

// TestGateMountChallengePaths checks every challenge Middleware issues under a
// mounted endpoint points at a metadata document that Mount serves.
func TestGateMountChallengePaths(t *testing.T) {
	g := mustGate(t, validOAuth())
	mux := http.NewServeMux()
	g.Mount(mux, testEndpoint)
	protected := g.Middleware(http.NotFoundHandler())
	for _, target := range []string{testEndpoint, "/mcp/", "/mcp/tools/list"} {
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, newReq(t, http.MethodGet, testAPIOrigin+target, http.NoBody))
		_, meta, _ := strings.Cut(w.Header().Get(headerChallenge), `resource_metadata="`)
		meta = strings.TrimSuffix(meta, `"`)
		w, doc := serveMux(t, g, newReq(t, http.MethodGet, meta, http.NoBody), testEndpoint)
		if w.Code != http.StatusOK || doc[memberResource] != testAPIOrigin+target {
			t.Errorf("GET %s for %s = %d %v, want 200 naming %s", meta, target, w.Code, doc, testAPIOrigin+target)
		}
	}
	other := testAPIOrigin + pathResourceMetadata + "/other"
	w, _ := serveMux(t, g, newReq(t, http.MethodGet, other, http.NoBody), testEndpoint)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET unmounted path = %d, want 404", w.Code)
	}
	w, doc := serveMux(t, g, newReq(t, http.MethodGet, other, http.NoBody), "", pathRoot)
	if w.Code != http.StatusOK || doc[memberResource] != "http://api.example/other" {
		t.Fatalf("GET under a root endpoint = %d %v, want 200 naming http://api.example/other", w.Code, doc)
	}
	bare := testAPIOrigin + pathResourceMetadata
	w, doc = serveMux(t, g, newReq(t, http.MethodGet, bare, http.NoBody), pathRoot)
	if doc[memberResource] != testAPIOrigin {
		t.Fatalf("GET bare path under a root endpoint = %d %v, want %s", w.Code, doc, testAPIOrigin)
	}
}

func TestGateMountIdentifier(t *testing.T) {
	cfg := validOAuth()
	cfg.OAuth.Resource.Identifier = "https://resource.example"
	cfg.OAuth.PublicURL = testPublicURL
	_, doc := serveMux(t, mustGate(t, cfg), newReq(t, http.MethodGet, "http://x"+pathResourceMetadata, http.NoBody))
	if doc[memberResource] != "https://resource.example" || doc["scopes_supported"] != nil ||
		doc["resource_name"] != nil {
		t.Fatalf("doc = %v, want the identifier without scopes or name", doc)
	}
}

func TestGateMountWithoutServers(t *testing.T) {
	cfg := validOAuth()
	cfg.OAuth.Issuer = testNameIssuer
	_, doc := serveMux(t, mustGate(t, cfg), newReq(t, http.MethodGet, "http://x"+pathResourceMetadata, http.NoBody))
	if _, ok := doc["authorization_servers"]; ok || doc[memberResource] != "http://x" {
		t.Fatalf("doc = %v, want resource http://x without authorization servers", doc)
	}
}

func TestGateMountFacade(t *testing.T) {
	cfg := validOAuth()
	cfg.OAuth.Facade.ClientID = testClientID
	mux := facadeMux(t, cfg)
	w := serve(mux, newReq(t, http.MethodGet, "https://api.example"+pathResourceMetadata+testEndpoint, http.NoBody))
	var doc map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &doc)
	if err != nil || fmt.Sprint(doc["authorization_servers"]) != "[https://api.example]" {
		t.Fatalf("doc = %v, %v, want the origin as the one authorization server", doc, err)
	}
	registerBody := strings.NewReader(`{"redirect_uris":["http://127.0.0.1:1/cb"]}`)
	for _, tc := range []struct {
		r    *http.Request
		code int
	}{
		{newReq(t, http.MethodGet, "https://api.example"+testServerMetadata, http.NoBody), http.StatusOK},
		{newReq(t, http.MethodPost, "https://api.example"+pathRegister, registerBody), http.StatusCreated},
		{newReq(t, http.MethodGet, "https://api.example"+pathAuthorize, http.NoBody), http.StatusBadRequest},
		{newReq(t, http.MethodPost, "https://api.example"+pathToken, http.NoBody), http.StatusBadRequest},
		{newReq(t, http.MethodPost, "https://api.example"+pathAuthorize, http.NoBody), http.StatusMethodNotAllowed},
		{newReq(t, http.MethodGet, "https://api.example"+pathToken, http.NoBody), http.StatusMethodNotAllowed},
		{newReq(t, http.MethodGet, "https://api.example"+pathRegister, http.NoBody), http.StatusMethodNotAllowed},
		{newReq(t, http.MethodPost, "https://api.example"+testServerMetadata, http.NoBody),
			http.StatusMethodNotAllowed},
		{
			newReq(t, http.MethodPost, "https://api.example"+pathResourceMetadata+testEndpoint, http.NoBody),
			http.StatusMethodNotAllowed,
		},
	} {
		if w := serve(mux, tc.r); w.Code != tc.code {
			t.Errorf("%s %s = %d, want %d", tc.r.Method, tc.r.URL.Path, w.Code, tc.code)
		}
	}
}

func TestGateMountIgnoresStaticModes(t *testing.T) {
	for mode, cfg := range staticConfigs() {
		if mode == ModeOAuth {
			continue
		}
		w, _ := serveMux(t, mustGate(t, cfg), newReq(t, http.MethodGet, pathResourceMetadata, http.NoBody),
			testEndpoint)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET metadata in %s = %d, want 404", mode, w.Code)
		}
	}
}

// TestNewSharesIssuer serves an issuer whose metadata both the key source
// and the facade need: one discovery serves both.
func TestNewSharesIssuer(t *testing.T) {
	priv := testRSAKey()
	jwks := jwksDocument(t, publicJWK(t, priv, map[string]any{memberKid: "r"}))
	idp := newFakeIDP(t)
	idp.doc = func() (int, string) {
		return http.StatusOK, `{"issuer":"` + testIDPIssuer + `","authorization_endpoint":"` + testIDPAuthorize +
			`","token_endpoint":"` + testIDPToken + `","jwks_uri":"https://` + testIDPHost + `/tenant/keys"}`
	}
	keys := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(jwks); err != nil {
			t.Errorf("Write = %v, want nil", err)
		}
	})
	mux := http.NewServeMux()
	mux.Handle("/tenant/keys", keys)
	mux.Handle(pathRoot, idp)
	cfg := facadeConfig(idp)
	cfg.HTTPClient = &http.Client{Transport: hostTransport{testIDPHost: mux}}
	cfg.OAuth.HMACSecret = secret.Value{}
	g := mustGate(t, cfg)
	claims := claimsWith(map[string]any{claimIss: testIDPIssuer, claimExp: time.Now().Add(time.Hour).Unix(),
		claimScope: testScopeMemory})
	r := newReq(t, http.MethodGet, testEndpoint, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+signToken(t, algRS256, priv, "r", claims))
	if id, err := g.Authenticate(r); err != nil || id.Subject() != testUser {
		t.Fatalf("Authenticate = %v, %v, want %s", id, err, testUser)
	}
	if _, err := g.authServer.endpoints(t.Context(), time.Now()); err != nil {
		t.Fatalf("endpoints = %v, want the discovered endpoints", err)
	}
	if n := idp.discoveries.Load(); n != 1 {
		t.Fatalf("discoveries = %d, want 1 shared by the keys and the facade", n)
	}
}

func ExampleNew() {
	gate, err := New(&Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New(testLongSecret)}})
	if err != nil {
		fmt.Println(err)
		return
	}
	api := gate.Middleware(gate.Require()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := IdentityFromContext(r.Context())
		w.Header().Set("X-Subject", id.Subject())
	})))
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, pathRoot, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+testLongSecret)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	fmt.Println(w.Code, w.Header().Get("X-Subject"))
	// Output: 200 static-bearer
}

// ExampleGate_Mount guards /mcp in ModeOAuth and serves its protected
// resource metadata.
func ExampleGate_Mount() {
	mcpHandler := http.NotFoundHandler()
	gate, err := New(&Config{
		Mode: ModeOAuth,
		OAuth: OAuthConfig{
			Issuer:         "https://login.example.com/tenant",
			Audience:       "api://orders",
			RequiredScopes: []string{"orders.read"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", gate.Middleware(mcpHandler))
	gate.Mount(mux, "/mcp") // protected resource metadata for /mcp
	for _, path := range []string{"/mcp", "/.well-known/oauth-protected-resource/mcp"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"https://api.example"+path, http.NoBody))
		fmt.Println(path, w.Code)
	}
	// Output:
	// /mcp 401
	// /.well-known/oauth-protected-resource/mcp 200
}

// ExampleGate_Require admits only OAuth identities that hold the admin scope
// and the tenant claim acme; a request without a token gets 401.
func ExampleGate_Require() {
	adminHandler := http.NotFoundHandler()
	gate, err := New(validOAuth())
	if err != nil {
		log.Fatal(err)
	}
	admin := gate.Middleware(gate.Require(
		HasMode(ModeOAuth),
		HasAllScopes("admin"),
		HasClaim("tenant", "acme"),
	)(adminHandler))
	w := httptest.NewRecorder()
	admin.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, pathRoot, http.NoBody))
	fmt.Println(w.Code)
	// Output: 401
}

// ExampleGate_CheckHandler answers an nginx auth_request subrequest.
func ExampleGate_CheckHandler() {
	gate, err := New(&Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New(testLongSecret)}})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/check", gate.CheckHandler())
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/check", http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+testLongSecret)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	fmt.Println(w.Code, w.Header().Get(headerSubject))
	// Output: 200 static-bearer
}

func TestGateCheckHandlerAllocs(t *testing.T) {
	h := mustGate(t, staticConfigs()[ModeBearer]).CheckHandler()
	r := newReq(t, http.MethodGet, pathRoot, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+testLongSecret)
	w := newBenchWriter()
	// One allocation: the array the identity headers share.
	assertAllocs(t, 1, func() {
		w.reset()
		h.ServeHTTP(w, r)
		if w.status != http.StatusOK {
			t.Fatalf("CheckHandler(bearer) = %d, want 200", w.status)
		}
	})
}

func BenchmarkGateCheckHandler(b *testing.B) {
	for _, tc := range []struct {
		name, credential string
		cfg              *Config
		status           int
	}{
		{"bearer", testLongSecret, staticConfigs()[ModeBearer], http.StatusOK},
		{"oauth", oauthToken(b, testReadW), validOAuth(), http.StatusOK},
		{"bearer deny", testLongSecret[1:] + wrongByte, staticConfigs()[ModeBearer], http.StatusUnauthorized},
		{"oauth deny", malformedJWT, validOAuth(), http.StatusUnauthorized},
	} {
		h := mustGate(b, tc.cfg).CheckHandler()
		r := newReq(b, http.MethodGet, pathRoot, http.NoBody)
		r.Header.Set(headerAuthorization, "Bearer "+tc.credential)
		w := newBenchWriter()
		b.Run(tc.name, func(b *testing.B) {
			h.ServeHTTP(w, r)
			if w.status != tc.status || (w.status == http.StatusOK) == (w.headers.Get(headerSubject) == "") {
				b.Fatalf("CheckHandler = %d %v, want %d with a subject only on 200", w.status, w.headers, tc.status)
			}
			b.ReportAllocs()
			for b.Loop() {
				w.reset()
				h.ServeHTTP(w, r)
			}
		})
	}
}

func BenchmarkGateRequire(b *testing.B) {
	g := mustGate(b, validOAuth())
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	bare := newReq(b, http.MethodGet, testEndpoint, http.NoBody)
	identified := bare.WithContext(WithIdentity(bare.Context(), scoped(testRead)))
	for _, bc := range []struct {
		name   string
		check  Capability
		r      *http.Request
		status int
	}{
		{"any scope", HasAnyScope(testWrite, testRead), identified, 0},
		{"all scopes", HasAllScopes(testRead), identified, 0},
		{"deny", HasMode(ModeBearer), identified, http.StatusForbidden},
		{"no identity", HasAllScopes(testRead), bare, http.StatusUnauthorized},
	} {
		h := g.Require(bc.check)(next)
		w := newBenchWriter()
		b.Run(bc.name, func(b *testing.B) {
			h.ServeHTTP(w, bc.r)
			if w.status != bc.status {
				b.Fatalf("Require = %d, want %d", w.status, bc.status)
			}
			b.ReportAllocs()
			for b.Loop() {
				w.reset()
				h.ServeHTTP(w, bc.r)
			}
		})
	}
}

func BenchmarkGateMiddleware(b *testing.B) {
	admitted := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { admitted = true })
	for _, tc := range []struct {
		name, credential string
		cfg              *Config
		status           int
	}{
		{"accept", oauthToken(b, testRead), validOAuth(), 0},
		{"deny", malformedJWT, validOAuth(), http.StatusUnauthorized},
		{"static deny", testLongSecret[1:] + wrongByte, staticConfigs()[ModeBearer], http.StatusUnauthorized},
	} {
		h := mustGate(b, tc.cfg).Middleware(next)
		r := newReq(b, http.MethodGet, testEndpoint, http.NoBody)
		r.Header.Set(headerAuthorization, "Bearer "+tc.credential)
		w := newBenchWriter()
		b.Run(tc.name, func(b *testing.B) {
			admitted = false
			h.ServeHTTP(w, r)
			if w.status != tc.status || admitted != (tc.status == 0) {
				b.Fatalf("Middleware = %d admitted %v, want %d", w.status, admitted, tc.status)
			}
			b.ReportAllocs()
			for b.Loop() {
				w.reset()
				h.ServeHTTP(w, r)
			}
		})
	}
}

func BenchmarkGateAuthenticate(b *testing.B) {
	for _, tc := range []struct {
		name, credential string
		cfg              *Config
		want             error
	}{
		{"static token", testLongSecret, staticConfigs()[ModeBearer], nil},
		{"OAuth token", oauthToken(b, testRead), validOAuth(), nil},
		{"malformed token", malformedJWT, validOAuth(), ErrInvalidCredentials},
	} {
		g := mustGate(b, tc.cfg)
		r := newReq(b, http.MethodGet, testEndpoint, http.NoBody)
		r.Header.Set(headerAuthorization, "Bearer "+tc.credential)
		b.Run(tc.name, func(b *testing.B) {
			if _, err := g.Authenticate(r); !errors.Is(err, tc.want) {
				b.Fatalf("Authenticate = %v, want %v", err, tc.want)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := g.Authenticate(r); !errors.Is(err, tc.want) {
					b.Fatalf("Authenticate = %v, want %v", err, tc.want)
				}
			}
		})
	}
}

// TestGateAuthenticateAllocs pins what admitting and refusing a credential
// costs: nothing for a static token or its refusal, verifiedTokenAllocs for an OAuth
// token, and for a refused one, whose refusal is built once, its decoded text.
func TestGateAuthenticateAllocs(t *testing.T) {
	typed := validOAuth()
	typed.OAuth.RequireAccessTokenType = true
	expired := signToken(t, algHS256, []byte(testLongSecret), "", claimsWith(map[string]any{
		claimExp: time.Now().Add(-time.Hour).Unix(),
	}))
	rs256 := segment(`{"alg":"RS256"}`) + jwsSeparator + segment(emptyObject) + jwsSeparator + segment("sig")
	unsigned := func(header string) string {
		return segment(header) + jwsSeparator + segment(emptyObject) + jwsSeparator + segment("sig")
	}
	signed := func(payload string) string {
		return signRaw(t, algHS256, []byte(testLongSecret), `{"alg":"HS256"}`, payload)
	}
	for _, tc := range []struct {
		name, credential string
		cfg              *Config
		allocs           float64
		want             error
	}{
		{"static token", testLongSecret, staticConfigs()[ModeBearer], 0, nil},
		{"OAuth token", oauthToken(t, testRead), validOAuth(), verifiedTokenAllocs, nil},
		{"wrong token", testLongSecret[1:] + wrongByte, staticConfigs()[ModeBearer], 0, ErrInvalidCredentials},
		{"malformed token", malformedJWT, validOAuth(), 0, ErrInvalidCredentials},
		{"token of another mode", rs256, validOAuth(), decodedTextAllocs, ErrInvalidCredentials},
		{"header no JSON object", unsigned(`{"alg":"HS256",}`), validOAuth(), decodedTextAllocs, ErrInvalidCredentials},
		{"alg no string", unsigned(`{"alg":1}`), validOAuth(), decodedTextAllocs, ErrInvalidCredentials},
		{"claims no JSON object", signed(`{"iss":`), validOAuth(), decodedTextAllocs, ErrInvalidCredentials},
		{"iss no string", signed(`{"iss":1}`), validOAuth(), decodedTextAllocs, ErrInvalidCredentials},
		{"untyped token", oauthToken(t, testRead), typed, decodedTextAllocs, ErrInvalidCredentials},
		{"expired token", expired, validOAuth(), decodedTextAllocs, ErrTokenExpired},
		{"keys unavailable", signToken(t, algRS256, []byte(testLongSecret), "k", testClaims()),
			unavailableKeys(t), decodedTextAllocs, ErrKeysUnavailable},
	} {
		g := mustGate(t, tc.cfg)
		r := newReq(t, http.MethodGet, testEndpoint, http.NoBody)
		r.Header.Set(headerAuthorization, "Bearer "+tc.credential)
		t.Run(tc.name, func(t *testing.T) {
			assertAllocs(t, tc.allocs, func() {
				if _, err := g.Authenticate(r); !errors.Is(err, tc.want) {
					t.Fatalf("Authenticate = %v, want %v", err, tc.want)
				}
			})
		})
	}
}

// TestGateMiddlewareAllocs pins what Middleware adds to admitting a static
// token: the context that carries the identity and the request bound to it.
func TestGateMiddlewareAllocs(t *testing.T) {
	admitted := false
	h := mustGate(t, staticConfigs()[ModeBearer]).Middleware(http.HandlerFunc(func(http.ResponseWriter,
		*http.Request) {
		admitted = true
	}))
	r := newReq(t, http.MethodGet, testEndpoint, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+testLongSecret)
	w := newBenchWriter()
	assertAllocs(t, 2, func() {
		admitted = false
		h.ServeHTTP(w, r)
		if !admitted {
			t.Fatalf("Middleware = %d, want the request admitted", w.status)
		}
	})
}

// TestGateMountPatterns serves the metadata of every path that endpoint path patterns
// with a wildcard or {$} match and of its sub-paths, reads a method or host as path
// text, and panics as ServeMux.Handle does on an invalid pattern or one the mux holds.
func TestGateMountPatterns(t *testing.T) {
	g := mustGate(t, validOAuth())
	for _, tc := range []struct {
		endpoint, path string
		resource       any
	}{
		{"/{tenant}/mcp", "/a/mcp", testAPIOrigin + "/a/mcp"},
		{"/{tenant}/mcp", "/b/mcp/tools", testAPIOrigin + "/b/mcp/tools"},
		{"/{tenant}/mcp", "/a/other", nil},
		{"/v/{id}", "/v/7/x", testAPIOrigin + "/v/7/x"},
		{"/x/{$}", "/x/", testAPIOrigin + "/x/"},
		{"/x/{$}", "/x/y", testAPIOrigin + "/x/y"},
		{"/files/{path...}", "/files/", testAPIOrigin + "/files/"},
		{"/files/{path...}", "/files/a/b", testAPIOrigin + "/files/a/b"},
		{"/files/{path...}", "/other", nil},
		{"POST /mcp", "/POST%20/mcp", testAPIOrigin + "/POST%20/mcp"},
		{"POST /mcp", testEndpoint, nil},
		{"api.example/mcp", "/api.example/mcp", testAPIOrigin + "/api.example/mcp"},
		{"api.example/mcp", testEndpoint, nil},
	} {
		r := newReq(t, http.MethodGet, testAPIOrigin+pathResourceMetadata+tc.path, http.NoBody)
		w, doc := serveMux(t, g, r, tc.endpoint)
		if doc[memberResource] != tc.resource {
			t.Errorf("GET %s under %s = %d %v, want resource %v", tc.path, tc.endpoint, w.Code, doc, tc.resource)
		}
	}
	held := http.NewServeMux()
	g.Mount(held, testEndpoint)
	bare := "GET " + pathResourceMetadata
	for _, tc := range []struct {
		name       string
		mount, mux func()
	}{
		{"/x/{$}/y", func() { g.Mount(http.NewServeMux(), "/x/{$}/y") }, func() {
			http.NewServeMux().Handle(bare+"/x/{$}/y", http.NotFoundHandler())
		}},
		{testEndpoint + " again", func() { g.Mount(held, testEndpoint) }, func() {
			mux := http.NewServeMux()
			mux.Handle(bare, http.NotFoundHandler())
			mux.Handle(bare, http.NotFoundHandler())
		}},
	} {
		if got, want := muxPanic(tc.mount), muxPanic(tc.mux); got == "" || got != want {
			t.Errorf("Mount(%s) panics with %q, want the panic of ServeMux.Handle, %q", tc.name, got, want)
		}
	}
}

// registrationSite matches each registration site a ServeMux panic names.
var registrationSite = regexp.MustCompile(` \(registered at [^)]*\)`)

// muxPanic returns the text of what f panics with, without the registration
// sites it names, or "" when f returns.
func muxPanic(f func()) (text string) {
	defer func() {
		if p := recover(); p != nil {
			text = registrationSite.ReplaceAllString(fmt.Sprint(p), "")
		}
	}()
	f()
	return ""
}

// TestGateMiddlewareScopeDenyAllocs refuses a token lacking two required
// scopes for what any verified token and OAuth refusal cost: the scope text
// of the challenge is joined once, by New.
func TestGateMiddlewareScopeDenyAllocs(t *testing.T) {
	cfg := validOAuth()
	cfg.OAuth.RequiredScopes = []string{testRead, testWrite}
	h := mustGate(t, cfg).Middleware(http.NotFoundHandler())
	r := newReq(t, http.MethodGet, testEndpoint, http.NoBody)
	r.Header.Set(headerAuthorization, "Bearer "+oauthToken(t, testAdmin))
	w := newBenchWriter()
	assertAllocs(t, verifiedTokenAllocs+oauthDenyAllocs, func() {
		w.reset()
		h.ServeHTTP(w, r)
		if w.status != http.StatusForbidden {
			t.Fatalf("Middleware = %d, want 403", w.status)
		}
	})
}

// FuzzOriginalPath checks the challenge CheckHandler answers for any X-Original-URI
// value: it names the metadata of the path url.ParseRequestURI reads from it, the bare
// one for no path or "/", which a root Mount serves or redirects to its clean path.
func FuzzOriginalPath(f *testing.F) {
	for _, seed := range []string{"", pathRoot, testEndpoint, "/mcp/tools?x=%22", "/a%2Fb#f", "*", "http://h",
		"https://u@h/p", "//x/y", "/a/../b", "/a b", "/%zz", "mcp", "/\u00e9\xff"} {
		f.Add(seed)
	}
	g := mustGate(f, validOAuth())
	mux := http.NewServeMux()
	g.Mount(mux, pathRoot)
	h := g.CheckHandler()
	f.Fuzz(func(t *testing.T, original string) {
		path := referenceOriginalPath(original)
		meta := testAPIOrigin + "/.well-known/oauth-protected-resource" + path
		r := newReq(t, http.MethodGet, testAPIOrigin+"/auth/check", http.NoBody)
		r.Header.Set(headerOriginalURI, original)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := `Bearer realm="restricted", resource_metadata="` + meta + `"`
		if w.Code != http.StatusUnauthorized || w.Header().Get(headerChallenge) != want {
			t.Fatalf("CheckHandler with X-Original-URI %q = %d %q, want 401 %q", original, w.Code,
				w.Header().Get(headerChallenge), want)
		}
		got := httptest.NewRecorder()
		mux.ServeHTTP(got, newReq(t, http.MethodGet, meta, http.NoBody))
		var doc map[string]any
		served := got.Code == http.StatusOK && json.Unmarshal(got.Body.Bytes(), &doc) == nil &&
			doc[memberResource] == testAPIOrigin+path
		redirected := got.Code >= http.StatusMultipleChoices && got.Code < http.StatusBadRequest &&
			got.Header().Get("Location") != ""
		if !served && !redirected {
			t.Fatalf("GET %s = %d %q, want 200 naming %s, or the redirect to its clean path", meta, got.Code,
				got.Body.String(), testAPIOrigin+path)
		}
	})
}

// referenceOriginalPath returns the escaped path url.ParseRequestURI reads from
// target, "" when it reads none, an error or only "/".
func referenceOriginalPath(target string) string {
	u, err := url.ParseRequestURI(target)
	if err != nil || !strings.HasPrefix(u.Path, "/") || u.Path == "/" {
		return ""
	}
	return u.EscapedPath()
}
