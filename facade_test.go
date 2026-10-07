package authware

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// plainIDP is the identity provider of the tests over plain http.
const plainIDP = "http://" + testIDPHost

// callers is how many callers ask for the endpoints at once.
const callers = 16

// unusableDoc answers discovery with metadata that names no token endpoint.
func unusableDoc() (status int, doc string) {
	return http.StatusOK, `{"issuer":"` + testIDPIssuer + `","authorization_endpoint":"` + testIDPAuthorize + `"}`
}

func TestNewUpstream(t *testing.T) {
	for name, tc := range map[string]struct {
		authorize string
		token     string
		base      string
		query     url.Values
		err       error
	}{
		"plain": {testIDPAuthorize, testIDPToken, testIDPAuthorize, url.Values{}, nil},
		"b2c policy": {testIDPAuthorize + "?p=b2c_1_signin", testIDPToken, testIDPAuthorize,
			url.Values{"p": {"b2c_1_signin"}}, nil},
		"fragment":         {testIDPAuthorize + "#x", testIDPToken, "", nil, errUpstreamEndpoint},
		"bad query":        {testIDPAuthorize + "?p=%zz", testIDPToken, "", nil, errUpstreamEndpoint},
		"no authorize":     {"", testIDPToken, "", nil, errUpstreamEndpoint},
		"no token":         {testIDPAuthorize, "", "", nil, errUpstreamEndpoint},
		"plain http token": {testIDPAuthorize, plainIDP + "/token", "", nil, errUpstreamEndpoint},
		"plain http authorize": {plainIDP + "/authorize", testIDPToken, "", nil,
			errUpstreamEndpoint},
	} {
		u, err := newUpstream(&serverMetadata{authorizationEndpoint: tc.authorize, tokenEndpoint: tc.token})
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: newUpstream error = %v, want %v", name, err, tc.err)
			continue
		}
		if err != nil {
			if !reflect.ValueOf(u).IsZero() {
				t.Errorf("%s: newUpstream = %+v, want the zero upstream with %v", name, u, err)
			}
			continue
		}
		if u.authorizeURL != tc.base || u.tokenURL.String() != tc.token ||
			!maps.EqualFunc(u.authorizeQuery, tc.query, slices.Equal) {
			t.Errorf("%s: newUpstream = %s %v %v, want %s %v %s", name, u.authorizeURL, u.authorizeQuery, u.tokenURL,
				tc.base, tc.query, tc.token)
		}
	}
}

// TestNewUpstreamWrapsTheCause keeps the reason an endpoint is refused.
func TestNewUpstreamWrapsTheCause(t *testing.T) {
	for name, tc := range map[string]struct {
		authorize, token string
		cause            error
	}{
		"token":     {testIDPAuthorize, plainIDP + "/token", ErrInsecureURL},
		"authorize": {plainIDP + "/authorize", testIDPToken, ErrInsecureURL},
		"query":     {testIDPAuthorize + "?p=%zz", testIDPToken, url.EscapeError("%zz")},
	} {
		u, err := newUpstream(&serverMetadata{authorizationEndpoint: tc.authorize, tokenEndpoint: tc.token})
		if !reflect.ValueOf(u).IsZero() || !errors.Is(err, errUpstreamEndpoint) || !errors.Is(err, tc.cause) {
			t.Errorf("%s: newUpstream = %+v, %v, want the zero upstream, errUpstreamEndpoint wrapping %v", name, u, err,
				tc.cause)
		}
	}
}

// TestFacadeEndpointsPassesTheContext fetches the metadata, and warns of
// unusable endpoints, under the context endpoints gets.
func TestFacadeEndpointsPassesTheContext(t *testing.T) {
	idp := newFakeIDP(t)
	idp.doc = unusableDoc
	var fetches atomic.Int32
	logs := &logCapture{}
	cfg := facadeConfig(idp)
	cfg.HTTPClient.Transport, cfg.ErrorLog = markCounting(&fetches, cfg.HTTPClient.Transport), slog.New(logs)
	up, err := testFacade(t, cfg).endpoints(marked(t), time.Now())
	got := logs.logged()
	if !reflect.ValueOf(up).IsZero() || !errors.Is(err, errUpstreamEndpoint) || fetches.Load() != 1 || len(got) != 1 ||
		!got[0].inMarked {
		t.Fatalf("endpoints = %+v, %v after %d marked fetches, logged %+v; want the zero upstream, "+
			"errUpstreamEndpoint after 1, warned under the caller's context", up, err, fetches.Load(), got)
	}
}

func TestNewFacade(t *testing.T) {
	for _, required := range [][]string{nil, {testScopeMemory}, {scopeOfflineAccess, testScopeMemory}} {
		cfg := facadeConfig(newFakeIDP(t))
		cfg.OAuth.RequiredScopes = required
		iss := &issuer{url: testIDPIssuer}
		origin := originResolver{public: testPublicURL}
		f := newFacade(&withDefaults(cfg).OAuth, origin, iss)
		want := append(slices.Clone(required), scopeOfflineAccess)
		if slices.Contains(required, scopeOfflineAccess) {
			want = required
		}
		if !slices.Equal(f.params.defaults, want) || f.idp != iss || f.origin != origin ||
			!f.secret.Equal(secret.New(testFacadeSecret)) || f.params.clientID != testFacadeClient {
			t.Errorf("newFacade(%v) = %+v, want scopes %v, the given issuer and origin, and the facade client",
				required, f, want)
		}
	}
}

// TestEndpointErrorWrite answers a refused request 400 and an issuer the facade
// cannot reach or use 503 with Retry-After: 30, each as an OAuth JSON error.
func TestEndpointErrorWrite(t *testing.T) {
	tests := []struct {
		e      *endpointError
		status int
		body   string
		retry  []string
	}{
		{badRequest("invalid_request", "bad"), http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"bad"}`, nil},
		{unavailable(), http.StatusServiceUnavailable,
			`{"error":"temporarily_unavailable","error_description":"authorization server unavailable"}`,
			[]string{"30"}},
	}
	for _, tc := range tests {
		w := httptest.NewRecorder()
		tc.e.write(w)
		if got := w.Header().Values("Retry-After"); w.Code != tc.status || w.Body.String() != tc.body ||
			!slices.Equal(got, tc.retry) {
			t.Errorf("write(%+v) = %d %s, Retry-After %q; want %d %s, Retry-After %q", tc.e, w.Code,
				w.Body.String(), got, tc.status, tc.body, tc.retry)
		}
	}
}

func TestFacadeEndpoints(t *testing.T) {
	idp := newFakeIDP(t)
	f := testFacade(t, facadeConfig(idp))
	first, err := f.endpoints(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("endpoints error = %v, want nil", err)
	}
	again, err := f.endpoints(t.Context(), time.Now())
	if err != nil || again.authorizeURL != first.authorizeURL || again.tokenURL != first.tokenURL ||
		idp.discoveries.Load() != 1 {
		t.Fatalf("second endpoints = %+v, %v after %d discoveries; want the first endpoints %+v after 1",
			again, err, idp.discoveries.Load(), first)
	}
	if first.authorizeURL != testIDPAuthorize || len(first.authorizeQuery) != 0 ||
		first.tokenURL.String() != testIDPToken {
		t.Fatalf("endpoints = %s %v %v, want %s without query and %s",
			first.authorizeURL, first.authorizeQuery, first.tokenURL, testIDPAuthorize, testIDPToken)
	}
}

func TestFacadeEndpointsBacksOffAfterFailure(t *testing.T) {
	idp := newFakeIDP(t)
	doc := idp.doc
	idp.doc = func() (int, string) { return http.StatusServiceUnavailable, "" }
	f := testFacade(t, facadeConfig(idp))
	now := time.Now()
	if up, err := f.endpoints(t.Context(), now); !reflect.ValueOf(up).IsZero() ||
		!errorMatches(err, statusError(http.StatusServiceUnavailable)) {
		t.Fatalf("endpoints on a failed discovery = %+v, %v, want the zero upstream, a 503 answer", up, err)
	}
	idp.doc = doc
	later := now.Add(fetchPause)
	if up, err := f.endpoints(t.Context(), later.Add(-time.Nanosecond)); !reflect.ValueOf(up).IsZero() ||
		!errors.Is(err, errRetryBackoff) || idp.discoveries.Load() != 1 {
		t.Fatalf("endpoints during backoff = %+v, %v after %d discoveries, want the zero upstream, errRetryBackoff "+
			"after 1", up, err, idp.discoveries.Load())
	}
	if _, err := f.endpoints(t.Context(), later); err != nil || idp.discoveries.Load() != 2 {
		t.Fatalf("endpoints after backoff = %v after %d discoveries, want nil after 2", err, idp.discoveries.Load())
	}
}

func TestFacadeEndpointsRejectsUnusableMetadata(t *testing.T) {
	idp := newFakeIDP(t)
	idp.doc = unusableDoc
	var logs logCapture
	cfg := facadeConfig(idp)
	cfg.ErrorLog = slog.New(&logs)
	f := testFacade(t, cfg)
	for range 2 {
		if up, err := f.endpoints(t.Context(), time.Now()); !reflect.ValueOf(up).IsZero() ||
			!errors.Is(err, errUpstreamEndpoint) {
			t.Fatalf("endpoints without token endpoint = %+v, %v, want the zero upstream, errUpstreamEndpoint", up, err)
		}
	}
	if n := idp.discoveries.Load(); n != 1 {
		t.Fatalf("discoveries = %d, want 1: the metadata stays cached", n)
	}
	if !logs.warned("authware: upstream endpoints unusable", errUpstreamEndpoint) {
		t.Fatalf("logged %+v, want the unusable endpoints warned once", logs.logged())
	}
}

// TestFacadeEndpointsRecordsEachMetadataOnce serves the first of two fetched
// metadata again, as to a caller that held it across the refresh: each metadata
// keeps the endpoints recorded with it, warned once.
func TestFacadeEndpointsRecordsEachMetadataOnce(t *testing.T) {
	idp := newFakeIDP(t)
	idp.doc = unusableDoc
	var logs logCapture
	cfg := facadeConfig(idp)
	cfg.ErrorLog = slog.New(&logs)
	f := testFacade(t, cfg)
	now := time.Now()
	later := now.Add(wantKeysTTL)
	_, first := f.endpoints(t.Context(), now)
	held := f.idp.metadata.snap.Load().value
	_, second := f.endpoints(t.Context(), later)
	f.idp.metadata.snap.Store(&snapshot[*serverMetadata]{fetched: later, value: held})
	up, err := f.endpoints(t.Context(), later)
	got := logs.logged()
	warning := func(rec logRecord, cause error) bool {
		return rec.level == slog.LevelWarn && rec.msg == "authware: upstream endpoints unusable" &&
			errors.Is(rec.err, cause)
	}
	if !reflect.ValueOf(up).IsZero() || !errors.Is(first, errUpstreamEndpoint) || !errors.Is(err, first) ||
		idp.discoveries.Load() != 2 || len(got) != 2 || !warning(got[0], first) || !warning(got[1], second) {
		t.Fatalf("endpoints of the first metadata again = %+v, %v after %v and %v, %d discoveries, logged %+v; "+
			"want the zero upstream and the first errUpstreamEndpoint after 2, one warning each", up, err, first,
			second, idp.discoveries.Load(), got)
	}
}

// TestFacadeEndpointsFollowIssuer moves the token endpoint upstream: the
// facade keeps the cached one within the TTL and relays to the new one after.
func TestFacadeEndpointsFollowIssuer(t *testing.T) {
	idp := newFakeIDP(t)
	f := testFacade(t, facadeConfig(idp))
	now := time.Now()
	if _, err := f.endpoints(t.Context(), now); err != nil {
		t.Fatalf("endpoints = %v, want nil", err)
	}
	moved := testIDPToken + "2"
	idp.doc = func() (int, string) {
		return http.StatusOK, `{"issuer":"` + testIDPIssuer + `","authorization_endpoint":"` + testIDPAuthorize +
			`","token_endpoint":"` + moved + `"}`
	}
	for _, step := range []struct {
		at   time.Duration
		want string
	}{
		{wantKeysTTL - time.Nanosecond, testIDPToken},
		{wantKeysTTL, moved},
	} {
		up, err := f.endpoints(t.Context(), now.Add(step.at))
		if err != nil || up.tokenURL.String() != step.want {
			t.Fatalf("endpoints(+%v) = %v, %v, want %s", step.at, up.tokenURL, err, step.want)
		}
	}
}

func TestFacadeEndpointsSharesDiscovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		idp := newFakeIDP(t)
		doc, release := idp.doc, make(chan struct{})
		idp.doc = func() (int, string) {
			<-release
			return doc()
		}
		f := testFacade(t, facadeConfig(idp))
		var wg sync.WaitGroup
		errs := make(chan error, callers)
		for range callers {
			wg.Go(func() {
				_, err := f.endpoints(t.Context(), time.Now())
				errs <- err
			})
		}
		synctest.Wait()
		if n := idp.discoveries.Load(); n != 1 {
			t.Fatalf("discoveries in flight = %d, want 1", n)
		}
		close(release)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("shared endpoints error = %v, want nil", err)
			}
		}
	})
}

// TestFacadeEndpointsWarnsOnce has many callers ask at once for unusable endpoints
// while every warning is held: the endpoints are warned once.
func TestFacadeEndpointsWarnsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		idp := newFakeIDP(t)
		idp.doc = unusableDoc
		logs := &logCapture{hold: make(chan struct{})}
		cfg := facadeConfig(idp)
		cfg.ErrorLog = slog.New(logs)
		f := testFacade(t, cfg)
		var wg sync.WaitGroup
		for range callers {
			wg.Go(func() {
				if up, err := f.endpoints(t.Context(), time.Now()); !reflect.ValueOf(up).IsZero() ||
					!errors.Is(err, errUpstreamEndpoint) {
					t.Errorf("endpoints = %+v, %v, want the zero upstream, errUpstreamEndpoint", up, err)
				}
			})
		}
		synctest.Wait()
		close(logs.hold)
		wg.Wait()
		if !logs.warned("authware: upstream endpoints unusable", errUpstreamEndpoint) {
			t.Fatalf("logged %+v, want the unusable endpoints warned once", logs.logged())
		}
	})
}

// TestFacadeRecordWarnsOnce calls record twice on one metadata with unusable
// endpoints, as two callers that both found no record do: only the first call
// records and warns them.
func TestFacadeRecordWarnsOnce(t *testing.T) {
	idp := newFakeIDP(t)
	idp.doc = unusableDoc
	var logs logCapture
	cfg := facadeConfig(idp)
	cfg.ErrorLog = slog.New(&logs)
	f := testFacade(t, cfg)
	md, err := f.idp.metadata.get(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("metadata error = %v, want nil", err)
	}
	firstUp, first := f.record(t.Context(), md)
	secondUp, second := f.record(t.Context(), md)
	d := md.derived.Load()
	if !reflect.ValueOf(firstUp).IsZero() || !reflect.ValueOf(secondUp).IsZero() ||
		!errors.Is(first, errUpstreamEndpoint) || !errors.Is(second, errUpstreamEndpoint) || d == nil ||
		!errors.Is(d.err, first) || !logs.warned("authware: upstream endpoints unusable", first) {
		t.Fatalf("record twice = %+v, %v and %+v, %v, recorded %+v, logged %+v; want the zero upstream and "+
			"errUpstreamEndpoint twice, the first recorded and warned once", firstUp, first, secondUp, second, d,
			logs.logged())
	}
}

// TestFacadeEndpointsTimesOut stalls both discovery documents: the shared
// fetch as a whole ends after FetchTimeout, not after one timeout per document.
func TestFacadeEndpointsTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := facadeConfig(newFakeIDP(t))
		cfg.HTTPClient = &http.Client{Transport: roundTripFunc(stall)}
		f := testFacade(t, cfg)
		start := time.Now()
		up, err := f.endpoints(t.Context(), start)
		if elapsed := time.Since(start); !reflect.ValueOf(up).IsZero() || !errors.Is(err, context.DeadlineExceeded) ||
			elapsed != wantFetchTimeout {
			t.Fatalf("endpoints = %+v, %v after %v, want the zero upstream, context.DeadlineExceeded after %v", up, err,
				elapsed, wantFetchTimeout)
		}
	})
}

func BenchmarkFacadeEndpoints(b *testing.B) {
	idp := newFakeIDP(b)
	f := testFacade(b, facadeConfig(idp))
	now := time.Now()
	if up, err := f.endpoints(b.Context(), now); err != nil || up.authorizeURL != testIDPAuthorize {
		b.Fatalf("endpoints = %s, %v, want %s", up.authorizeURL, err, testIDPAuthorize)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := f.endpoints(b.Context(), now); err != nil {
			b.Fatalf("endpoints = %v, want nil", err)
		}
	}
	if n := idp.discoveries.Load(); n != 1 {
		b.Fatalf("discoveries = %d, want 1", n)
	}
}

// metadataDocument renders the metadata the facade serves for issuerURL.
func metadataDocument(issuerURL string) string {
	return fmt.Sprintf(`{"issuer":%[1]q,"authorization_endpoint":"%[1]s/authorize",`+
		`"token_endpoint":"%[1]s/token","registration_endpoint":"%[1]s/register",`+
		`"scopes_supported":["memory","offline_access"],"response_types_supported":["code"],`+
		`"grant_types_supported":["authorization_code","refresh_token"],`+
		`"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"]}`, issuerURL)
}

// TestFacadeServeMetadata checks the document, its caching, and that its
// issuer is the authorization server the resource metadata names.
func TestFacadeServeMetadata(t *testing.T) {
	const host = "http://mcp.example.com"
	tests := []struct {
		name      string
		configure func(*OAuthConfig)
		request   func(*http.Request)
		issuerURL string
		public    bool
	}{
		{"request", func(*OAuthConfig) {}, func(*http.Request) {}, host, false},
		{"untrusted proto", func(*OAuthConfig) {},
			func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }, host, false},
		{"trusted proto", func(o *OAuthConfig) { o.TrustForwardedProto = true },
			func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "HTTPS, http") }, testMCPOrigin, false},
		{"tls", func(*OAuthConfig) {}, func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, testMCPOrigin, false},
		{"public URL", func(o *OAuthConfig) { o.PublicURL = testPublicURL }, func(*http.Request) {}, testPublicURL,
			true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := facadeConfig(newFakeIDP(t))
			tc.configure(&cfg.OAuth)
			mux := facadeMux(t, cfg)
			r := newReq(t, http.MethodGet, host+testServerMetadata, http.NoBody)
			tc.request(r)
			w := serve(mux, r)
			reference := httptest.NewRecorder()
			originResolver{public: cfg.OAuth.PublicURL}.writeDocument(reference, nil)
			hd := w.Header()
			if w.Code != http.StatusOK || w.Body.String() != metadataDocument(tc.issuerURL) ||
				tc.public != (hd.Get("Vary") == "") || !maps.EqualFunc(hd, reference.Header(), slices.Equal) {
				t.Fatalf("metadata = %d %v %s, want 200 %s with the headers of writeDocument",
					w.Code, hd, w.Body, metadataDocument(tc.issuerURL))
			}
			r = newReq(t, http.MethodGet, host+pathResourceMetadata+"/mcp", http.NoBody)
			tc.request(r)
			var prm struct {
				Servers []string `json:"authorization_servers"`
			}
			if err := json.Unmarshal(serve(mux, r).Body.Bytes(), &prm); err != nil ||
				!slices.Equal(prm.Servers, []string{tc.issuerURL}) {
				t.Fatalf("resource metadata servers = %v (%v), want [%s]", prm.Servers, err, tc.issuerURL)
			}
		})
	}
}

func TestValidRedirectURI(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback": true,
		testLoopbackURI:                true,
		"http://127.0.0.1:8080/cb":     true,
		"http://[::1]:8080/cb":         true,
		"https://claude.ai/cb?x=1":     true,
		"http://claude.ai/cb":          false,
		"https://claude.ai/cb#":        false,
		"https://user:pw@claude.ai/cb": false,
		"/relative":                    false,
		"cursor://callback":            false,
		"":                             false,
	} {
		if got := validRedirectURI(raw); got != want {
			t.Errorf("validRedirectURI(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestResourceURI(t *testing.T) {
	for s, want := range map[string]bool{
		testUpstreamRes: true, "urn:example:api": true, "api://app": true,
		"not-a-uri": false, "/path": false, "https://api.example/#f": false, "https://api.example/#": false,
		"urn:a b": false, "https://a b/": false, "https://api.example/%zz": false,
	} {
		if got := resourceURI(s); got != want {
			t.Errorf("resourceURI(%q) = %v, want %v", s, got, want)
		}
	}
}

// ExampleFacadeConfig enables the authorization server facade in front of
// Microsoft Entra ID and mounts its endpoints beside /mcp.
func ExampleFacadeConfig() {
	mcpHandler := http.NotFoundHandler()
	clientSecret := secret.New("the client secret of the Entra app")
	gate, err := New(&Config{
		Mode: ModeOAuth,
		OAuth: OAuthConfig{
			Issuer:    "https://login.microsoftonline.com/contoso/v2.0",
			Audience:  "api://orders",
			PublicURL: "https://mcp.example.com",
			Facade: FacadeConfig{
				ClientID:     "orders-mcp",
				ClientSecret: clientSecret,
				ScopePrefix:  "api://orders",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", gate.Middleware(mcpHandler))
	gate.Mount(mux, "/mcp") // metadata, /authorize, /register, /token
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://mcp.example.com/register", strings.NewReader(`{"redirect_uris":["http://127.0.0.1:8765/cb"]}`)))
	fmt.Println(w.Code)
	// Output: 201
}
