package authware

import (
	"crypto/sha256"
	"encoding/base64"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

// requestAuthorize answers the authorization request with rawQuery through f.
func requestAuthorize(t *testing.T, f *facade, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	r := newReq(t, http.MethodGet, testMCPOrigin+pathAuthorize+"?"+rawQuery, http.NoBody)
	return serve(http.HandlerFunc(f.serveAuthorize), r)
}

// upstreamAuthorize splits the redirect in w into its endpoint and query.
func upstreamAuthorize(tb testing.TB, w *httptest.ResponseRecorder) (endpoint string, query url.Values) {
	tb.Helper()
	loc, err := url.Parse(w.Header().Get(headerLocation))
	if w.Code != http.StatusFound || err != nil || w.Header().Get("Cache-Control") != oauthwire.CacheNoStore {
		tb.Fatalf("authorize = %d %v %v, want 302 no-store with a Location", w.Code, w.Header(), err)
	}
	return loc.Scheme + "://" + loc.Host + loc.Path, loc.Query()
}

func TestFacadeServeAuthorize(t *testing.T) {
	for _, c := range claudeClients() {
		f := testFacade(t, facadeConfig(newFakeIDP(t)))
		q := claudeAuthorizeQuery()
		q.Set(paramRedirectURI, c.redirectURI)
		q.Set(oauthwire.ParamClientID, "stale-registration")
		endpoint, got := upstreamAuthorize(t, requestAuthorize(t, f, q.Encode()))
		want := claudeAuthorizeQuery()
		want.Del(oauthwire.ParamResource)
		want.Set(paramRedirectURI, c.redirectURI)
		want.Set(oauthwire.ParamScope, "openid offline_access "+testScopePrefix+"/"+testScopeMemory)
		if endpoint != testIDPAuthorize || !maps.EqualFunc(got, want, slices.Equal) {
			t.Errorf("%s: authorize redirect = %s?%v, want %s?%v", c.name, endpoint, got, testIDPAuthorize, want)
		}
	}
}

// TestFacadeServeAuthorizePassesTheContext discovers the upstream endpoints
// under the context of the request.
func TestFacadeServeAuthorizePassesTheContext(t *testing.T) {
	var fetches atomic.Int32
	cfg := facadeConfig(newFakeIDP(t))
	cfg.HTTPClient.Transport = markCounting(&fetches, cfg.HTTPClient.Transport)
	r := newReq(t, http.MethodGet, testMCPOrigin+pathAuthorize+"?"+claudeAuthorizeQuery().Encode(), http.NoBody)
	w := serve(http.HandlerFunc(testFacade(t, cfg).serveAuthorize), r.WithContext(marked(t)))
	if w.Code != http.StatusFound || fetches.Load() != 1 {
		t.Fatalf("authorize = %d after %d marked fetches, want 302 after 1", w.Code, fetches.Load())
	}
}

// TestFacadeServeAuthorizeDefaultScopes asks upstream for RequiredScopes when
// the client requests no scope.
func TestFacadeServeAuthorizeDefaultScopes(t *testing.T) {
	q := without(claudeAuthorizeQuery(), oauthwire.ParamScope)
	_, got := upstreamAuthorize(t, requestAuthorize(t, testFacade(t, facadeConfig(newFakeIDP(t))), q.Encode()))
	want := "openid offline_access " + testScopePrefix + "/" + testScopeMemory
	if got.Get(oauthwire.ParamScope) != want {
		t.Fatalf("authorize scope = %q, want %q", got.Get(oauthwire.ParamScope), want)
	}
}

// TestFacadeServeAuthorizeRelaysKnownParams drops every client parameter the
// facade does not relay, so none reaches the issuer.
func TestFacadeServeAuthorizeRelaysKnownParams(t *testing.T) {
	q := claudeAuthorizeQuery()
	for k, v := range smuggled() {
		if k != paramRequest && k != paramRequestURI {
			q[k] = v
		}
	}
	for _, k := range []string{paramNonce, paramPrompt, paramLoginHint} {
		q.Set(k, k+"-value")
	}
	_, got := upstreamAuthorize(t, requestAuthorize(t, testFacade(t, facadeConfig(newFakeIDP(t))), q.Encode()))
	want := without(claudeAuthorizeQuery(), oauthwire.ParamResource)
	want.Set(oauthwire.ParamScope, "openid offline_access "+testScopePrefix+"/"+testScopeMemory)
	for _, k := range []string{paramNonce, paramPrompt, paramLoginHint} {
		want.Set(k, k+"-value")
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("authorize relayed %v, want %v", got, want)
	}
}

func TestFacadeServeAuthorizeKeepsEndpointQuery(t *testing.T) {
	idp := newFakeIDP(t)
	idp.doc = func() (int, string) {
		return http.StatusOK, `{"issuer":"` + testIDPIssuer + `","authorization_endpoint":"` + testIDPAuthorize +
			`?p=b2c_1_signin","token_endpoint":"` + testIDPToken + `"}`
	}
	q := claudeAuthorizeQuery()
	q.Set("p", "attacker_policy")
	endpoint, got := upstreamAuthorize(t, requestAuthorize(t, testFacade(t, facadeConfig(idp)), q.Encode()))
	if endpoint != testIDPAuthorize || !slices.Equal(got["p"], []string{"b2c_1_signin"}) ||
		got.Get("state") != "state-1" {
		t.Fatalf("authorize redirect = %s?%v, want %s with p=b2c_1_signin and state-1", endpoint, got, testIDPAuthorize)
	}
}

func TestFacadeServeAuthorizeRejects(t *testing.T) {
	valid := claudeAuthorizeQuery().Encode()
	for name, tc := range map[string]struct{ query, code string }{
		"bad escape":     {valid + "&x=%zz", codeInvalidRequest},
		"repeated state": {valid + "&state=other", codeInvalidRequest},
		"encoded repeat": {valid + "&response%5Ftype=token", codeInvalidRequest},
		"no redirect":    {without(claudeAuthorizeQuery(), paramRedirectURI).Encode(), codeInvalidRequest},
		"request object": {valid + "&request=eyJhbGciOiJub25lIn0.e30.", codeInvalidRequest},
		"request_uri":    {valid + "&request_uri=https%3A%2F%2Fattacker.example%2Freq.jwt", codeInvalidRequest},
		"empty request":  {valid + "&request=", codeInvalidRequest},
		"graph scope": {with(claudeAuthorizeQuery(), oauthwire.ParamScope,
			"memory https://graph.microsoft.com/.default").Encode(),
			testInvalidScope},
	} {
		idp := newFakeIDP(t)
		w := requestAuthorize(t, testFacade(t, facadeConfig(idp)), tc.query)
		if code := oauthErrorCode(t, w); w.Code != http.StatusBadRequest || code != tc.code ||
			w.Header().Get(headerLocation) != "" || idp.discoveries.Load() != 0 {
			t.Errorf("%s: authorize = %d %s, Location %q after %d discoveries; want 400 %s, no Location, no discovery",
				name, w.Code, code, w.Header().Get(headerLocation), idp.discoveries.Load(), tc.code)
		}
	}
}

func TestFacadeServeAuthorizeUnavailable(t *testing.T) {
	idp := newFakeIDP(t)
	idp.doc = func() (int, string) { return http.StatusInternalServerError, "" }
	w := requestAuthorize(t, testFacade(t, facadeConfig(idp)), claudeAuthorizeQuery().Encode())
	if code := oauthErrorCode(t, w); w.Code != http.StatusServiceUnavailable ||
		code != oauthwire.CodeTemporarilyUnavailable || w.Header().Get("Retry-After") != "30" ||
		w.Header().Get(headerLocation) != "" {
		t.Fatalf("authorize = %d %s, Retry-After %q, Location %q; want 503 %s, Retry-After 30, no Location",
			w.Code, code, w.Header().Get("Retry-After"), w.Header().Get(headerLocation),
			oauthwire.CodeTemporarilyUnavailable)
	}
}

// redirectCase is a redirect_uri and whether the facade accepts it.
type redirectCase struct {
	uri   string
	valid bool
}

// headerLocation names a redirect target, and longChallenge is the length of
// a verifier sent as a challenge.
const (
	headerLocation = "Location"
	longChallenge  = 64
)

// FuzzFacadeServeAuthorize answers structured authorization requests with a
// reference: a redirect upstream in its client's terms exactly when every
// check passes, and otherwise a 400 without a Location.
func FuzzFacadeServeAuthorize(f *testing.F) {
	_, codeChallenge := pkcePair("claude")
	for _, seed := range []struct {
		pick                                 uint8
		responseType, method, pkce, scope, x string
	}{
		{0, responseTypeCode, pkceMethodS256, codeChallenge, testScopeMemory, ""},
		{1, responseTypeCode, pkceMethodS256, codeChallenge, "", "state=s&resource=r"},
		{0, "token", pkceMethodS256, codeChallenge, "", ""},
		{0, responseTypeCode, "plain", codeChallenge, "", ""},
		{0, responseTypeCode, pkceMethodS256, codeChallenge + "=", "", ""},
		{0, responseTypeCode, pkceMethodS256, codeChallenge, "memory https://graph.microsoft.com/.default", ""},
		{0, responseTypeCode, pkceMethodS256, codeChallenge, "openid " + testScopePrefix + "/x urn:x", ""},
		{0, responseTypeCode, pkceMethodS256, codeChallenge, "memory\turn:other:admin", ""},
		{0, responseTypeCode, pkceMethodS256, codeChallenge, "", "redirect%5Furi=https://evil.example/cb"},
		{0, responseTypeCode, pkceMethodS256, codeChallenge, "", "audience=x&claims=%7B%7D&nonce=n&prompt=login"},
		{0, responseTypeCode, pkceMethodS256, codeChallenge, "", "request_uri=https://evil.example/r"},
		{2, responseTypeCode, pkceMethodS256, codeChallenge, "", "x=%zz"},
	} {
		f.Add(seed.pick, seed.responseType, seed.method, seed.pkce, seed.scope, seed.x)
	}
	redirects := []redirectCase{
		{"https://claude.ai/api/mcp/auth_callback", true}, {testLoopbackURI, true}, {"http://evil.example/cb", false},
		{"https://claude.ai/cb#x", false}, {"https://u@claude.ai/cb", false}, {"javascript:alert(1)", false}, {"",
			false},
	}
	for pick := range redirects {
		f.Add(uint8(pick), responseTypeCode, pkceMethodS256, codeChallenge, "", "")
	}
	f.Fuzz(func(t *testing.T, pick uint8, responseType, method, pkce, scope, extra string) {
		fac := testFacade(t, facadeConfig(newFakeIDP(t)))
		redirect := redirects[int(pick)%len(redirects)]
		raw := url.Values{
			paramRedirectURI: {redirect.uri}, paramResponseType: {responseType}, paramCodeChallengeMethod: {method},
			paramCodeChallenge: {pkce}, oauthwire.ParamScope: {scope}, oauthwire.ParamClientID: {"any"},
		}.Encode() + "&" + extra
		r := newReq(t, http.MethodGet, testMCPOrigin+pathAuthorize, http.NoBody)
		r.URL.RawQuery = raw
		w := serve(http.HandlerFunc(fac.serveAuthorize), r)
		want, code := referenceAuthorize(raw, redirect)
		if code != "" {
			if w.Code != http.StatusBadRequest || w.Header().Get(headerLocation) != "" || oauthErrorCode(t, w) != code {
				t.Fatalf("authorize(%s) = %d %s, Location %q, want 400 %s without a Location", raw, w.Code,
					w.Body, w.Header().Get(headerLocation), code)
			}
			return
		}
		endpoint, got := upstreamAuthorize(t, w)
		if endpoint != testIDPAuthorize || !maps.EqualFunc(got, want, slices.Equal) {
			t.Fatalf("authorize(%s) = %s?%v, want %s?%v", raw, endpoint, got, testIDPAuthorize, want)
		}
	})
}

// formScope is the scope parameter the facade qualifies upstream.
const formScope = "scope"

// referenceAuthorize returns the upstream query the facade redirects the
// query raw to, or the OAuth error code of its refusal; redirect is the case
// of its redirect_uri.
func referenceAuthorize(raw string, redirect redirectCase) (want url.Values, code string) {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return nil, codeInvalidRequest
	}
	if code = refusedAuthorize(vals, redirect.valid); code != "" {
		return nil, code
	}
	scope, ok := referenceScope(vals.Get(oauthwire.ParamScope))
	if !ok {
		return nil, testInvalidScope
	}
	want = url.Values{formClientID: {testFacadeClient}, formScope: {scope}}
	for _, k := range []string{
		paramResponseType, "redirect_uri", "state", "code_challenge", "code_challenge_method", "nonce", "prompt",
		"login_hint",
	} {
		if v, ok := vals[k]; ok {
			want[k] = v
		}
	}
	return want, ""
}

// refusedAuthorize returns the OAuth error code of the refusal of vals, whose
// redirect_uri is valid as redirectValid says, or "" when each parameter comes
// once and they ask for a code with an S256 challenge and no request object.
func refusedAuthorize(vals url.Values, redirectValid bool) string {
	for _, v := range vals {
		if len(v) != 1 {
			return codeInvalidRequest
		}
	}
	switch {
	case vals.Has("request") || vals.Has("request_uri") || !redirectValid:
		return codeInvalidRequest
	case vals.Get("response_type") != "code":
		return codeUnsupportedResponse
	case vals.Get("code_challenge_method") != "S256" || !s256Challenge(vals.Get("code_challenge")):
		return codeInvalidRequest
	}
	return ""
}

// s256Challenge reports whether pkce is a SHA-256 digest in strict unpadded
// base64url on one line.
func s256Challenge(pkce string) bool {
	sum, err := base64.RawURLEncoding.Strict().DecodeString(pkce)
	return err == nil && len(sum) == sha256.Size && !strings.ContainsAny(pkce, "\r\n")
}

// referenceScope returns the upstream scope of an authorization request that
// asks for scope, or false when one of its scopes is malformed or names
// another resource.
func referenceScope(scope string) (string, bool) {
	requested := spaceFields(scope)
	if len(requested) == 0 {
		requested = []string{testScopeMemory}
	}
	return referenceUpstreamScope([]string{scopeOpenID, scopeOfflineAccess}, requested)
}

func TestCheckAuthorize(t *testing.T) {
	_, codeChallenge := pkcePair("claude")
	const redirect, method, pkce = paramRedirectURI, "code_challenge_method", "code_challenge"
	valid := claudeAuthorizeQuery()
	for name, tc := range map[string]struct {
		query url.Values
		code  string
	}{
		"valid":               {valid, ""},
		"no redirect":         {without(valid, redirect), codeInvalidRequest},
		"plain http redirect": {with(valid, redirect, "http://evil.example/cb"), codeInvalidRequest},
		"script redirect":     {with(valid, redirect, "javascript:alert(1)"), codeInvalidRequest},
		"fragment redirect": {with(valid, redirect, "https://claude.ai/api/mcp/auth_callback#x"),
			codeInvalidRequest},
		"userinfo redirect":     {with(valid, redirect, "https://u@claude.ai/cb"), codeInvalidRequest},
		"implicit":              {with(valid, paramResponseType, "token"), codeUnsupportedResponse},
		"hybrid":                {with(valid, paramResponseType, "code id_token"), codeUnsupportedResponse},
		"no response type":      {without(valid, paramResponseType), codeUnsupportedResponse},
		"plain method":          {with(valid, method, "plain"), codeInvalidRequest},
		"lowercase method":      {with(valid, method, "s256"), codeInvalidRequest},
		"no method":             {without(valid, method), codeInvalidRequest},
		"no challenge":          {without(valid, pkce), codeInvalidRequest},
		"short challenge":       {with(valid, pkce, codeChallenge[:42]), codeInvalidRequest},
		"padded challenge":      {with(valid, pkce, codeChallenge+"="), codeInvalidRequest},
		"standard alphabet":     {with(valid, pkce, "+"+codeChallenge[1:]), codeInvalidRequest},
		"verifier as challenge": {with(valid, pkce, strings.Repeat("a", longChallenge)), codeInvalidRequest},
	} {
		e := checkAuthorize(tc.query)
		switch {
		case tc.code == "" && e != nil:
			t.Errorf("%s: checkAuthorize = %+v, want nil", name, e)
		case tc.code != "" && (e == nil || e.code != tc.code || e.status != http.StatusBadRequest):
			t.Errorf("%s: checkAuthorize = %+v, want 400 %s", name, e, tc.code)
		}
	}
}

func TestValidChallenge(t *testing.T) {
	_, codeChallenge := pkcePair("x")
	for c, want := range map[string]bool{
		codeChallenge: true,
		"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM": true,
		"":                                  false,
		codeChallenge[:minVerifier-1]:       false,
		codeChallenge + "A":                 false,
		codeChallenge[:minVerifier-1] + "_": false,
		strings.Repeat("-", minVerifier):    false,
		codeChallenge + "\n":                false,
		codeChallenge[:minVerifier/2] + "\r" + codeChallenge[minVerifier/2:]: false,
		strings.Repeat("A", minVerifier-1) + "\n":                            false,
	} {
		if got := validChallenge(c); got != want {
			t.Errorf("validChallenge(%q) = %v, want %v", c, got, want)
		}
	}
}

// claudeAuthorizeQuery returns the authorization request Claude Code sends.
func claudeAuthorizeQuery() url.Values {
	_, codeChallenge := pkcePair("claude")
	return url.Values{
		"response_type": {responseTypeCode}, oauthwire.ParamClientID: {testFacadeClient},
		"code_challenge": {codeChallenge}, "code_challenge_method": {pkceMethodS256},
		paramRedirectURI: {testLoopbackURI}, "state": {"state-1"}, oauthwire.ParamScope: {testScopeMemory},
		oauthwire.ParamResource: {testMCPResource},
	}
}
