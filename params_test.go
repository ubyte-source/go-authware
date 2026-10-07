package authware

import (
	"errors"
	"maps"
	"net/url"
	"slices"
	"testing"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

// testHint is a login hint the policy relays.
const (
	testHint = "s"
)

func TestNewParamPolicy(t *testing.T) {
	for prefix, want := range map[string]string{"": "", "api://x": "api://x/", "api://x/": "api://x/"} {
		p := newParamPolicy(&FacadeConfig{ClientID: testClientID, ScopePrefix: prefix, UpstreamResource: "r"}, nil)
		if p.qualifier != want || p.clientID != testClientID || p.upstreamResource != "r" {
			t.Errorf("newParamPolicy(prefix %q) = %+v, want qualifier %q, client %q, resource r",
				prefix, p, want, testClientID)
		}
	}
}

// rewritePolicies returns the policies of an Entra facade, without and with
// an upstream resource, and of a facade without a scope prefix.
func rewritePolicies() (entra, withResource, bare paramPolicy) {
	entra = newParamPolicy(&FacadeConfig{ClientID: testFacadeClient, ScopePrefix: testScopePrefix},
		[]string{testScopeMemory})
	withResource = entra
	withResource.upstreamResource = testUpstreamRes
	return entra, withResource, newParamPolicy(&FacadeConfig{ClientID: testFacadeClient}, nil)
}

func TestParamPolicyRewrite(t *testing.T) {
	entra, withResource, bare := rewritePolicies()
	const (
		client, scope, resource = oauthwire.ParamClientID, oauthwire.ParamScope, oauthwire.ParamResource
		grant, refresh          = oauthwire.ParamGrantType, oauthwire.GrantRefreshToken
		qualified, hint         = testScopePrefix + "/" + testScopeMemory, "login_hint"
		openQualified           = "openid offline_access " + qualified
	)
	tests := []struct {
		name    string
		policy  paramPolicy
		rewrite func(*paramPolicy, url.Values) (url.Values, bool)
		in, out url.Values
	}{
		{
			"authorize claude", entra, (*paramPolicy).authorize,
			url.Values{client: {"dcr-id"}, scope: {testScopeMemory}, resource: {testMCPResource}, hint: {testHint}},
			url.Values{client: {testFacadeClient}, scope: {openQualified}, hint: {testHint}},
		},
		{
			"authorize default scopes", entra, (*paramPolicy).authorize,
			url.Values{hint: {testHint}},
			url.Values{client: {testFacadeClient}, scope: {openQualified}, hint: {testHint}},
		},
		{
			"authorize mixed scopes", entra, (*paramPolicy).authorize,
			url.Values{scope: {"profile  " + testScopePrefix + "/x memory:read memory openid memory"}},
			url.Values{client: {testFacadeClient}, scope: {"openid offline_access profile " +
				testScopePrefix + "/x " + testScopePrefix + "/memory:read " + qualified}},
		},
		{
			"authorize upstream resource", withResource, (*paramPolicy).authorize,
			url.Values{resource: {testMCPResource}},
			url.Values{client: {testFacadeClient}, scope: {openQualified}, resource: {testUpstreamRes}},
		},
		{
			"authorize without prefix", bare, (*paramPolicy).authorize,
			url.Values{scope: {testScopeMemory}},
			url.Values{client: {testFacadeClient}, scope: {"openid offline_access memory"}},
		},
		{
			"token without scope", entra, (*paramPolicy).token,
			url.Values{grant: {refresh}, resource: {testMCPResource}},
			url.Values{grant: {refresh}, client: {testFacadeClient}},
		},
		{
			"token scope", entra, (*paramPolicy).token,
			url.Values{scope: {"memory offline_access"}},
			url.Values{client: {testFacadeClient}, scope: {qualified + " offline_access"}},
		},
		{
			"token upstream resource", withResource, (*paramPolicy).token,
			url.Values{},
			url.Values{client: {testFacadeClient}, resource: {testUpstreamRes}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := tc.rewrite(&tc.policy, tc.in); !ok || !maps.EqualFunc(got, tc.out, slices.Equal) {
				t.Fatalf("rewrite(%v) = %v, %v; want %v, true", tc.in, got, ok, tc.out)
			}
		})
	}
}

// TestParamPolicyRewriteRelaysKnownParams drops every parameter outside the
// allowlist of the endpoint.
func TestParamPolicyRewriteRelaysKnownParams(t *testing.T) {
	entra := newParamPolicy(&FacadeConfig{ClientID: testFacadeClient, ScopePrefix: testScopePrefix},
		[]string{testScopeMemory})
	const client, hint, grant = oauthwire.ParamClientID, "login_hint", oauthwire.ParamGrantType
	authorize, ok := entra.authorize(with(smuggled(), hint, testHint))
	want := url.Values{client: {testFacadeClient}, oauthwire.ParamScope: {"openid offline_access " + testScopePrefix +
		"/" + testScopeMemory}, hint: {testHint}}
	if !ok || !maps.EqualFunc(authorize, want, slices.Equal) {
		t.Fatalf("authorize = %v, %v; want %v, true", authorize, ok, want)
	}
	token, ok := entra.token(with(smuggled(), grant, oauthwire.GrantRefreshToken))
	want = url.Values{client: {testFacadeClient}, grant: {oauthwire.GrantRefreshToken}}
	if !ok || !maps.EqualFunc(token, want, slices.Equal) {
		t.Fatalf("token = %v, %v; want %v, true", token, ok, want)
	}
}

func TestParamPolicyAuthorizeKeepsDefaults(t *testing.T) {
	defaults := []string{testScopeMemory}
	p := newParamPolicy(&FacadeConfig{ClientID: testFacadeClient, ScopePrefix: testScopePrefix}, defaults)
	if _, ok := p.authorize(url.Values{}); !ok {
		t.Fatal("authorize = false, want true")
	}
	if want := []string{testScopeMemory}; !slices.Equal(defaults, want) {
		t.Fatalf("defaults after authorize = %v, want %v", defaults, want)
	}
}

func TestParamPolicyRewriteRefusesOtherResources(t *testing.T) {
	entra := newParamPolicy(&FacadeConfig{ClientID: testFacadeClient, ScopePrefix: testScopePrefix}, nil)
	bare := newParamPolicy(&FacadeConfig{ClientID: testFacadeClient}, nil)
	for _, scope := range []string{
		"https://graph.microsoft.com/.default", "memory api://other/memory", "urn:other", "api://memory-appx/memory",
		"memory\turn:x", "a\nb", "a\x00b", "café",
	} {
		for _, p := range []paramPolicy{entra, bare} {
			rewrites := map[string]func(url.Values) (url.Values, bool){"authorize": p.authorize, "token": p.token}
			for name, rewrite := range rewrites {
				if got, ok := rewrite(url.Values{oauthwire.ParamScope: {scope}}); ok || got != nil {
					t.Errorf("%s(%q) with qualifier %q = %v, %v; want nil, false", name, scope, p.qualifier, got, ok)
				}
			}
		}
	}
}

func TestParamPolicyQualify(t *testing.T) {
	entra := newParamPolicy(&FacadeConfig{ScopePrefix: testScopePrefix}, nil)
	bare := newParamPolicy(&FacadeConfig{}, nil)
	const graph, qualified = "https://graph.microsoft.com/.default", testScopePrefix + "/" + testScopeMemory
	for _, tc := range []struct {
		policy paramPolicy
		in     []string
		want   string
		ok     bool
	}{
		{entra, []string{"memory:read", "email", testScopePrefix + "/x"},
			testScopePrefix + "/memory:read email " + testScopePrefix + "/x", true},
		{entra, []string{testScopeMemory, graph}, "", false},
		{entra, []string{qualified, testScopeMemory}, qualified, true},
		{bare, []string{scopeOpenID, testScopeMemory, "memory:read", testScopeMemory},
			scopeOpenID + " " + testScopeMemory + " memory:read", true},
	} {
		if got, ok := tc.policy.qualify(tc.in); got != tc.want || ok != tc.ok {
			t.Errorf("qualify(%q) with qualifier %q = %q, %v; want %q, %v", tc.in, tc.policy.qualifier, got, ok,
				tc.want, tc.ok)
		}
	}
}

func TestParamPolicyQualifyScope(t *testing.T) {
	entra := newParamPolicy(&FacadeConfig{ScopePrefix: testScopePrefix}, nil)
	bare := newParamPolicy(&FacadeConfig{}, nil)
	plain := newParamPolicy(&FacadeConfig{ScopePrefix: "app"}, nil)
	const graph, qualified = "https://graph.microsoft.com/.default", testScopePrefix + "/" + testScopeMemory
	for _, tc := range []struct {
		policy paramPolicy
		in     string
		want   string
		ok     bool
	}{
		{entra, testScopeMemory, qualified, true},
		{entra, "orders:read", testScopePrefix + "/orders:read", true},
		{entra, scopeOpenID, scopeOpenID, true},
		{entra, qualified, qualified, true},
		{entra, graph, "", false},
		{entra, "api://memory-appx/memory", "", false},
		{entra, "urn:x", "", false},
		{bare, testScopeMemory, testScopeMemory, true},
		{bare, scopeOfflineAccess, scopeOfflineAccess, true},
		{bare, graph, "", false},
		{bare, "urn:x", "", false},
		{plain, "read", "app/read", true},
		{plain, "app/read", "app/read", true},
		{entra, "memory\turn:x", "", false},
		{entra, "a\nb", "", false},
		{bare, "a\x00b", "", false},
		{bare, "café", "", false},
		{bare, `a"b`, "", false},
		{bare, `a\b`, "", false},
		{bare, "!#[]~", "!#[]~", true},
	} {
		if got, ok := tc.policy.qualifyScope(tc.in); got != tc.want || ok != tc.ok {
			t.Errorf("qualifyScope(%q) with qualifier %q = %q, %v; want %q, %v", tc.in, tc.policy.qualifier, got, ok,
				tc.want, tc.ok)
		}
	}
}

func TestUriScope(t *testing.T) {
	for s, want := range map[string]bool{
		"https://graph.microsoft.com/.default": true, "api://x/y": true, "urn:x": true,
		"memory:read": false, "memory/read": false, "memory": false,
	} {
		if got := uriScope(s); got != want {
			t.Errorf("uriScope(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestOidcScope(t *testing.T) {
	for s, want := range map[string]bool{
		scopeOpenID: true, scopeOfflineAccess: true, "profile": true, "email": true,
		testScopeMemory: false, "OpenID": false,
	} {
		if got := oidcScope(s); got != want {
			t.Errorf("oidcScope(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestParseParams(t *testing.T) {
	for raw, want := range map[string]error{
		"":                              nil,
		"login_hint=x%20y&scope=memory": nil,
		"grant_type=a&grant_type=b":     errInvalidParams,
		"grant%5Ftype=client_credentials&grant_type=authorization_code": errInvalidParams,
		"a=&a":    errInvalidParams,
		"a=%zz":   errInvalidParams,
		"a=1;b=2": errInvalidParams,
	} {
		vals, err := parseParams(raw)
		if !errors.Is(err, want) || (err == nil) != (vals != nil) {
			t.Errorf("parseParams(%q) = %v, %v; want %v", raw, vals, err, want)
		}
	}
	if _, err := parseParams("a=%zz"); !errors.Is(err, url.EscapeError("%zz")) {
		t.Fatalf("parseParams(a=%%zz) = %v, want the escape error wrapped", err)
	}
	vals, err := parseParams("login_hint=x%20y&scope=memory")
	if err != nil || vals.Get("login_hint") != "x y" || vals.Get(oauthwire.ParamScope) != testScopeMemory {
		t.Fatalf("parseParams = %v, %v; want login_hint \"x y\", scope memory", vals, err)
	}
}
