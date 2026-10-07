package authware

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// jwksOAuth configures the JWKS served at jwksURL.
func jwksOAuth(jwksURL string) *OAuthConfig {
	return &OAuthConfig{Issuer: testIssuerURL, Audience: testMCPServer, JWKSURL: jwksURL}
}

// hmacOAuth configures HMAC verification with testLongSecret.
func hmacOAuth() *OAuthConfig {
	return &OAuthConfig{Issuer: testIssuerURL, Audience: testMCPServer, HMACSecret: secret.New(testLongSecret)}
}

// Literals of the OAuth tests: key ids, the padding and kid lengths that
// reach a token size, and the JWKS requests once a refetch ran.
const (
	kidA             = "a"
	kidR             = "r"
	padRange         = 16
	maxKidLen        = 3
	hitsAfterRefetch = 3
)

func TestOAuthConfigValidate(t *testing.T) {
	const plainURL, upstreamProblem = "http://idp.example", "facade upstream resource"
	tests := []struct {
		name string
		edit func(o *OAuthConfig)
		want string
	}{
		{"short hmac", func(o *OAuthConfig) { o.HMACSecret = secret.New("short") }, "HMAC secret is shorter"},
		{"hmac and jwks", func(o *OAuthConfig) { o.JWKSURL = testJWKSURL }, "are exclusive"},
		{"plain jwks", func(o *OAuthConfig) { o.HMACSecret, o.JWKSURL = secret.Value{}, plainURL }, "JWKS URL"},
		{"plain issuer", func(o *OAuthConfig) { o.HMACSecret, o.Issuer = secret.Value{}, plainURL }, "oauth issuer"},
		{"facade issuer", func(o *OAuthConfig) { o.Issuer, o.Facade.ClientID = plainURL, testClientID },
			"oauth issuer"},
		{"spaced scope", func(o *OAuthConfig) { o.RequiredScopes = []string{"a b"} }, "not a scope token"},
		{"empty scope", func(o *OAuthConfig) { o.RequiredScopes = []string{""} }, "not a scope token"},
		{"repeated scope", func(o *OAuthConfig) { o.RequiredScopes = []string{kidA, kidA} }, "is repeated"},
		{"negative skew", func(o *OAuthConfig) { o.ClockSkew = -time.Second }, "clock skew is negative"},
		{"negative ttl", func(o *OAuthConfig) { o.KeysCacheTTL = -time.Second }, "cache TTL is negative"},
		{"negative timeout", func(o *OAuthConfig) { o.FetchTimeout = -time.Second }, "fetch timeout is negative"},
		{"plain public", func(o *OAuthConfig) { o.PublicURL = "http://public.example" }, "public URL"},
		{"public path", func(o *OAuthConfig) { o.PublicURL = testHTTPS + "/" }, "must be an origin"},
		{"plain resource", func(o *OAuthConfig) { o.Resource.Identifier = "http://r.example" }, "resource identifier"},
		{"plain server", func(o *OAuthConfig) { o.Resource.AuthorizationServers = []string{plainURL} },
			"authorization"},
		{"facade without id", func(o *OAuthConfig) { o.Facade.ScopePrefix = "api://x" }, "facade client ID"},
		{"secret without id", func(o *OAuthConfig) { o.Facade.ClientSecret = secret.New("s") }, "facade client ID"},
		{"resource without id", func(o *OAuthConfig) { o.Facade.UpstreamResource = kidR }, "facade client ID"},
		{"spaced prefix", func(o *OAuthConfig) {
			o.Facade = FacadeConfig{ClientID: testClientID, ScopePrefix: "api://app https://graph.microsoft.com"}
		}, "facade scope prefix"},
		{"relative resource", func(o *OAuthConfig) {
			o.Facade = FacadeConfig{ClientID: testClientID, UpstreamResource: "not-a-uri"}
		}, upstreamProblem},
		{"resource fragment", func(o *OAuthConfig) {
			o.Facade = FacadeConfig{ClientID: testClientID, UpstreamResource: "https://api.example/#f"}
		}, upstreamProblem},
		{"resource space", func(o *OAuthConfig) {
			o.Facade = FacadeConfig{ClientID: testClientID, UpstreamResource: "urn:a b"}
		}, upstreamProblem},
		{"unparsable resource", func(o *OAuthConfig) {
			o.Facade = FacadeConfig{ClientID: testClientID, UpstreamResource: "https://a b/"}
		}, upstreamProblem},
		{"facade servers", func(o *OAuthConfig) {
			o.Facade.ClientID, o.Resource.AuthorizationServers = testClientID, []string{testIssuerURL}
		}, "authorization servers and facade client ID are exclusive"},
		{"facade uri scope", func(o *OAuthConfig) {
			o.Facade.ClientID, o.RequiredScopes = testClientID, []string{"https://api.example.com/read"}
		}, `scope "https://api.example.com/read" names a resource outside`},
		{"facade foreign scope", func(o *OAuthConfig) {
			o.Facade, o.RequiredScopes = FacadeConfig{ClientID: testClientID, ScopePrefix: "api://app"}, []string{kidA,
				"urn:y"}
		}, `scope "urn:y" names a resource outside`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validOAuth()
			tc.edit(&cfg.OAuth)
			got, err := cfg.prepare()
			if got != nil || !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("prepare = %+v, %v, want nil, ErrInvalidConfig with %q", got, err, tc.want)
			}
		})
	}
}

func TestNewOAuthAuthenticator(t *testing.T) {
	oc := jwksOAuth(testJWKSURL)
	oc.RequiredScopes, oc.ClockSkew, oc.RequireAccessTokenType = []string{testRead}, time.Minute, true
	keys := newHMACKey(nil)
	a := newOAuthAuthenticator(oc, keys)
	policy := claimPolicy{iss: testIssuerURL, audience: testMCPServer, skew: time.Minute}
	if a.resolver != keys || a.policy != policy || !a.accessType || !slices.Equal(a.required, []string{testRead}) {
		t.Fatalf("authenticator = %+v, want the keys, the policy, the at+jwt requirement and scope %s", a, testRead)
	}
}

// keyOf reports whether k is the HMAC key of mac: of its size, it verifies
// what mac signs.
func keyOf(t *testing.T, k *hmacKey, mac string) bool {
	t.Helper()
	sig, alg := signInput(t, algHS256, []byte(mac), testInput), mustAlgorithm(t, algHS256)
	return k.size == len(mac) && verifySignature(k, alg, []byte(testInput), sig, verifyRoom()) == nil
}

func TestOAuthConfigKeys(t *testing.T) {
	calls := 0
	iss := &issuer{}
	reach := func() *issuer {
		calls++
		return iss
	}
	if k, ok := hmacOAuth().keys(reach).(*hmacKey); !ok || !keyOf(t, k, testLongSecret) || calls != 0 {
		t.Fatalf("keys(HMAC) = %+v after %d issuers, want the HMAC key of the secret and no issuer", k, calls)
	}
	oc := &withDefaults(&Config{OAuth: *jwksOAuth(testJWKSURL)}).OAuth
	s, ok := oc.keys(reach).(*keySource)
	if !ok || s.idp != iss || s.jwksURL != testJWKSURL || s.sets.ttl != wantKeysTTL ||
		s.sets.timeout != wantFetchTimeout || calls != 1 {
		t.Fatalf("keys(JWKS) = %+v after %d issuers, want a key source of %s through the one issuer", s, calls,
			testJWKSURL)
	}
}

func TestCheckURL(t *testing.T) {
	p := problems.New(ErrInvalidConfig)
	checkURL(p, anyValue, "https://idp.example/a")
	if got := recorded(p); len(got) != 0 {
		t.Fatalf("checkURL(secure URL) problems = %v, want none", got)
	}
	checkURL(p, anyValue, "http://user:pw@localhost/")
	got := recorded(p)
	if len(got) != 1 || !errors.Is(got[0], ErrInvalidConfig) || !errors.Is(got[0], ErrInsecureURL) {
		t.Fatalf("checkURL(userinfo) problems = %v, want one ErrInvalidConfig wrapping ErrInsecureURL", got)
	}
	if strings.Contains(got[0].Error(), "pw") || strings.Count(got[0].Error(), "authware:") != 1 {
		t.Fatalf("checkURL(userinfo) problem = %v, want no userinfo and one package prefix", got[0])
	}
}

// TestCheckOrigin expects each refusal as one ErrInvalidConfig: wrapping
// ErrInsecureURL for the outbound URL policy, else naming the origin form.
func TestCheckOrigin(t *testing.T) {
	const notOrigin = "public URL must be an origin"
	for raw, want := range map[string]error{
		testHTTPS:                      nil,
		"https://api.example:8443":     nil,
		"http://localhost:8080":        nil,
		"https://[::1]:1":              nil,
		"http://public.example":        ErrInsecureURL,
		"https://user@example.com":     ErrInsecureURL,
		testHTTPS + "/":                ErrInvalidConfig,
		"HTTPS://example.com":          ErrInvalidConfig,
		"https://Example.COM":          ErrInvalidConfig,
		"https://[FE80::1]":            ErrInvalidConfig,
		"https://example.com:443":      ErrInvalidConfig,
		"http://localhost:80":          ErrInvalidConfig,
		"https://example.com:":         ErrInvalidConfig,
		"https://example.com:0443":     ErrInvalidConfig,
		"https://example.com:0":        ErrInvalidConfig,
		"https://example.com:65536":    ErrInvalidConfig,
		"https://example.com?x":        ErrInvalidConfig,
		"https://example.com#frag":     ErrInvalidConfig,
		"http://localhost:8080/app":    ErrInvalidConfig,
		"https://example.com:8443/app": ErrInvalidConfig,
	} {
		p := problems.New(ErrInvalidConfig)
		checkOrigin(p, raw)
		got, err := recorded(p), p.Err()
		insecure := errors.Is(want, ErrInsecureURL)
		if !errors.Is(err, want) || errors.Is(err, ErrInsecureURL) != insecure ||
			(err != nil && (len(got) != 1 || !errors.Is(err, ErrInvalidConfig) ||
				insecure == strings.Contains(err.Error(), notOrigin))) {
			t.Errorf("checkOrigin(%q) = %v, want one ErrInvalidConfig matching %v", raw, err, want)
		}
	}
}

func TestCanonicalPort(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://h": true, "https://h:8443": true, "http://h:443": true, "https://h:80": true, "https://h:1": true,
		"https://h:65535": true, "https://h:": false, "https://h:443": false, "http://h:80": false,
		"https://h:0": false, "https://h:08443": false, "https://h:65536": false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q) = %v, want a URL", raw, err)
		}
		if got := canonicalPort(u); got != want {
			t.Errorf("canonicalPort(%q) = %t, want %t", raw, got, want)
		}
	}
}

// jwksFixture serves one key of each kind and signs tokens with them.
type jwksFixture struct {
	srv     *jwksServer
	members map[string]any
	kids    map[string]string
}

func newJWKSFixture(tb testing.TB) *jwksFixture {
	tb.Helper()
	ed := mustEdKey(tb)
	f := &jwksFixture{
		members: map[string]any{
			algRS256: testRSAKey(), algRS384: testRSAKey(), algRS512: testRSAKey(),
			algPS256: testRSAKey(), algPS384: testRSAKey(), algPS512: testRSAKey(),
			algES256: mustECKey(tb, elliptic.P256()), algES384: mustECKey(tb, elliptic.P384()),
			algES512: mustECKey(tb, elliptic.P521()), algEdDSA: ed,
		},
		kids: map[string]string{algRS256: kidR, algES256: "e256", algES384: "e384", algES512: "e521", algEdDSA: "ed"},
	}
	jwks := make([]map[string]any, 0, len(f.kids))
	for alg, kid := range f.kids {
		jwks = append(jwks, publicJWK(tb, f.key(tb, alg), map[string]any{memberKid: kid}))
	}
	f.srv = newJWKSServer(tb, jwksDocument(tb, jwks...))
	return f
}

func (f *jwksFixture) sign(tb testing.TB, alg string, claims map[string]any) string {
	tb.Helper()
	kid := f.kids[alg]
	if kid == "" {
		kid = f.kids[algRS256]
	}
	return signToken(tb, alg, f.key(tb, alg), kid, claims)
}

// key returns the private key of alg.
func (f *jwksFixture) key(tb testing.TB, alg string) any {
	tb.Helper()
	k, ok := f.members[alg]
	if !ok {
		tb.Fatalf("key(%s) found none, want a fixture key", alg)
	}
	return k
}

func TestOAuthAuthenticatorValidateToken(t *testing.T) {
	f := newJWKSFixture(t)
	a := newTestOAuth(t, jwksOAuth(f.srv.URL), nil)
	now := time.Unix(testUnix, 0)
	for alg := range f.members {
		token := f.sign(t, alg, testClaims())
		id, err := a.validateToken(t.Context(), token, now)
		if err != nil {
			t.Errorf("validateToken(%s) = %v, want nil", alg, err)
			continue
		}
		if id.subject != testUser || id.mode != ModeOAuth || !slices.Equal(id.scopes, []string{testRead, testWrite}) ||
			id.claims != mustJSON(t, testClaims()) {
			t.Errorf("validateToken(%s) = %+v, want %s granted read and write with the signed claims", alg, id,
				testUser)
		}
		other := f.sign(t, alg, claimsWith(map[string]any{claimSub: testAdmin}))
		parts, otherParts := strings.Split(token, jwsSeparator), strings.Split(other, jwsSeparator)
		forged := parts[0] + jwsSeparator + otherParts[1] + jwsSeparator + parts[2]
		if id, err := a.validateToken(t.Context(), forged, now); id != nil || !errors.Is(err, errSignature) {
			t.Errorf("validateToken(%s, swapped payload) = %+v, %v, want nil, errSignature", alg, id, err)
		}
	}
	if hits := f.srv.hits.Load(); hits != 1 {
		t.Errorf("JWKS requests = %d, want 1", hits)
	}
}

func TestOAuthAuthenticatorValidateTokenRejects(t *testing.T) {
	f := newJWKSFixture(t)
	a := newTestOAuth(t, jwksOAuth(f.srv.URL), nil)
	now := time.Unix(testUnix, 0)
	priv := testRSAKey()
	tests := []struct {
		name  string
		token string
		want  error
	}{
		{algHS256, signToken(t, algHS256, []byte(testLongSecret), "", testClaims()), errUnsupportedAlg},
		{"none", segment(`{"alg":"none"}`) + jwsSeparator + segment(mustJSON(t, testClaims())) + jwsSeparator,
			errUnsupportedAlg},
		{"garbage", "not a token", errMalformedToken},
		{"ES256 over RSA", signRaw(t, algRS256, priv, `{"alg":"ES256","kid":"r"}`, mustJSON(t, testClaims())),
			errNoKey},
		{"unknown kid", signToken(t, algRS256, priv, "zz", testClaims()), errNoKey},
		{"other key", signToken(t, algRS256, testRSAKey2(), kidR, testClaims()), errSignature},
		{"expired", f.sign(t, algES256, claimsWith(map[string]any{claimExp: testUnix - 3600})), ErrTokenExpired},
		{"ID token", f.sign(t, algEdDSA, claimsWith(map[string]any{testClaimNonce: "n", claimScope: nil})), errIDToken},
	}
	for _, tc := range tests {
		f.srv.hits.Store(0)
		if id, err := a.validateToken(t.Context(), tc.token, now); id != nil || !errors.Is(err, tc.want) {
			t.Errorf("validateToken(%s) = %+v, %v, want nil, %v", tc.name, id, err, tc.want)
		}
		if errors.Is(tc.want, errUnsupportedAlg) && f.srv.hits.Load() != 0 {
			t.Errorf("validateToken(%s) fetched keys %d times, want 0", tc.name, f.srv.hits.Load())
		}
	}
}

func TestOAuthAuthenticatorValidateTokenHMAC(t *testing.T) {
	a := newTestOAuth(t, hmacOAuth(), nil)
	now := time.Unix(testUnix, 0)
	mac := []byte(testLongSecret)
	input := segment(`{"alg":"HS256"}`) + ".A"
	badPayload := input + jwsSeparator + base64.RawURLEncoding.EncodeToString(signInput(t, algHS256, mac, input))
	tests := []struct {
		name  string
		token string
		want  error
	}{
		{algHS256, signToken(t, algHS256, mac, "", testClaims()), nil},
		{algHS384, signToken(t, algHS384, mac, "any", testClaims()), errUnsupportedAlg},
		{algHS512, signToken(t, algHS512, mac, "any", testClaims()), errUnsupportedAlg},
		{algRS256, signToken(t, algRS256, testRSAKey(), "", testClaims()), errUnsupportedAlg},
		{"other secret", signToken(t, algHS256, []byte(testLongSecret+"x"), "", testClaims()), errSignature},
		{"payload encoding", badPayload, errMalformedToken},
		{"over max size", tokenOfSize(t, tokenLimit+1), errTokenTooLarge},
		{"max size", tokenOfSize(t, tokenLimit), nil},
	}
	for _, tc := range tests {
		id, err := a.validateToken(t.Context(), tc.token, now)
		if !errors.Is(err, tc.want) || (err == nil) == (id == nil) {
			t.Errorf("validateToken(%s) = %+v, %v, want %v and an identity only without error", tc.name, id, err,
				tc.want)
		}
	}
}

// tokenOfSize signs an HS256 token of exactly size bytes.
func tokenOfSize(tb testing.TB, size int) string {
	tb.Helper()
	build := func(pad, kid int) string {
		return signToken(tb, algHS256, []byte(testLongSecret), strings.Repeat("k", kid),
			claimsWith(map[string]any{"pad": strings.Repeat("p", pad)}))
	}
	start := max(0, (size-len(build(0, 1)))*3/4-8)
	for pad := start; pad < start+padRange; pad++ {
		for kid := 1; kid <= maxKidLen; kid++ {
			if token := build(pad, kid); len(token) == size {
				return token
			}
		}
	}
	tb.Fatalf("tokenOfSize(%d) found no token, want one of that size", size)
	return ""
}

func TestOAuthAuthenticatorValidateTokenAccessType(t *testing.T) {
	oc := hmacOAuth()
	oc.RequireAccessTokenType = true
	a := newTestOAuth(t, oc, nil)
	mac, claims := []byte(testLongSecret), mustJSON(t, testClaims())
	for typ, want := range map[string]error{"at+jwt": nil, "application/at+jwt": nil, "JWT": errTokenType} {
		token := signRaw(t, algHS256, mac, `{"alg":"HS256","typ":"`+typ+`"}`, claims)
		id, err := a.validateToken(t.Context(), token, time.Unix(testUnix, 0))
		if !errors.Is(err, want) || (err == nil) == (id == nil) {
			t.Errorf("validateToken(typ %s) = %+v, %v, want %v and an identity only without error", typ, id, err, want)
		}
	}
	untyped := signRaw(t, algHS256, mac, `{"alg":"HS256"}`, claims)
	if id, err := a.validateToken(t.Context(), untyped, time.Unix(testUnix, 0)); id != nil ||
		!errors.Is(err, errTokenType) {
		t.Errorf("validateToken(no typ) = %+v, %v, want nil, errTokenType", id, err)
	}
}

// TestOAuthAuthenticatorValidateTokenRenewsKeys presents a token of a key
// the set lacks: the set is refetched once per retry.After until it has it.
func TestOAuthAuthenticatorValidateTokenRenewsKeys(t *testing.T) {
	keyA, keyB := testRSAKey(), testRSAKey2()
	jwkA, jwkB := publicJWK(t, keyA, map[string]any{memberKid: kidA}), publicJWK(t, keyB,
		map[string]any{memberKid: "b"})
	srv := newJWKSServer(t, jwksDocument(t, jwkA))
	a := newTestOAuth(t, jwksOAuth(srv.URL), nil)
	t0 := time.Unix(testUnix, 0)
	tokenB := signToken(t, algRS256, keyB, "b", testClaims())
	if _, err := a.validateToken(t.Context(), tokenB, t0); !errors.Is(err, errNoKey) || srv.hits.Load() != 2 {
		t.Fatalf("validateToken = %v after %d requests, want errNoKey after 2", err, srv.hits.Load())
	}
	srv.set(http.StatusOK, jwksDocument(t, jwkA, jwkB))
	for _, st := range []struct {
		at   time.Duration
		want error
		hits int32
	}{
		{fetchPause - time.Second, errNoKey, 2},
		{fetchPause, nil, hitsAfterRefetch},
	} {
		if _, err := a.validateToken(t.Context(), tokenB, t0.Add(st.at)); !errors.Is(err, st.want) ||
			srv.hits.Load() != st.hits {
			t.Fatalf("validateToken(+%v) = %v after %d requests, want %v after %d", st.at, err, srv.hits.Load(),
				st.want, st.hits)
		}
	}
	noKid := signToken(t, algRS256, keyA, "", testClaims())
	_, err := a.validateToken(t.Context(), noKid, t0.Add(2*fetchPause))
	if !errors.Is(err, errAmbiguousKey) || srv.hits.Load() != hitsAfterRefetch {
		t.Fatalf("validateToken(no kid, two keys) = %v after %d requests, want errAmbiguousKey after 3", err,
			srv.hits.Load())
	}
}

func TestOAuthAuthenticatorValidateTokenLongTTL(t *testing.T) {
	key := testRSAKey()
	srv := newJWKSServer(t, jwksDocument(t, publicJWK(t, key, map[string]any{memberKid: kidA})))
	oc := jwksOAuth(srv.URL)
	oc.KeysCacheTTL = 2 * staleLimit
	a := newTestOAuth(t, oc, nil)
	t0 := time.Unix(testUnix, 0)
	if _, err := a.validateToken(t.Context(), signToken(t, algRS256, key, kidA, testClaims()), t0); err != nil {
		t.Fatalf("validateToken = %v, want nil", err)
	}
	srv.set(http.StatusServiceUnavailable, nil)
	unknown := signToken(t, algRS256, key, "b", testClaims())
	_, err := a.validateToken(t.Context(), unknown, t0.Add(25*time.Hour))
	if !errors.Is(err, ErrKeysUnavailable) || !errors.Is(err, errNoKey) || srv.hits.Load() != 2 {
		t.Fatalf("validateToken(unknown kid, refresh failing) = %v after %d requests, want ErrKeysUnavailable "+
			"of errNoKey after 2", err, srv.hits.Load())
	}
}

// liveToken signs testClaims, valid for the next hour, with members replaced.
func liveToken(tb testing.TB, members map[string]any) string {
	tb.Helper()
	c := claimsWith(map[string]any{claimExp: time.Now().Add(time.Hour).Unix()})
	maps.Copy(c, members)
	return signToken(tb, algHS256, []byte(testLongSecret), "", c)
}

// scopedOAuth requires testRead.
func scopedOAuth(tb testing.TB) *oauthAuthenticator {
	tb.Helper()
	oc := hmacOAuth()
	oc.RequiredScopes = []string{testRead}
	return newTestOAuth(tb, oc, nil)
}

// TestOAuthAuthenticatorAuthenticatePassesTheContext discovers the issuer and
// fetches its keys, again for an unknown kid, under the context of the request.
func TestOAuthAuthenticatorAuthenticatePassesTheContext(t *testing.T) {
	priv := testRSAKey()
	jwks := jwksDocument(t, publicJWK(t, priv, map[string]any{memberKid: "r"}))
	idp := newFakeIDP(t)
	idp.doc = func() (int, string) {
		return http.StatusOK, `{"issuer":"` + testIDPIssuer + `","jwks_uri":"https://` + testIDPHost + `/tenant/keys"}`
	}
	mux := http.NewServeMux()
	mux.Handle("/tenant/keys", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(jwks); err != nil {
			t.Errorf("Write = %v, want nil", err)
		}
	}))
	mux.Handle(pathRoot, idp)
	var fetches atomic.Int32
	cfg := validOAuth()
	cfg.HTTPClient = &http.Client{Transport: markCounting(&fetches, hostTransport{testIDPHost: mux})}
	cfg.OAuth.Issuer, cfg.OAuth.HMACSecret = testIDPIssuer, secret.Value{}
	g := mustGate(t, cfg)
	claims := claimsWith(map[string]any{claimIss: testIDPIssuer, claimExp: time.Now().Add(time.Hour).Unix()})
	// The discovery and the key set, then the key set again for an unknown kid.
	const firstFetches, refetches = 2, 3
	for _, tc := range []struct {
		kid   string
		want  error
		total int32
	}{{"r", nil, firstFetches}, {"unknown", errNoKey, refetches}} {
		r := newReq(t, http.MethodGet, pathRoot, http.NoBody).WithContext(marked(t))
		r.Header.Set(headerAuthorization, "Bearer "+signToken(t, algRS256, priv, tc.kid, claims))
		_, err := g.Authenticate(r)
		if !errors.Is(err, tc.want) || fetches.Load() != tc.total {
			t.Fatalf("Authenticate(kid %s) = %v after %d marked fetches, want %v after %d", tc.kid, err,
				fetches.Load(), tc.want, tc.total)
		}
	}
}

func TestOAuthAuthenticatorAuthenticate(t *testing.T) {
	id, e := scopedOAuth(t).authenticate(bearerRequest(t, liveToken(t, nil)))
	if e != nil || id.Subject() != testUser || id.Mode() != ModeOAuth {
		t.Fatalf("authenticate = %+v, %v, want an OAuth identity of %s", id, e, testUser)
	}
	if sub, ok := id.ClaimString(claimSub); !ok || sub != testUser {
		t.Fatalf("ClaimString(sub) = %q, %v, want %q", sub, ok, testUser)
	}
}

func TestOAuthAuthenticatorAuthenticateFailures(t *testing.T) {
	a := scopedOAuth(t)
	expired := liveToken(t, map[string]any{claimExp: time.Now().Add(-time.Hour).Unix()})
	tests := []struct {
		name   string
		token  string
		kind   error
		status int
		scope  string
	}{
		{"no token", "", ErrMissingCredentials, http.StatusUnauthorized, ""},
		{"missing scope", liveToken(t, map[string]any{claimScope: testWrite}), ErrInsufficientScope,
			http.StatusForbidden, testRead},
		{"expired", expired, ErrTokenExpired, http.StatusUnauthorized, ""},
		{"bad signature", liveToken(t, nil) + "A", ErrInvalidCredentials, http.StatusUnauthorized, ""},
	}
	for _, tc := range tests {
		id, e := a.authenticate(bearerRequest(t, tc.token))
		if id != nil || e == nil || !errors.Is(e, tc.kind) || e.status != tc.status || e.scope != tc.scope {
			t.Errorf("authenticate(%s) = %+v, %v, want nil, %v %d scope %q", tc.name, id, e, tc.kind, tc.status,
				tc.scope)
		}
	}
}

func TestOAuthAuthenticatorAuthenticateKeysUnavailable(t *testing.T) {
	good := newJWKSServer(t, jwksDocument(t, publicJWK(t, testRSAKey(), map[string]any{memberKid: kidR})))
	moved := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, good.URL, http.StatusFound)
	}))
	defer moved.Close()
	down := newJWKSServer(t, nil)
	down.set(http.StatusBadGateway, nil)
	expSec := time.Now().Add(time.Hour).Unix()
	token := signToken(t, algRS256, testRSAKey(), kidR, claimsWith(map[string]any{claimExp: expSec}))
	for jwksURL, status := range map[string]int{moved.URL: http.StatusFound, down.URL: http.StatusBadGateway} {
		a := newTestOAuth(t, jwksOAuth(jwksURL), moved.Client())
		id, e := a.authenticate(bearerRequest(t, token))
		if id != nil || e == nil || !errors.Is(e, ErrKeysUnavailable) || e.status != http.StatusServiceUnavailable ||
			!errorMatches(e, statusError(status)) || good.hits.Load() != 0 {
			t.Errorf("authenticate(JWKS answering %d) = %+v, %v, want nil, a 503 ErrKeysUnavailable caused by it",
				status, id, e)
		}
	}
}

// TestOAuthAuthenticatorValidateTokenHMACSizes verifies every HMAC algorithm
// under a secret as long as the widest hash.
func TestOAuthAuthenticatorValidateTokenHMACSizes(t *testing.T) {
	oc := hmacOAuth()
	oc.HMACSecret = secret.New(testWideSecret)
	a := newTestOAuth(t, oc, nil)
	for _, alg := range []string{algHS256, algHS384, algHS512} {
		token := signToken(t, alg, []byte(testWideSecret), "", testClaims())
		if _, err := a.validateToken(t.Context(), token, time.Unix(testUnix, 0)); err != nil {
			t.Errorf("validateToken(%s under a 64-byte secret) = %v, want nil", alg, err)
		}
	}
}

func TestOAuthAuthenticatorTokenFailure(t *testing.T) {
	a := newOAuthAuthenticator(hmacOAuth(), nil)
	outage := failure(ErrKeysUnavailable, "verification keys unavailable", errUpstream)
	if got := a.tokenFailure(outage); got != outage {
		t.Fatalf("tokenFailure(keys unavailable) = %+v, want it unchanged", got)
	}
	tests := []struct {
		err       error
		kind      error
		msg, text string
		status    int
	}{
		{ErrTokenExpired, ErrTokenExpired, "", "authware: token expired", http.StatusUnauthorized},
		{wrapError(errIssuer), ErrInvalidCredentials, string(errIssuer),
			"authware: invalid credentials: detail: invalid token issuer", http.StatusUnauthorized},
		{errOther, ErrInvalidCredentials, "invalid token", "authware: invalid credentials: test: other",
			http.StatusUnauthorized},
	}
	for _, tc := range tests {
		e := a.tokenFailure(tc.err)
		if !errors.Is(e, tc.kind) || !errors.Is(e, tc.err) || e.msg != tc.msg || e.Error() != tc.text ||
			e.status != tc.status {
			t.Errorf("tokenFailure(%v) = %+v %q, want %v %q %q %d", tc.err, e, e, tc.kind, tc.msg, tc.text, tc.status)
		}
	}
}

// TestTokenTextNamesEveryTokenError reads every tokenError constant of the
// package source: tokenText names each by its own text.
func TestTokenTextNamesEveryTokenError(t *testing.T) {
	pkg := os.DirFS(".")
	names, err := fs.Glob(pkg, "*.go")
	if err != nil {
		t.Fatalf("Glob = %v, want the package files", err)
	}
	var texts []string
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := fs.ReadFile(pkg, name)
		if err != nil {
			t.Fatalf("ReadFile(%s) = %v, want its source", name, err)
		}
		for _, m := range tokenErrorLiteral.FindAllStringSubmatch(string(src), -1) {
			text, err := strconv.Unquote(m[1])
			if err != nil {
				t.Fatalf("Unquote(%s) = %v, want the text", m[1], err)
			}
			texts = append(texts, text)
		}
	}
	if len(texts) < minTokenErrors {
		t.Fatalf("tokenError constants = %q, want at least %d", texts, minTokenErrors)
	}
	for _, text := range texts {
		if got := tokenText(wrapError(tokenError(text))); got != text {
			t.Errorf("tokenText(a %q failure) = %q, want %q", text, got, text)
		}
	}
}

// tokenErrorLiteral matches the conversion of a string literal to tokenError.
var tokenErrorLiteral = regexp.MustCompile(`tokenError\(("(?:[^"\\]|\\.)*")\)`)

// minTokenErrors is how many tokenError constants the package declares at
// least.
const minTokenErrors = 15

// errOther is an error that no classification knows.
var errOther = errors.New("test: other")

func wrapError(err error) error {
	return fmt.Errorf("detail: %w", err)
}

// FuzzOAuthAuthenticatorValidateToken checks every token against
// referenceValidate: the identity of a token it accepts, else its refusal
// class.
func FuzzOAuthAuthenticatorValidateToken(f *testing.F) {
	mac := []byte(testWideSecret)
	for _, alg := range []string{algHS256, algHS384, algHS512} {
		f.Add(signToken(f, alg, mac, "k", testClaims()))
	}
	f.Add(signRaw(f, algHS256, mac, `{"alg":"HS256","typ":"at+jwt"}`, mustJSON(f, claimsWith(map[string]any{
		claimAud: []string{"x", testMCPServer}, claimScp: []string{kidA}, testClaimNbf: testUnix,
	}))))
	f.Add(signRaw(f, algHS256, mac, `{"alg":"HS256"}`, mustJSON(f, claimsWith(map[string]any{claimIss: "x"}))))
	f.Add(signToken(f, algHS256, []byte(testLongSecret), "", testClaims()))
	f.Add(signToken(f, algRS256, testRSAKey(), "", testClaims()))
	oc := hmacOAuth()
	oc.HMACSecret, oc.ClockSkew = secret.New(testWideSecret), policySkew*time.Second
	a := newTestOAuth(f, oc, nil)
	f.Fuzz(func(t *testing.T, token string) {
		id, err := a.validateToken(t.Context(), token, time.Unix(testUnix, 0))
		want, wantErr := referenceValidate(token)
		if got := outcomeOf(id); !errors.Is(err, wantErr) || (wantErr == nil) != (err == nil) || got != want {
			t.Fatalf("validateToken(%q) = %+v, %v; want %+v, %v", token, got, err, want, wantErr)
		}
	})
}

// tokenOutcome is the identity of a validated token: its mode, subject,
// scopes joined by spaces, and claims text; the zero value stands for none.
type tokenOutcome struct {
	mode                    Mode
	subject, grants, claims string
}

func outcomeOf(id *Identity) tokenOutcome {
	if id == nil {
		return tokenOutcome{}
	}
	return tokenOutcome{mode: id.mode, subject: id.subject, grants: strings.Join(id.scopes, " "), claims: id.claims}
}

// referenceValidate returns the outcome of a token that referenceJWS reads, of
// an HS* alg and the HMAC of testWideSecret, whose claims referenceClaims
// accepts, or the class of its refusal.
func referenceValidate(token string) (tokenOutcome, error) {
	tok, err := referenceJWS(token)
	if err != nil {
		return tokenOutcome{}, err
	}
	hashes := map[string]crypto.Hash{"HS256": crypto.SHA256, "HS384": crypto.SHA384, "HS512": crypto.SHA512}
	hash, ok := hashes[tok.jose.algName]
	if !ok {
		return tokenOutcome{}, errUnsupportedAlg
	}
	mac := hmac.New(hash.New, []byte(testWideSecret))
	_, _ = mac.Write([]byte(tok.signedAs))
	if !hmac.Equal(mac.Sum(nil), []byte(tok.sigText)) {
		return tokenOutcome{}, errSignature
	}
	c, err := referenceClaims(tok.claims)
	if err != nil {
		return tokenOutcome{}, err
	}
	return tokenOutcome{mode: ModeOAuth, subject: c.subject, grants: strings.Join(c.scopes, " "), claims: tok.claims},
		nil
}

// TestOAuthAuthenticatorValidateTokenAllocs verifies an HMAC token and an
// EdDSA token whose key the JWKS cache holds: neither key adds an allocation.
func TestOAuthAuthenticatorValidateTokenAllocs(t *testing.T) {
	oc := hmacOAuth()
	oc.HMACSecret = secret.New(testWideSecret)
	f := newJWKSFixture(t)
	now := time.Unix(testUnix, 0)
	for _, tc := range []struct {
		alg   string
		a     *oauthAuthenticator
		token string
	}{
		{algHS256, newTestOAuth(t, oc, nil), signToken(t, algHS256, []byte(testWideSecret), "", testClaims())},
		{algEdDSA, newTestOAuth(t, jwksOAuth(f.srv.URL), nil), f.sign(t, algEdDSA, testClaims())},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			assertAllocs(t, verifiedTokenAllocs, func() {
				if _, err := tc.a.validateToken(t.Context(), tc.token, now); err != nil {
					t.Fatalf("validateToken(%s) = %v, want an identity", tc.alg, err)
				}
			})
		})
	}
}

func BenchmarkOAuthAuthenticatorValidateToken(b *testing.B) {
	now := time.Unix(testUnix, 0)
	bench := func(a *oauthAuthenticator, alg, token string) {
		b.Run(alg, func(b *testing.B) {
			if id, err := a.validateToken(b.Context(), token, now); err != nil || id.subject != testUser {
				b.Fatalf("validateToken = %v, %v, want %s", id, err, testUser)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.validateToken(b.Context(), token, now); err != nil {
					b.Fatalf("validateToken = %v, want nil", err)
				}
			}
		})
	}
	f := newJWKSFixture(b)
	jwks := newTestOAuth(b, jwksOAuth(f.srv.URL), nil)
	for _, alg := range []string{
		algRS256, algRS384, algRS512, algPS256, algPS384, algPS512, algES256, algES384, algES512, algEdDSA,
	} {
		bench(jwks, alg, f.sign(b, alg, testClaims()))
	}
	oc := hmacOAuth()
	oc.HMACSecret = secret.New(testWideSecret)
	mac := newTestOAuth(b, oc, nil)
	for _, alg := range []string{algHS256, algHS384, algHS512} {
		bench(mac, alg, signToken(b, alg, []byte(testWideSecret), "", testClaims()))
	}
}
