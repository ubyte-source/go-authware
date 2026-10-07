package authware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// Header names and sizes of the token tests.
const (
	headerContentType = "Content-Type"
	headerPragma      = "Pragma"
	kib               = 1 << 10
	mib               = 1 << 20
)

func tokenRequest(tb testing.TB, body, contentType string) *http.Request {
	tb.Helper()
	r := newReq(tb, http.MethodPost, testMCPOrigin+pathToken, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set(headerContentType, contentType)
	}
	return r
}

func postToken(tb testing.TB, f *facade, body, contentType string) *httptest.ResponseRecorder {
	tb.Helper()
	return serve(http.HandlerFunc(f.serveToken), tokenRequest(tb, body, contentType))
}

// codeExchange returns the code exchange Claude Code sends.
func codeExchange() url.Values {
	verifier, _ := pkcePair("claude")
	return url.Values{
		oauthwire.ParamGrantType: {grantAuthorizationCode}, "code": {"0.AXcode"}, paramCodeVerifier: {verifier},
		paramRedirectURI: {testLoopbackURI}, oauthwire.ParamClientID: {testFacadeClient},
		oauthwire.ParamResource: {testMCPResource},
	}
}

// refreshGrant returns a refresh request for testRefreshToken.
func refreshGrant() url.Values {
	return url.Values{
		oauthwire.ParamGrantType: {oauthwire.GrantRefreshToken}, oauthwire.ParamRefreshToken: {testRefreshToken},
	}
}

// forwarded returns params as the provider expects them relayed: without
// the client resource and authenticated as the facade client.
func forwarded(params url.Values) url.Values {
	out := maps.Clone(params)
	out.Del(oauthwire.ParamResource)
	out.Set(oauthwire.ParamClientID, testFacadeClient)
	out.Set(oauthwire.ParamClientSecret, testFacadeSecret)
	return out
}

// checkRelayed requires w to carry the provider token reply, uncached.
func checkRelayed(tb testing.TB, w *httptest.ResponseRecorder) {
	tb.Helper()
	hd := w.Header()
	if w.Code != http.StatusOK || w.Body.String() != testTokenReply || hd.Get(headerContentType) != testTypeJSON ||
		hd.Get("Cache-Control") != oauthwire.CacheNoStore || hd.Get(headerPragma) != oauthwire.PragmaNoCache {
		tb.Fatalf("token = %d %v %s, want 200 uncached %s", w.Code, hd, w.Body, testTokenReply)
	}
}

func TestFacadeServeToken(t *testing.T) {
	exchange := codeExchange()
	refresh := refreshGrant()
	const form = oauthwire.FormContentType
	tests := []struct {
		name        string
		configure   func(*FacadeConfig)
		body        string
		contentType string
		want        url.Values
	}{
		{"code exchange", keepFacade, exchange.Encode(), form, forwarded(exchange)},
		{"form charset", keepFacade, exchange.Encode(), form + "; charset=UTF-8", forwarded(exchange)},
		{"client credentials stripped", keepFacade,
			exchange.Encode() + "&client_secret=evil&client_assertion=jwt&client_assertion_type=bearer", form,
			forwarded(exchange)},
		{"unknown parameters dropped", keepFacade, exchange.Encode() + "&" + smuggled().Encode(), form,
			forwarded(exchange)},
		{"encoded names stripped", keepFacade,
			strings.Replace(exchange.Encode(), "client_id=", "client%5Fid=", 1) + "&client%5Fsecret=evil", form,
			forwarded(exchange)},
		{
			"refresh", keepFacade,
			with(with(refresh, oauthwire.ParamClientID, "dcr"), oauthwire.ParamResource, testMCPResource).Encode(),
			form,
			forwarded(refresh),
		},
		{"refresh scope", keepFacade, with(refresh, oauthwire.ParamScope, "memory offline_access").Encode(), form,
			with(forwarded(refresh), oauthwire.ParamScope, testScopePrefix+"/memory offline_access")},
		{
			"refresh colon scope", keepFacade,
			with(refresh, oauthwire.ParamScope, "memory:read "+testScopePrefix+"/x").Encode(), form,
			with(forwarded(refresh), oauthwire.ParamScope, testScopePrefix+"/memory:read "+testScopePrefix+"/x"),
		},
		{"public client", func(c *FacadeConfig) { c.ClientSecret = secret.Value{} },
			with(refresh, oauthwire.ParamClientSecret, "evil").Encode(), form,
			with(refresh, oauthwire.ParamClientID, testFacadeClient)},
		{"upstream resource", func(c *FacadeConfig) { c.UpstreamResource = testUpstreamRes },
			with(refresh, oauthwire.ParamResource, "https://x").Encode(), form,
			with(forwarded(refresh), oauthwire.ParamResource, testUpstreamRes)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkForwarded(t, tc.configure, tc.body, tc.contentType, tc.want)
		})
	}
}

// keepFacade leaves the facade settings unchanged.
func keepFacade(*FacadeConfig) {}

// checkForwarded posts body to a facade adjusted by configure and requires
// the provider to receive exactly the form want, authenticated in the body.
func checkForwarded(t *testing.T, configure func(*FacadeConfig), body, contentType string, want url.Values) {
	t.Helper()
	idp := newFakeIDP(t)
	cfg := facadeConfig(idp)
	configure(&cfg.OAuth.Facade)
	checkRelayed(t, postToken(t, testFacade(t, cfg), body, contentType))
	got := idp.received()
	if len(got) != 1 || !maps.EqualFunc(got[0].form, want, slices.Equal) ||
		got[0].contentType != oauthwire.FormContentType || got[0].basicAuth {
		t.Fatalf("provider received %+v, want one form request %v without Basic auth", got, want)
	}
}

// TestFacadeServeTokenClaudeClients relays the code exchange and the refresh
// each Claude client sends.
func TestFacadeServeTokenClaudeClients(t *testing.T) {
	for _, c := range claudeClients() {
		t.Run(c.name, func(t *testing.T) {
			code := with(codeExchange(), paramRedirectURI, c.redirectURI)
			checkForwarded(t, keepFacade, code.Encode(), oauthwire.FormContentType, forwarded(code))
			refresh := with(refreshGrant(), oauthwire.ParamClientID, testFacadeClient)
			refresh = with(refresh, oauthwire.ParamResource, testMCPResource)
			want := forwarded(refresh)
			if c.refreshScope != "" {
				refresh.Set(oauthwire.ParamScope, c.refreshScope)
				want.Set(oauthwire.ParamScope, testScopePrefix+"/"+c.refreshScope)
			}
			checkForwarded(t, keepFacade, refresh.Encode(), oauthwire.FormContentType, want)
		})
	}
}

// TestFacadeServeTokenBodyLimit pins the 64 KiB body bound: a grant padded
// to exactly the limit is relayed, one byte more is refused.
func TestFacadeServeTokenBodyLimit(t *testing.T) {
	const limit = 64 << 10
	valid := refreshGrant().Encode() + "&pad="
	for size, want := range map[int]int{limit: http.StatusOK, limit + 1: http.StatusBadRequest} {
		idp := newFakeIDP(t)
		w := postToken(t, testFacade(t, facadeConfig(idp)), valid+strings.Repeat(verifierLetter, size-len(valid)),
			oauthwire.FormContentType)
		relayed := len(idp.received())
		if w.Code != want || (want == http.StatusOK) != (relayed == 1) ||
			w.Code == http.StatusBadRequest && oauthErrorCode(t, w) != codeInvalidRequest {
			t.Errorf("token of %d bytes = %d, %d relayed; want %d (%s when refused)",
				size, w.Code, relayed, want, codeInvalidRequest)
		}
	}
}

func TestFacadeServeTokenRejects(t *testing.T) {
	exchange := codeExchange()
	valid := exchange.Encode()
	verifier := func(v string) string { return with(exchange, paramCodeVerifier, v).Encode() }
	const form, bad, grant = oauthwire.FormContentType, codeInvalidRequest, codeUnsupportedGrantType
	const scope = testInvalidScope
	tests := map[string]struct{ body, contentType, code string }{
		"no content type": {valid, "", bad},
		"json":            {`{"grant_type":"authorization_code"}`, testTypeJSON, bad},
		"multipart":       {valid, "multipart/form-data; boundary=x", bad},
		"bad escape":      {valid + "&x=%zz", form, bad},
		"semicolon":       {valid + ";x=1", form, bad},
		"repeated grant":  {"grant_type=refresh_token&refresh_token=r&grant_type=client_credentials", form, bad},
		"encoded grant":   {"grant%5Ftype=client_credentials&grant_type=refresh_token&refresh_token=r", form, bad},
		"repeated client": {valid + "&client_id=other", form, bad},
		"client grant":    {"grant_type=client_credentials&scope=api%3A%2F%2Fx%2F.default", form, grant},
		"password":        {"grant_type=password&username=u&password=p", form, grant},
		"device code":     {"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code", form, grant},
		"no grant":        {without(exchange, oauthwire.ParamGrantType).Encode(), form, grant},
		"no verifier":     {without(exchange, paramCodeVerifier).Encode(), form, bad},
		"short verifier":  {verifier(strings.Repeat(verifierLetter, minVerifier-1)), form, bad},
		"long verifier":   {verifier(strings.Repeat(verifierLetter, maxVerifier+1)), form, bad},
		"spaced verifier": {verifier(strings.Repeat(verifierLetter, 42) + " "), form, bad},
		"bad redirect":    {with(exchange, paramRedirectURI, "not a uri").Encode(), form, bad},
		"http redirect":   {with(exchange, paramRedirectURI, "http://evil.example/cb").Encode(), form, bad},
		"empty redirect":  {with(refreshGrant(), paramRedirectURI, "").Encode(), form, bad},
		"fragment":        {with(refreshGrant(), paramRedirectURI, "https://claude.ai/cb#f").Encode(), form, bad},
		"graph scope": {
			with(refreshGrant(), oauthwire.ParamScope, "https://graph.microsoft.com/.default").Encode(), form, scope,
		},
		"other api scope": {with(refreshGrant(), oauthwire.ParamScope, "memory api://other/memory").Encode(), form,
			scope},
		"urn scope": {with(refreshGrant(), oauthwire.ParamScope, "urn:other").Encode(), form, scope},
	}
	for name, tc := range tests {
		idp := newFakeIDP(t)
		w := postToken(t, testFacade(t, facadeConfig(idp)), tc.body, tc.contentType)
		if code := oauthErrorCode(t, w); w.Code != http.StatusBadRequest || code != tc.code ||
			len(idp.received()) != 0 || idp.discoveries.Load() != 0 ||
			w.Header().Get(headerPragma) != oauthwire.PragmaNoCache {
			t.Errorf("%s: token = %d %s after %d discoveries, %d relayed; want 400 %s no-cache, nothing sent upstream",
				name, w.Code, code, idp.discoveries.Load(), len(idp.received()), tc.code)
		}
	}
}

func TestFacadeServeTokenRelaysErrors(t *testing.T) {
	idp := newFakeIDP(t)
	idp.answer = func(w http.ResponseWriter, _ *http.Request) {
		hd := w.Header()
		hd.Set(headerContentType, testTypeJSON)
		hd.Add(headerChallenge, `Basic realm="login"`)
		hd.Add(headerChallenge, `Bearer realm="api"`)
		hd.Set("Set-Cookie", "upstream=1")
		hd.Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusUnauthorized)
		writeBody(t, w, `{"error":"invalid_client"}`)
	}
	w := postToken(t, testFacade(t, facadeConfig(idp)), codeExchange().Encode(), oauthwire.FormContentType)
	hd := w.Header()
	challenges := []string{`Basic realm="login"`, `Bearer realm="api"`}
	if code := oauthErrorCode(t, w); w.Code != http.StatusUnauthorized || code != "invalid_client" ||
		hd.Get("Set-Cookie") != "" || !slices.Equal(hd.Values(headerChallenge), challenges) ||
		hd.Get(headerPragma) != oauthwire.PragmaNoCache {
		t.Fatalf("token = %d %s %v, want 401 invalid_client, WWW-Authenticate %q, no cookie, no-cache",
			w.Code, code, hd, challenges)
	}
}

// redirectTo makes the provider answer token requests with a redirect of
// status code to evil.
func redirectTo(evil http.Handler, code int) func(*fakeIDP, *Config) {
	return func(idp *fakeIDP, cfg *Config) {
		cfg.HTTPClient = &http.Client{Transport: hostTransport{testIDPHost: idp, "evil.example": evil}}
		idp.answer = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example/steal", code)
		}
	}
}

// serverError makes the provider answer token requests with status code, a
// temporarily_unavailable error and a Retry-After of its own, 120 seconds.
func serverError(code int) func(*fakeIDP, *Config) {
	return func(idp *fakeIDP, _ *Config) {
		idp.answer = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(headerContentType, testTypeJSON)
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(code)
			writeBody(idp.tb, w, `{"error":"temporarily_unavailable"}`)
		}
	}
}

// closeRecorder is a response body that records its closing and fails it
// with err.
type closeRecorder struct {
	io.Reader

	err    error
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return c.err
}

func TestFacadeServeTokenUpstreamFailures(t *testing.T) {
	var elsewhere atomic.Int32
	evil := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) })
	const relayFailed = "authware: token relay failed"
	tests := map[string]struct {
		setup func(*fakeIDP, *Config)
		msg   string
		cause error
	}{
		"found":                 {redirectTo(evil, http.StatusFound), relayFailed, errUpstreamStatus},
		"see other":             {redirectTo(evil, http.StatusSeeOther), relayFailed, errUpstreamStatus},
		"temporary redirect":    {redirectTo(evil, http.StatusTemporaryRedirect), relayFailed, errUpstreamStatus},
		"internal server error": {serverError(http.StatusInternalServerError), relayFailed, errUpstreamStatus},
		"bad gateway":           {serverError(http.StatusBadGateway), relayFailed, errUpstreamStatus},
		"service unavailable":   {serverError(http.StatusServiceUnavailable), relayFailed, errUpstreamStatus},
		"gateway timeout":       {serverError(http.StatusGatewayTimeout), relayFailed, errUpstreamStatus},
		"oversized answer": {func(idp *fakeIDP, _ *Config) {
			idp.answer = func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, string(make([]byte, mib+1)))
			}
		}, relayFailed, errBodyTooLarge},
		"transport error": {func(_ *fakeIDP, cfg *Config) {
			onTokenPost(cfg, func(*http.Request) (*http.Response, error) { return nil, errUpstream })
		}, relayFailed, errUpstream},
		"close failure": {func(_ *fakeIDP, cfg *Config) {
			onTokenPost(cfg, func(*http.Request) (*http.Response, error) {
				body := &closeRecorder{Reader: strings.NewReader(testTokenReply), err: errUpstream}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: body}, nil
			})
		}, relayFailed, errUpstream},
		"status below 100": {func(_ *fakeIDP, cfg *Config) {
			onTokenPost(cfg, answerWith(0, testTokenReply))
		}, relayFailed, errUpstreamStatus},
		"switching protocols": {func(_ *fakeIDP, cfg *Config) {
			onTokenPost(cfg, answerWith(http.StatusSwitchingProtocols, testTokenReply))
		}, relayFailed, errUpstreamStatus},
		"no content with a body": {func(_ *fakeIDP, cfg *Config) {
			onTokenPost(cfg, answerWith(http.StatusNoContent, testTokenReply))
		}, relayFailed, errBodyNotAllowed},
		"discovery": {func(idp *fakeIDP, _ *Config) {
			idp.doc = func() (int, string) { return http.StatusNotFound, "" }
		}, "authware: metadata fetch failed", errDiscovery},
	}
	for name, tc := range tests {
		idp := newFakeIDP(t)
		var logs logCapture
		cfg := facadeConfig(idp)
		cfg.ErrorLog = slog.New(&logs)
		tc.setup(idp, cfg)
		w := postToken(t, testFacade(t, cfg), codeExchange().Encode(), oauthwire.FormContentType)
		if code := oauthErrorCode(t, w); w.Code != http.StatusServiceUnavailable ||
			code != oauthwire.CodeTemporarilyUnavailable || w.Header().Get("Retry-After") != "30" ||
			elsewhere.Load() != 0 || !logs.warned(tc.msg, tc.cause) {
			t.Errorf("%s: token = %d %s, Retry-After %q after %d requests elsewhere, logged %+v; want 503 %s, "+
				"Retry-After 30, none elsewhere and %q", name, w.Code, code, w.Header().Get("Retry-After"),
				elsewhere.Load(), logs.logged(), oauthwire.CodeTemporarilyUnavailable, tc.msg)
		}
	}
}

// TestFacadeServeTokenPassesTheContext discovers, relays and warns of a failed
// relay under the context of the request.
func TestFacadeServeTokenPassesTheContext(t *testing.T) {
	idp := newFakeIDP(t)
	idp.answer = func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, string(make([]byte, mib+1)))
	}
	var sends atomic.Int32
	logs := &logCapture{}
	cfg := facadeConfig(idp)
	cfg.HTTPClient.Transport, cfg.ErrorLog = markCounting(&sends, cfg.HTTPClient.Transport), slog.New(logs)
	r := tokenRequest(t, codeExchange().Encode(), oauthwire.FormContentType).WithContext(marked(t))
	w := serve(http.HandlerFunc(testFacade(t, cfg).serveToken), r)
	if got := logs.logged(); w.Code != http.StatusServiceUnavailable || sends.Load() != 2 ||
		len(got) != 1 || !got[0].inMarked {
		t.Fatalf("token = %d after %d marked requests, logged %+v; want 503 after the discovery and the relay, "+
			"warned under the request's context", w.Code, sends.Load(), got)
	}
}

// TestFacadeServeTokenAnswerLimit pins the 1 MiB bound on the upstream
// answer: exactly 1 MiB is relayed, one byte more is an upstream failure.
func TestFacadeServeTokenAnswerLimit(t *testing.T) {
	for size, want := range map[int]int{mib: http.StatusOK, mib + 1: http.StatusServiceUnavailable} {
		idp := newFakeIDP(t)
		idp.answer = func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write(make([]byte, size)); err != nil {
				t.Errorf("Write = %v, want nil", err)
			}
		}
		w := postToken(t, testFacade(t, facadeConfig(idp)), refreshGrant().Encode(), oauthwire.FormContentType)
		if w.Code != want || (want == http.StatusOK && w.Body.Len() != size) {
			t.Errorf("token with a %d-byte answer = %d with %d bytes, want %d", size, w.Code, w.Body.Len(), want)
		}
	}
}

// onTokenPost answers the token requests of cfg with rt and sends every other
// request through the transport cfg had.
func onTokenPost(cfg *Config, rt roundTripFunc) {
	routes := cfg.HTTPClient.Transport
	cfg.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return rt(r)
		}
		return routes.RoundTrip(r)
	})}
}

// TestFacadeServeTokenStalls stalls the upstream token endpoint: the relay
// gives up after exactly FetchTimeout, or at once when the client leaves.
func TestFacadeServeTokenStalls(t *testing.T) {
	for name, tc := range map[string]struct {
		want  time.Duration
		leave bool
	}{"timeout": {want: wantFetchTimeout}, "client gone": {leave: true}} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				cfg := facadeConfig(newFakeIDP(t))
				onTokenPost(cfg, func(r *http.Request) (*http.Response, error) {
					if tc.leave {
						cancel()
					}
					return stall(r)
				})
				f := testFacade(t, cfg)
				r := tokenRequest(t, codeExchange().Encode(), oauthwire.FormContentType).WithContext(ctx)
				start := time.Now()
				w := serve(http.HandlerFunc(f.serveToken), r)
				if code, elapsed := oauthErrorCode(t, w), time.Since(start); w.Code != http.StatusServiceUnavailable ||
					code != oauthwire.CodeTemporarilyUnavailable || elapsed != tc.want {
					t.Fatalf("token = %d %s after %v, want 503 %s after %v", w.Code, code, elapsed,
						oauthwire.CodeTemporarilyUnavailable, tc.want)
				}
			})
		})
	}
}

var errClientLeft = errors.New("test: client left")

// TestFacadeServeTokenCanceledByClient logs at debug a relay that failed because its
// client left, and at warn one the upstream failed, also after the client left, or
// canceled while the client stayed.
func TestFacadeServeTokenCanceledByClient(t *testing.T) {
	for name, tc := range map[string]struct {
		leave error
		cause error
		level slog.Level
	}{
		"client left":                  {leave: context.Canceled, cause: context.Canceled, level: slog.LevelDebug},
		"client left with a cause":     {leave: errClientLeft, cause: errClientLeft, level: slog.LevelDebug},
		"client left, cause dropped":   {leave: errClientLeft, cause: context.Canceled, level: slog.LevelDebug},
		"upstream failed, client left": {leave: context.Canceled, cause: errUpstream, level: slog.LevelWarn},
		"upstream canceled":            {cause: context.Canceled, level: slog.LevelWarn},
	} {
		ctx, cancel := context.WithCancelCause(t.Context())
		var logs logCapture
		cfg := facadeConfig(newFakeIDP(t))
		cfg.ErrorLog = slog.New(&logs)
		onTokenPost(cfg, func(*http.Request) (*http.Response, error) {
			if tc.leave != nil {
				cancel(tc.leave)
			}
			return nil, tc.cause
		})
		r := tokenRequest(t, refreshGrant().Encode(), oauthwire.FormContentType).WithContext(ctx)
		w := serve(http.HandlerFunc(testFacade(t, cfg).serveToken), r)
		cancel(nil)
		got := logs.logged()
		if code := oauthErrorCode(t, w); w.Code != http.StatusServiceUnavailable ||
			code != oauthwire.CodeTemporarilyUnavailable || len(got) != 1 || got[0].level != tc.level ||
			got[0].msg != "authware: token relay failed" || !errors.Is(got[0].err, tc.cause) {
			t.Errorf("%s: token = %d %s, logged %+v; want 503 %s and one token relay record at %v of %v",
				name, w.Code, code, got, oauthwire.CodeTemporarilyUnavailable, tc.level, tc.cause)
		}
	}
}

// TestFacadeServeTokenPastDeadline warns of a relay whose request passed its
// deadline, which is no cancellation.
func TestFacadeServeTokenPastDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		var logs logCapture
		cfg := facadeConfig(newFakeIDP(t))
		cfg.ErrorLog = slog.New(&logs)
		onTokenPost(cfg, stall)
		r := tokenRequest(t, refreshGrant().Encode(), oauthwire.FormContentType).WithContext(ctx)
		w := serve(http.HandlerFunc(testFacade(t, cfg).serveToken), r)
		if code := oauthErrorCode(t, w); w.Code != http.StatusServiceUnavailable ||
			code != oauthwire.CodeTemporarilyUnavailable ||
			!logs.warned("authware: token relay failed", context.DeadlineExceeded) {
			t.Fatalf("token past its deadline = %d %s, logged %+v; want 503 %s and the relay warned of %v", w.Code,
				code, logs.logged(), oauthwire.CodeTemporarilyUnavailable, context.DeadlineExceeded)
		}
	})
}

func TestValidVerifier(t *testing.T) {
	for v, want := range map[string]bool{
		strings.Repeat(verifierLetter, minVerifier):                                true,
		strings.Repeat(verifierAlphabet, maxVerifier/len(verifierAlphabet)) + "ab": true,
		strings.Repeat(verifierLetter, maxVerifier+1):                              false,
		strings.Repeat(verifierLetter, minVerifier-1):                              false,
		strings.Repeat(verifierLetter, minVerifier-1) + "+":                        false,
		strings.Repeat(verifierLetter, minVerifier-1) + "%":                        false,
		strings.Repeat(verifierLetter, minVerifier-1) + "é":                        false,
		"": false,
	} {
		if got := validVerifier(v); got != want {
			t.Errorf("validVerifier(%q) = %v, want %v", v, got, want)
		}
	}
}

// relayedAnswer relays an answer of status carrying testTokenReply and two
// challenges.
func relayedAnswer(status int) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	header := http.Header{headerContentType: {testTypeJSON}, "Www-Authenticate": {"Bearer a", "Bearer b"}}
	writeUpstreamAnswer(w, oauthwire.Answer{Header: header, Body: []byte(testTokenReply), Status: status})
	return w
}

func TestWriteUpstreamAnswer(t *testing.T) {
	for _, status := range []int{http.StatusOK, lastSuccess, http.StatusBadRequest, http.StatusUnauthorized} {
		w := relayedAnswer(status)
		hd := w.Header()
		if w.Code != status || w.Body.String() != testTokenReply || hd.Get(headerContentType) != testTypeJSON ||
			!slices.Equal(hd.Values(headerChallenge), []string{"Bearer a", "Bearer b"}) ||
			hd.Get("Cache-Control") != oauthwire.CacheNoStore || hd.Get(headerPragma) != oauthwire.PragmaNoCache {
			t.Errorf("relay of %d = %d %v %s, want it uncached as it came", status, w.Code, hd, w.Body)
		}
	}
}

// TestWriteUpstreamAnswerWithoutContentType relays an answer without a
// Content-Type through a real server, which sniffs one for a header that lacks
// it: the client must receive none.
func TestWriteUpstreamAnswerWithoutContentType(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ans := oauthwire.Answer{Header: http.Header{}, Body: []byte(testTokenReply), Status: status}
			writeUpstreamAnswer(w, ans)
		}))
		t.Cleanup(srv.Close)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequestWithContext(%s) = %v, want nil", srv.URL, err)
		}
		ans, err := oauthwire.Send(srv.Client(), req, errBodyTooLarge)
		if err != nil || ans.Status != status || string(ans.Body) != testTokenReply ||
			ans.Header.Values(headerContentType) != nil {
			t.Errorf("relay of %d without Content-Type = %d %q %v, %v; want %d %s without Content-Type", status,
				ans.Status, ans.Body, ans.Header, err, status, testTokenReply)
		}
	}
}

// writeRecorder passes each write to its ResponseWriter and keeps the failures.
type writeRecorder struct {
	http.ResponseWriter

	failed []error
}

func (w *writeRecorder) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if err != nil {
		w.failed = append(w.failed, err)
		return n, fmt.Errorf("write response: %w", err)
	}
	return n, nil
}

// TestWriteUpstreamAnswerNoContentOverHTTP2 relays a 204 through an HTTP/2 server,
// which refuses any write after a 204: the client gets the 204 and no write fails.
func TestWriteUpstreamAnswerNoContentOverHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := writeRecorder{ResponseWriter: w}
		writeUpstreamAnswer(&rec, oauthwire.Answer{Header: http.Header{}, Status: http.StatusNoContent})
		if r.ProtoMajor != 2 || rec.failed != nil {
			t.Errorf("relay of 204 over HTTP/%d: writes failed with %v; want HTTP/2 and none", r.ProtoMajor,
				rec.failed)
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequestWithContext(%s) = %v, want nil", srv.URL, err)
	}
	ans, err := oauthwire.Send(srv.Client(), req, errBodyTooLarge)
	if err != nil || ans.Status != http.StatusNoContent {
		t.Errorf("relay of 204 = %d, %v; want 204", ans.Status, err)
	}
}

func TestFacadePost(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusContinue - 1, "", errUpstreamStatus}, {http.StatusSwitchingProtocols, "", errUpstreamStatus},
		{lastInformational, "", errUpstreamStatus}, {http.StatusOK, "", nil}, {http.StatusNoContent, "", nil},
		{http.StatusNoContent, "0", errBodyNotAllowed}, {lastSuccess, "", nil},
		{http.StatusMultipleChoices, "", errUpstreamStatus}, {http.StatusFound, "", errUpstreamStatus},
		{lastRedirect, "", errUpstreamStatus}, {http.StatusBadRequest, "", nil}, {lastClientError, "", nil},
		{http.StatusInternalServerError, "", errUpstreamStatus},
	} {
		cfg := facadeConfig(newFakeIDP(t))
		onTokenPost(cfg, answerWith(tc.status, tc.body))
		f := testFacade(t, cfg)
		up, err := f.endpoints(t.Context(), time.Now())
		if err != nil {
			t.Fatalf("endpoints = %v, want the upstream endpoints", err)
		}
		ans, err := f.post(t.Context(), up.tokenURL, url.Values{})
		if !errors.Is(err, tc.want) || (tc.want == nil) != (ans.Status == tc.status) ||
			(tc.want == nil) == reflect.ValueOf(ans).IsZero() {
			t.Errorf("post answered %d %q = %+v, %v; want %v, with the zero answer on error", tc.status, tc.body,
				ans, err, tc.want)
		}
	}
	cfg := facadeConfig(newFakeIDP(t))
	onTokenPost(cfg, func(*http.Request) (*http.Response, error) { return nil, errUpstream })
	f := testFacade(t, cfg)
	up, err := f.endpoints(t.Context(), time.Now())
	if err != nil {
		t.Fatalf("endpoints = %v, want the upstream endpoints", err)
	}
	if ans, err := f.post(t.Context(), up.tokenURL, url.Values{}); !reflect.ValueOf(ans).IsZero() ||
		!errors.Is(err, errUpstream) {
		t.Errorf("post failing to send = %+v, %v; want the zero answer, %v", ans, err, errUpstream)
	}
}

// verifierPattern matches a PKCE code verifier of 43 to 128 unreserved
// characters.
var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// acceptedTokenForm is the oracle of the relay: it returns the form the
// provider must receive for body, else the OAuth error code of the refusal,
// the grant checked before the redirect_uri and the scope.
func acceptedTokenForm(body string) (want url.Values, code string) {
	in, code := tokenGrant(body)
	if code != "" {
		return nil, code
	}
	if in.Has("redirect_uri") && !referenceRedirectURI(in.Get("redirect_uri")) {
		return nil, codeInvalidRequest
	}
	want = url.Values{formClientID: {testFacadeClient}, oauthwire.ParamClientSecret: {testFacadeSecret},
		oauthwire.ParamResource: {testUpstreamRes}}
	for _, k := range []string{"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token"} {
		if v, ok := in[k]; ok {
			want[k] = v
		}
	}
	if in.Has("scope") {
		scope, ok := referenceUpstreamScope(nil, spaceFields(in.Get("scope")))
		if !ok {
			return nil, testInvalidScope
		}
		want.Set("scope", scope)
	}
	return want, ""
}

// tokenGrant decodes body, a form of unique parameters at most maxFormBytes
// long carrying a refresh grant or a code grant with a valid verifier, or
// returns the OAuth error code of its refusal.
func tokenGrant(body string) (in url.Values, code string) {
	in, err := url.ParseQuery(body)
	if err != nil || len(body) > maxFormBytes {
		return nil, codeInvalidRequest
	}
	for _, v := range in {
		if len(v) != 1 {
			return nil, codeInvalidRequest
		}
	}
	switch in.Get("grant_type") {
	case "authorization_code":
		if !verifierPattern.MatchString(in.Get("code_verifier")) {
			return nil, codeInvalidRequest
		}
	case "refresh_token":
	default:
		return nil, codeUnsupportedGrantType
	}
	return in, ""
}

// The longest PKCE verifier, letters of its alphabet, the last informational,
// redirect and client error statuses and the largest token request form.
const (
	maxVerifier       = 128
	verifierLetter    = "a"
	verifierAlphabet  = "Z9-._~"
	lastInformational = 199
	lastRedirect      = 399
	lastClientError   = 499
	maxFormBytes      = 64 * kib
)

// FuzzFacadeServeToken relays arbitrary form bodies: a body is forwarded
// exactly when the oracle accepts it, as the form the oracle builds.
func FuzzFacadeServeToken(f *testing.F) {
	for _, seed := range []string{
		codeExchange().Encode(),
		"grant_type=refresh_token&refresh_token=r&scope=memory+openid&resource=x",
		"grant_type=refresh_token&refresh_token=r&scope=memory%3Aread+api%3A%2F%2Fmemory-app%2Fx",
		"grant_type=refresh_token&refresh_token=r&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
		"grant_type=refresh_token&refresh_token=r&scope=urn%3Aother",
		"grant_type=refresh_token&refresh_token=r&scope=memory%0AMail.Read",
		"grant%5Ftype=client_credentials&grant_type=authorization_code",
		"grant_type=authorization_code&grant_type=client_credentials",
		"grant_type=refresh_token&refresh_token=r&client%5Fid=evil&client%5Fsecret=evil",
		"grant_type=refresh_token&refresh_token=r&client_assertion=a&client_assertion_type=b",
		"grant_type=refresh_token&refresh_token=r&audience=x&request=y&claims=z&x-unknown=1",
		"grant_type=refresh_token&refresh_token=%zz",
		"grant_type=refresh_token&refresh_token=r&redirect_uri=not%20a%20uri",
		"grant_type=password&redirect_uri=http%3A%2F%2Fevil.example%2Fcb",
		"grant_type=client_credentials",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		idp := newFakeIDP(t)
		cfg := facadeConfig(idp)
		cfg.OAuth.Facade.UpstreamResource = testUpstreamRes
		w := postToken(t, testFacade(t, cfg), body, oauthwire.FormContentType)
		want, code := acceptedTokenForm(body)
		got := idp.received()
		switch {
		case code != "" && (w.Code != http.StatusBadRequest || len(got) != 0 || oauthErrorCode(t, w) != code):
			t.Fatalf("token(%q) = %d %s, provider received %v; want 400 %s and nothing relayed", body, w.Code,
				w.Body, got, code)
		case code == "" && (w.Code != http.StatusOK || len(got) != 1 ||
			!maps.EqualFunc(got[0].form, want, slices.Equal)):
			t.Fatalf("token(%q) = %d, provider received %v; want 200 and the one form %v", body, w.Code, got, want)
		}
	})
}

// relayFailure is the oracle of the token relay: the cause the facade warns of
// for an upstream answer of status and body, or nil when it relays the answer.
func relayFailure(status int, body string) error {
	success := status >= http.StatusOK && status <= lastSuccess
	clientError := status >= http.StatusBadRequest && status <= lastClientError
	switch {
	case len(body) > mib:
		return errBodyTooLarge
	case !success && !clientError:
		return errUpstreamStatus
	case status == http.StatusNoContent && body != "":
		return errBodyNotAllowed
	}
	return nil
}

// FuzzFacadeServeTokenUpstreamAnswer draws the status and body of an upstream token
// answer: they are relayed exactly when the oracle accepts the answer, and otherwise
// the facade answers 503 and warns of the oracle's cause.
func FuzzFacadeServeTokenUpstreamAnswer(f *testing.F) {
	for _, status := range []int{
		0, http.StatusContinue - 1, http.StatusSwitchingProtocols, lastInformational, http.StatusOK,
		http.StatusNoContent, lastSuccess, http.StatusMultipleChoices, lastRedirect, http.StatusBadRequest,
		lastClientError, http.StatusInternalServerError,
	} {
		f.Add(status, testTokenReply)
	}
	f.Add(http.StatusNoContent, "")
	f.Fuzz(func(t *testing.T, status int, body string) {
		var logs logCapture
		cfg := facadeConfig(newFakeIDP(t))
		cfg.ErrorLog = slog.New(&logs)
		onTokenPost(cfg, answerWith(status, body))
		w := postToken(t, testFacade(t, cfg), refreshGrant().Encode(), oauthwire.FormContentType)
		if cause := relayFailure(status, body); cause != nil {
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" ||
				oauthErrorCode(t, w) != oauthwire.CodeTemporarilyUnavailable ||
				!logs.warned("authware: token relay failed", cause) {
				t.Fatalf("upstream %d with %d bytes = %d %s, Retry-After %q, logged %+v; want 503 %s, Retry-After "+
					"30 and the relay warned of %v", status, len(body), w.Code, w.Body, w.Header().Get("Retry-After"),
					logs.logged(), oauthwire.CodeTemporarilyUnavailable, cause)
			}
			return
		}
		if w.Code != status || w.Body.String() != body || len(logs.logged()) != 0 {
			t.Fatalf("upstream %d %q = %d %q, logged %+v; want its status and body relayed, nothing logged", status,
				body, w.Code, w.Body, logs.logged())
		}
	})
}
