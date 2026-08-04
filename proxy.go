package authware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

const defaultProxyFetchTimeout = 10 * time.Second

var (
	paramClientID     = []byte("client_id=")
	paramClientSecret = []byte("client_secret=")
	paramAmpersand    = []byte("&")
)

const (
	scopeOpenID        = "openid"
	scopeProfile       = "profile"
	scopeEmail         = "email"
	scopeOfflineAccess = "offline_access"
)

var (
	rawResponseTypes     = []byte(`["code"]`)
	rawGrantTypes        = []byte(`["authorization_code","refresh_token"]`)
	rawTokenAuthMethods  = []byte(`["none"]`)
	rawCodeChallengeS256 = []byte(`["S256"]`)
	rawRedirectURIsEmpty = []byte(`[]`)
)

// proxyState carries the upstream endpoints discovered from the IdP.
// Published as an immutable snapshot via atomic.Pointer so handlers
// read it lock-free.
type proxyState struct {
	tokenEndpoint string
	authzEndpoint string
}

// fetchCall lets concurrent callers share a single in-flight upstream
// metadata fetch instead of stampeding the IdP.
type fetchCall struct {
	done  chan struct{}
	state *proxyState
	err   error
}

// OAuthProxy provides HTTP handlers for the OAuth facade. Upstream
// discovery is lazy and single-flight: the elected goroutine never
// holds a mutex while the upstream HTTP call runs.
type OAuthProxy struct {
	httpClient           *http.Client
	inflight             atomic.Pointer[fetchCall]
	state                atomic.Pointer[proxyState]
	log                  *slog.Logger
	upstreamScopeStr     string
	clientID             string
	clientSecret         string
	scopesJSON           []byte
	credentials          []byte
	authorizationServers []string
	requiredScopes       []string
	fetchTimeout         time.Duration
	fetchMu              sync.Mutex
}

// NewOAuthProxy creates an OAuth proxy from the given Config. Returns
// nil when no AuthorizationServers are configured or no ClientID is
// set (proxy not needed).
//
// cfg.OAuthHTTPClient is used for upstream calls when set; nil installs
// a fresh client with the configured fetch timeout. The fetch timeout
// falls back to 10s when cfg.OAuthProxyFetchTimeout is zero.
func NewOAuthProxy(cfg *Config, log *slog.Logger) *OAuthProxy {
	if len(cfg.OAuthAuthorizationServers) == 0 || cfg.OAuthClientID == "" {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	scopes := append([]string(nil), cfg.OAuthRequiredScopes...)
	timeout := cfg.OAuthProxyFetchTimeout
	if timeout <= 0 {
		timeout = defaultProxyFetchTimeout
	}
	client := cfg.OAuthHTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &OAuthProxy{
		clientID:             cfg.OAuthClientID,
		clientSecret:         cfg.OAuthClientSecret,
		requiredScopes:       scopes,
		authorizationServers: append([]string(nil), cfg.OAuthAuthorizationServers...),
		scopesJSON:           buildScopesJSON(scopes),
		upstreamScopeStr:     buildUpstreamScopeStr(cfg.OAuthResource, scopes),
		credentials:          buildCredentials(cfg.OAuthClientID, cfg.OAuthClientSecret),
		log:                  log,
		httpClient:           client,
		fetchTimeout:         timeout,
	}
}

func (p *OAuthProxy) loadState() *proxyState { return p.state.Load() }

// ensureFetched returns the current upstream state. Fast path: a single
// atomic load. Cold callers join (or kick off) a single-flight fetch
// without holding any mutex during HTTP.
func (p *OAuthProxy) ensureFetched(ctx context.Context) (*proxyState, bool) {
	if st := p.loadState(); st != nil {
		return st, true
	}
	call := p.beginFetch(ctx)
	select {
	case <-call.done:
		return call.state, call.err == nil && call.state != nil
	case <-ctx.Done():
		return nil, false
	}
}

func (p *OAuthProxy) beginFetch(ctx context.Context) *fetchCall {
	if call := p.inflight.Load(); call != nil {
		return call
	}
	p.fetchMu.Lock()
	if call := p.inflight.Load(); call != nil {
		p.fetchMu.Unlock()
		return call
	}
	call := &fetchCall{done: make(chan struct{})}
	p.inflight.Store(call)
	p.fetchMu.Unlock()

	go p.runFetch(ctx, call)
	return call
}

// runFetch performs the fetch shared by every waiter: detached from the
// elected caller's cancellation, bounded by its own timeout, outside any
// lock. Success overwrites p.state; failure leaves it nil so the next
// caller retries. The inflight slot is cleared before close(done) so a
// new caller after a failure starts a fresh fetch instead of re-reading
// the cached failure.
func (p *OAuthProxy) runFetch(ctx context.Context, call *fetchCall) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.fetchTimeout)
	defer cancel()

	state, err := p.discoverUpstream(ctx)
	call.state, call.err = state, err
	if state != nil {
		p.state.Store(state)
	}
	p.fetchMu.Lock()
	p.inflight.Store(nil)
	p.fetchMu.Unlock()
	close(call.done)
}

// setStateForTest is a test-only seam.
func (p *OAuthProxy) setStateForTest(token, authz string) {
	p.state.Store(&proxyState{tokenEndpoint: token, authzEndpoint: authz})
}

// buildScopesJSON returns the pre-serialized scopes_supported array,
// with the four standard OIDC scopes followed by any non-duplicate
// requiredScopes.
func buildScopesJSON(requiredScopes []string) []byte {
	base := [...]string{scopeOpenID, scopeProfile, scopeEmail, scopeOfflineAccess}
	merged := make([]string, 0, len(base)+len(requiredScopes))
	seen := make(map[string]struct{}, len(base)+len(requiredScopes))
	for _, s := range base {
		seen[s] = struct{}{}
		merged = append(merged, s)
	}
	for _, s := range requiredScopes {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		merged = append(merged, s)
	}
	b := jsonfast.Acquire()
	defer jsonfast.Release(b)
	b.AppendRawString("[")
	for i, s := range merged {
		if i > 0 {
			b.AppendRawString(",")
		}
		b.AppendRawString(`"`)
		b.AppendEscapedString(s)
		b.AppendRawString(`"`)
	}
	b.AppendRawString("]")
	out := make([]byte, b.Len())
	copy(out, b.Bytes())
	return out
}

// buildUpstreamScopeStr returns the space-separated scope string sent
// to the upstream IdP.
func buildUpstreamScopeStr(resource string, requiredScopes []string) string {
	if len(requiredScopes) == 0 {
		return ""
	}
	resource = strings.TrimRight(resource, "/")
	seen := make(map[string]struct{}, len(requiredScopes)+2)
	parts := make([]string, 0, len(requiredScopes)+2)
	for _, s := range []string{scopeOpenID, scopeOfflineAccess} {
		seen[s] = struct{}{}
		parts = append(parts, s)
	}
	for _, s := range requiredScopes {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		qualified := s
		if resource != "" && !strings.Contains(s, "://") && !strings.Contains(s, "/") {
			qualified = resource + "/" + s
		}
		if _, dup := seen[qualified]; !dup {
			seen[qualified] = struct{}{}
			parts = append(parts, qualified)
		}
	}
	return strings.Join(parts, " ")
}

// buildCredentials returns the pre-built "client_id=...&client_secret=..."
// blob, or nil when clientSecret is empty.
func buildCredentials(clientID, clientSecret string) []byte {
	if clientSecret == "" {
		return nil
	}
	return []byte("client_id=" + clientID + "&client_secret=" + clientSecret)
}

// ASMetadataHandler serves the AS metadata document.
func (p *OAuthProxy) ASMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.ensureFetched(r.Context()); !ok {
			http.Error(w, "upstream AS metadata unavailable", http.StatusBadGateway)
			return
		}
		issuer := requestIssuer(r)

		b := jsonfast.Acquire()
		b.BeginObject()
		b.AddStringField("issuer", issuer)
		b.AddStringField("authorization_endpoint", issuer+"/authorize")
		b.AddStringField("token_endpoint", issuer+"/token")
		b.AddStringField("registration_endpoint", issuer+"/register")
		b.AddRawJSONField("response_types_supported", rawResponseTypes)
		b.AddRawJSONField("grant_types_supported", rawGrantTypes)
		b.AddRawJSONField("token_endpoint_auth_methods_supported", rawTokenAuthMethods)
		b.AddRawJSONField("code_challenge_methods_supported", rawCodeChallengeS256)
		b.AddRawJSONField("scopes_supported", p.scopesJSON)
		b.EndObject()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(b.Bytes()); err != nil {
			p.log.DebugContext(r.Context(), "write AS metadata response", "err", err)
		}
		jsonfast.Release(b)
	}
}

// requestIssuer derives the issuer URL from r, preferring TLS, then
// X-Forwarded-Proto, then http.
func requestIssuer(r *http.Request) string {
	scheme := schemeHTTP
	switch {
	case r.TLS != nil:
		scheme = schemeHTTPS
	default:
		if fp := r.Header.Get("X-Forwarded-Proto"); fp == schemeHTTPS || fp == schemeHTTP {
			scheme = fp
		}
	}
	return scheme + "://" + r.Host
}

// RegisterHandler returns a static client registration shim.
func (p *OAuthProxy) RegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := readAllLimited(r.Body, 64<<10)
		if closeErr := r.Body.Close(); closeErr != nil {
			p.log.DebugContext(ctx, "close DCR request body", "err", closeErr)
		}
		if err != nil {
			p.log.DebugContext(ctx, "read DCR request body", "err", err)
		}

		redirectURIs := rawRedirectURIsEmpty
		if raw, ok := jsonfast.FindField(body, "redirect_uris"); ok && len(raw) > 0 {
			redirectURIs = raw
		}

		b := jsonfast.Acquire()
		b.BeginObject()
		b.AddStringField("client_id", p.clientID)
		b.AddInt64Field("client_id_issued_at", time.Now().Unix())
		b.AddStringField("token_endpoint_auth_method", "none")
		b.AddRawJSONField("grant_types", rawGrantTypes)
		b.AddRawJSONField("response_types", rawResponseTypes)
		b.AddRawJSONField("redirect_uris", redirectURIs)
		b.EndObject()
		data := b.Bytes()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write(data); err != nil {
			p.log.DebugContext(ctx, "write DCR response", "err", err)
		}
		jsonfast.Release(b)
		p.log.InfoContext(ctx, "DCR shim: issued client_id",
			"client_id", p.clientID,
			"redirect_uris_len", len(redirectURIs))
	}
}

// AuthorizeHandler redirects to the upstream IdP authorisation endpoint.
func (p *OAuthProxy) AuthorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, ok := p.ensureFetched(r.Context())
		if !ok || st.authzEndpoint == "" {
			http.Error(w, "authorization endpoint not configured", http.StatusBadGateway)
			return
		}
		if err := requireHTTPS(st.authzEndpoint); err != nil {
			http.Error(w, "upstream authorize endpoint not https", http.StatusBadGateway)
			return
		}
		target, err := buildAuthorizeURL(st.authzEndpoint, r.URL.RawQuery, p.upstreamScopeStr)
		if err != nil {
			http.Error(w, "build authorize URL", http.StatusBadGateway)
			return
		}
		p.log.DebugContext(r.Context(), "authorize redirect", "target", target, "scope", p.upstreamScopeStr)
		// target authority is pinned to st.authzEndpoint (operator-
		// configured, host-validated against the issuer); only the
		// query string can be influenced by the inbound request.
		http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // G710: see comment.
	}
}

// buildAuthorizeURL composes the upstream authorize URL with the
// client's query string, optionally rewriting scope.
func buildAuthorizeURL(authzEndpoint, rawQuery, upstreamScope string) (string, error) {
	if _, err := url.Parse(authzEndpoint); err != nil {
		return "", err
	}
	target := authzEndpoint
	q := rawQuery
	if upstreamScope != "" && q != "" {
		if vals, err := url.ParseQuery(q); err == nil {
			vals.Set("scope", upstreamScope)
			q = vals.Encode()
		}
	}
	if q != "" {
		target += "?" + q
	}
	return target, nil
}

// TokenHandler proxies token exchange to the upstream IdP token endpoint.
func (p *OAuthProxy) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, ok := p.ensureFetched(r.Context())
		if !ok || st.tokenEndpoint == "" {
			http.Error(w, "token endpoint not configured", http.StatusBadGateway)
			return
		}
		body, ok := p.readTokenBody(w, r)
		if !ok {
			return
		}
		gt := formValue(body, "grant_type")
		if !bytes.Equal(gt, []byte("authorization_code")) && !bytes.Equal(gt, []byte("refresh_token")) {
			http.Error(w, "unsupported grant_type", http.StatusBadRequest)
			return
		}
		if p.clientSecret != "" {
			body = p.injectClientCredentials(body)
		}
		p.proxyToken(r.Context(), w, st.tokenEndpoint, body)
	}
}

func (p *OAuthProxy) readTokenBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		http.Error(w, "Content-Type must be application/x-www-form-urlencoded", http.StatusBadRequest)
		return nil, false
	}
	body, err := readAllLimited(r.Body, 64<<10)
	if closeErr := r.Body.Close(); closeErr != nil {
		p.log.DebugContext(r.Context(), "close token request body", "err", closeErr)
	}
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

// formValue extracts the first occurrence of a URL-encoded form field.
func formValue(body []byte, name string) []byte {
	search := []byte(name + "=")
	for len(body) > 0 {
		i := bytes.Index(body, search)
		if i < 0 {
			return nil
		}
		if i == 0 || body[i-1] == '&' {
			val := body[i+len(search):]
			if before, _, found := bytes.Cut(val, paramAmpersand); found {
				return before
			}
			return val
		}
		body = body[i+1:]
	}
	return nil
}

func (p *OAuthProxy) proxyToken(ctx context.Context, w http.ResponseWriter, tokenEndpoint string, body []byte) {
	if err := requireHTTPS(tokenEndpoint); err != nil {
		http.Error(w, "upstream token endpoint not https", http.StatusBadGateway)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.log.WarnContext(ctx, "token proxy: upstream request failed", "err", err)
		http.Error(w, "upstream token request failed", http.StatusBadGateway)
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			p.log.DebugContext(ctx, "close upstream token response body", "err", closeErr)
		}
	}()

	p.copyProxyHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, io.LimitReader(resp.Body, 256<<10)); err != nil {
		p.log.DebugContext(ctx, "token proxy: write response", "err", err)
	}
	p.log.DebugContext(ctx, "token proxy: forwarded", "status", resp.StatusCode)
}

func (p *OAuthProxy) copyProxyHeaders(w http.ResponseWriter, resp *http.Response) {
	for _, h := range [...]string{"Content-Type", "Cache-Control", "Pragma"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// injectClientCredentials strips client_id/client_secret from a URL-
// encoded body and appends the pre-computed credentials blob.
func (p *OAuthProxy) injectClientCredentials(body []byte) []byte {
	parts := bytes.Split(body, paramAmpersand)
	out := parts[:0]
	for _, part := range parts {
		if len(part) == 0 ||
			bytes.HasPrefix(part, paramClientID) ||
			bytes.HasPrefix(part, paramClientSecret) {
			continue
		}
		out = append(out, part)
	}
	out = append(out, p.credentials)
	return bytes.Join(out, paramAmpersand)
}

// upstreamMeta holds the fields lifted from an upstream IdP discovery
// document.
type upstreamMeta struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
}

// fetchUpstreamMeta tries each well-known URL and returns the first
// valid upstream metadata. expectedIssuer constrains the published
// issuer to the discovery host.
func (p *OAuthProxy) fetchUpstreamMeta(ctx context.Context, urls []string, expectedIssuer string) *upstreamMeta {
	for _, u := range urls {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := requireHTTPS(u); err != nil {
			p.log.WarnContext(ctx, "upstream AS metadata URL must be https", "url", u, "err", err)
			continue
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if reqErr != nil {
			p.log.WarnContext(ctx, "build upstream AS metadata request", "url", u, "err", reqErr)
			continue
		}
		resp, err := p.httpClient.Do(req)
		if err != nil {
			p.log.WarnContext(ctx, "fetch upstream AS metadata", "url", u, "err", err)
			continue
		}
		body, readErr := readAllLimited(resp.Body, 256<<10)
		if closeErr := resp.Body.Close(); closeErr != nil {
			p.log.DebugContext(ctx, "close upstream AS metadata response body", "err", closeErr)
		}
		if readErr != nil || resp.StatusCode != http.StatusOK {
			p.log.WarnContext(ctx, "fetch upstream AS metadata", "url", u, "status", resp.StatusCode)
			continue
		}
		um, err := parseUpstreamMeta(body, expectedIssuer)
		if err != nil {
			p.log.WarnContext(ctx, "validate upstream AS metadata", "url", u, "err", err)
			continue
		}
		return um
	}
	return nil
}

var (
	errUpstreamMissingFields = errors.New("upstream AS metadata missing required fields")
	errUpstreamHostMismatch  = errors.New("upstream AS metadata endpoint host does not match issuer")
)

// parseUpstreamMeta lifts the three required fields from the document
// and verifies endpoint authority binding.
func parseUpstreamMeta(data []byte, expectedIssuer string) (*upstreamMeta, error) {
	um, err := readUpstreamFields(data)
	if err != nil {
		return nil, err
	}
	if err := validateIssuerHost(um.Issuer, expectedIssuer); err != nil {
		return nil, err
	}
	if err := assertSameAuthority(um.Issuer, um.AuthorizationEndpoint, um.TokenEndpoint); err != nil {
		return nil, err
	}
	return um, nil
}

func readUpstreamFields(data []byte) (*upstreamMeta, error) {
	issuer, ok1 := findStringField(data, "issuer")
	authz, ok2 := findStringField(data, "authorization_endpoint")
	token, ok3 := findStringField(data, "token_endpoint")
	if !ok1 || !ok2 || !ok3 || issuer == "" || authz == "" || token == "" {
		return nil, errUpstreamMissingFields
	}
	return &upstreamMeta{
		Issuer:                issuer,
		AuthorizationEndpoint: authz,
		TokenEndpoint:         token,
	}, nil
}

// validateIssuerHost requires the issuer in the AS metadata to match
// the host the document was discovered from.
func validateIssuerHost(issuer, expected string) error {
	if expected == "" {
		return nil
	}
	issuerHost, err := schemeHost(issuer)
	if err != nil {
		return err
	}
	// A malformed expected host (e.g. an unusual server URL) is not
	// fatal: if the authority cannot be derived, no mismatch can be
	// proven and the document is accepted.
	if expectedHost, parseErr := schemeHost(expected); parseErr == nil && issuerHost != expectedHost {
		return errUpstreamHostMismatch
	}
	return nil
}

// assertSameAuthority verifies every endpoint shares the issuer's
// scheme://host[:port] authority.
func assertSameAuthority(issuer string, endpoints ...string) error {
	want, err := schemeHost(issuer)
	if err != nil {
		return err
	}
	for _, ep := range endpoints {
		got, err := schemeHost(ep)
		if err != nil {
			return err
		}
		if got != want {
			return errUpstreamHostMismatch
		}
	}
	return nil
}

func schemeHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errUpstreamMissingFields
	}
	return u.Scheme + "://" + u.Host, nil
}

func findStringField(data []byte, key string) (string, bool) {
	raw, ok := jsonfast.FindField(data, key)
	if !ok {
		return "", false
	}
	return jsonfast.DecodeString(raw)
}

// discoverUpstream iterates authorizationServers in order and returns
// the first valid AS discovery document.
func (p *OAuthProxy) discoverUpstream(ctx context.Context) (*proxyState, error) {
	for _, server := range p.authorizationServers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		issuer := strings.TrimRight(server, "/")
		urls := []string{
			issuer + "/.well-known/openid-configuration",
			issuer + "/.well-known/oauth-authorization-server",
		}
		um := p.fetchUpstreamMeta(ctx, urls, issuer)
		if um == nil {
			p.log.WarnContext(ctx, "upstream AS metadata unavailable, trying next", "server", server)
			continue
		}
		p.log.InfoContext(ctx, "fetched upstream AS metadata",
			"issuer", um.Issuer,
			"authorization_endpoint", um.AuthorizationEndpoint,
			"token_endpoint", um.TokenEndpoint)
		return &proxyState{
			tokenEndpoint: um.TokenEndpoint,
			authzEndpoint: um.AuthorizationEndpoint,
		}, nil
	}
	p.log.ErrorContext(ctx, "failed to fetch upstream AS metadata from any configured server")
	return nil, errUpstreamMissingFields
}
