package authware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

const proxyFetchTimeout = 10 * time.Second

// proxyHTTPClient is a shared client for token proxy requests and upstream
// AS metadata discovery. Reusing a single client enables connection pooling
// and avoids allocating a new transport per request.
var proxyHTTPClient = &http.Client{Timeout: proxyFetchTimeout}

// paramClientID and paramClientSecret are pre-allocated byte slices used
// as prefixes in injectClientCredentials to avoid per-call allocations.
var (
	paramClientID     = []byte("client_id=")
	paramClientSecret = []byte("client_secret=")
	paramAmpersand    = []byte("&")
)

// OAuthProxy provides HTTP handlers for the MCP OAuth facade: AS
// metadata discovery, static client registration shim, authorization
// redirect, and token endpoint proxying. Upstream endpoints are fetched
// once via sync.Once and cached for the process lifetime.
type OAuthProxy struct {
	log                   *slog.Logger
	clientID              string
	clientSecret          string
	requiredScopes        []string
	upstreamTokenEndpoint string
	upstreamAuthzEndpoint string
	authorizationServers  []string
	// scopesJSON is the pre-serialized "scopes_supported" JSON array.
	scopesJSON []byte
	// upstreamScopeStr qualifies bare scope names with the resource URI
	// (e.g. "myapi" → "api://resource-id/myapi") for upstream IdP
	// authorization requests. Empty when no resource URI is configured.
	upstreamScopeStr string
	// credentials is the pre-built "client_id=…&client_secret=…" blob.
	credentials []byte
	once        sync.Once
	fetched     bool
}

// NewOAuthProxy creates an OAuth proxy from the given Config.
// Returns nil if no OAuthAuthorizationServers are configured or
// OAuthClientID is empty (proxy not needed).
func NewOAuthProxy(cfg *Config, log *slog.Logger) *OAuthProxy {
	if len(cfg.OAuthAuthorizationServers) == 0 || cfg.OAuthClientID == "" {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	scopes := append([]string(nil), cfg.OAuthRequiredScopes...)
	return &OAuthProxy{
		clientID:             cfg.OAuthClientID,
		clientSecret:         cfg.OAuthClientSecret,
		requiredScopes:       scopes,
		authorizationServers: append([]string(nil), cfg.OAuthAuthorizationServers...),
		scopesJSON:           buildScopesJSON(scopes),
		upstreamScopeStr:     buildUpstreamScopeStr(cfg.OAuthResource, scopes),
		credentials:          buildCredentials(cfg.OAuthClientID, cfg.OAuthClientSecret),
		log:                  log,
	}
}

// buildScopesJSON returns the pre-serialized "scopes_supported" JSON array.
// Always includes the four standard OIDC scopes; appends any configured
// requiredScopes not already present. Called once at construction time.
func buildScopesJSON(requiredScopes []string) []byte {
	base := [...]string{"openid", "profile", "email", "offline_access"}
	seen := make(map[string]struct{}, len(base)+len(requiredScopes))

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, s := range base {
		seen[s] = struct{}{}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString(s)
		buf.WriteByte('"')
	}
	for _, s := range requiredScopes {
		if _, dup := seen[s]; dup || s == "" {
			continue
		}
		seen[s] = struct{}{}
		buf.WriteByte(',')
		buf.WriteByte('"')
		buf.WriteString(s)
		buf.WriteByte('"')
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

// buildUpstreamScopeStr returns the space-separated scope string for
// the upstream IdP authorization request, qualifying bare scope names
// with the resource URI ("myapi" → "api://resource-id/myapi") as
// required by Azure AD and similar IdPs. Adds "openid" and
// "offline_access" unconditionally.
func buildUpstreamScopeStr(resource string, requiredScopes []string) string {
	if len(requiredScopes) == 0 {
		return ""
	}
	resource = strings.TrimRight(resource, "/")
	seen := make(map[string]struct{}, len(requiredScopes)+2)
	parts := make([]string, 0, len(requiredScopes)+2)
	for _, s := range []string{"openid", "offline_access"} {
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

// buildCredentials returns the pre-built "client_id=...&client_secret=..." form
// parameter byte slice, or nil when clientSecret is empty. Called once at
// construction time so injectClientCredentials never allocates for this part.
func buildCredentials(clientID, clientSecret string) []byte {
	if clientSecret == "" {
		return nil
	}
	return []byte("client_id=" + clientID + "&client_secret=" + clientSecret)
}

// ASMetadataHandler returns an http.HandlerFunc that serves
// /.well-known/oauth-authorization-server per RFC 8414 and the MCP
// specification (2025-11-25). It fetches the upstream IdP's discovery
// document once, then serves a metadata document where the MCP server
// acts as the authorization server (issuer matches the request origin).
func (p *OAuthProxy) ASMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.once.Do(p.fetchUpstream)
		if !p.fetched {
			http.Error(w, "upstream AS metadata unavailable", http.StatusBadGateway)
			return
		}

		// Build issuer from request so it matches the MCP server origin.
		scheme := "https"
		if r.TLS == nil {
			if fp := r.Header.Get("X-Forwarded-Proto"); fp == "https" || fp == "http" {
				scheme = fp
			} else {
				scheme = "http"
			}
		}
		issuer := scheme + "://" + r.Host

		b := jsonfast.Acquire()
		b.BeginObject()
		b.AddStringField("issuer", issuer)
		b.AddStringField("authorization_endpoint", issuer+"/authorize")
		b.AddStringField("token_endpoint", issuer+"/token")
		b.AddStringField("registration_endpoint", issuer+"/register")
		b.AddRawJSONField("response_types_supported", []byte(`["code"]`))
		b.AddRawJSONField("grant_types_supported", []byte(`["authorization_code","refresh_token"]`))
		b.AddRawJSONField("token_endpoint_auth_methods_supported", []byte(`["none"]`))
		b.AddRawJSONField("code_challenge_methods_supported", []byte(`["S256"]`))
		b.AddRawJSONField("scopes_supported", p.scopesJSON)
		b.EndObject()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(b.Bytes()); err != nil {
			p.log.Debug("write AS metadata response", "err", err)
		}
		jsonfast.Release(b)
	}
}

// RegisterHandler returns a static RFC 7591 client registration shim:
// always responds with the pre-configured upstream IdP client_id, echoing
// back the client's redirect_uris. URIs are not validated — they must be
// pre-registered out-of-band with the upstream IdP.
func (p *OAuthProxy) RegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if closeErr := r.Body.Close(); closeErr != nil {
			p.log.Debug("close DCR request body", "err", closeErr)
		}
		if err != nil {
			p.log.Debug("read DCR request body", "err", err)
		}

		// RFC 7591 §3.2.1 requires the redirect_uris to appear in the response.
		redirectURIs := []byte(`[]`)
		if raw, ok := jsonfast.FindField(body, "redirect_uris"); ok && len(raw) > 0 {
			redirectURIs = raw
		}

		b := jsonfast.Acquire()
		b.BeginObject()
		b.AddStringField("client_id", p.clientID)
		b.AddInt64Field("client_id_issued_at", time.Now().Unix())
		b.AddStringField("token_endpoint_auth_method", "none")
		b.AddRawJSONField("grant_types", []byte(`["authorization_code","refresh_token"]`))
		b.AddRawJSONField("response_types", []byte(`["code"]`))
		b.AddRawJSONField("redirect_uris", redirectURIs)
		b.EndObject()
		data := b.Bytes()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write(data); err != nil {
			p.log.Debug("write DCR response", "err", err)
		}
		jsonfast.Release(b)
		p.log.Info("DCR shim: issued client_id", "client_id", p.clientID,
			"redirect_uris", string(redirectURIs))
	}
}

// AuthorizeHandler redirects the user to the upstream IdP authorization
// endpoint, overriding the "scope" query parameter with upstreamScopeStr
// (which qualifies bare scope names with the resource URI).
func (p *OAuthProxy) AuthorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.once.Do(p.fetchUpstream)
		if p.upstreamAuthzEndpoint == "" {
			http.Error(w, "authorization endpoint not configured", http.StatusBadGateway)
			return
		}
		target := p.upstreamAuthzEndpoint
		q := r.URL.RawQuery
		if p.upstreamScopeStr != "" && q != "" {
			vals, err := url.ParseQuery(q)
			if err == nil {
				vals.Set("scope", p.upstreamScopeStr)
				q = vals.Encode()
			}
		}
		if q != "" {
			target += "?" + q
		}
		p.log.Debug("authorize redirect", "target", target, "scope", p.upstreamScopeStr)
		http.Redirect(w, r, target, http.StatusFound)
	}
}

// TokenHandler returns an http.HandlerFunc that proxies token exchange
// requests to the upstream IdP's token endpoint.
func (p *OAuthProxy) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.once.Do(p.fetchUpstream)
		if p.upstreamTokenEndpoint == "" {
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
		p.proxyToken(r.Context(), w, body)
	}
}

// readTokenBody validates the Content-Type and reads the request body up to 64 KiB.
// On validation or read error it writes the appropriate response and returns (nil, false).
func (p *OAuthProxy) readTokenBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		http.Error(w, "Content-Type must be application/x-www-form-urlencoded", http.StatusBadRequest)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if closeErr := r.Body.Close(); closeErr != nil {
		p.log.Debug("close token request body", "err", closeErr)
	}
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

// formValue extracts the first occurrence of a URL-encoded form field value
// from a raw application/x-www-form-urlencoded body. The field must be
// preceded by the start of the body or an '&' separator.
func formValue(body []byte, name string) []byte {
	search := []byte(name + "=")
	for len(body) > 0 {
		i := bytes.Index(body, search)
		if i < 0 {
			return nil
		}
		if i == 0 || body[i-1] == '&' {
			val := body[i+len(search):]
			if j := bytes.IndexByte(val, '&'); j >= 0 {
				return val[:j]
			}
			return val
		}
		body = body[i+1:]
	}
	return nil
}

// proxyToken forwards a token exchange request to the upstream IdP and
// copies the response (status, selected headers, body) back to w.
func (p *OAuthProxy) proxyToken(ctx context.Context, w http.ResponseWriter, body []byte) {
	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost, p.upstreamTokenEndpoint, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := proxyHTTPClient.Do(req)
	if err != nil {
		p.log.Warn("token proxy: upstream request failed", "err", err)
		http.Error(w, "upstream token request failed", http.StatusBadGateway)
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			p.log.Debug("close upstream token response body", "err", closeErr)
		}
	}()

	p.copyProxyHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, io.LimitReader(resp.Body, 256<<10)); err != nil {
		p.log.Debug("token proxy: write response", "err", err)
	}
	p.log.Debug("token proxy: forwarded", "status", resp.StatusCode)
}

// copyProxyHeaders copies a safe subset of upstream response headers to w.
func (p *OAuthProxy) copyProxyHeaders(w http.ResponseWriter, resp *http.Response) {
	for _, h := range [...]string{"Content-Type", "Cache-Control", "Pragma"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// injectClientCredentials strips client_id/client_secret from a URL-
// encoded body and appends the pre-computed p.credentials, enabling
// confidential-client token exchange on behalf of a public MCP client.
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

// upstreamMeta holds the fields we need from an upstream IdP discovery document.
type upstreamMeta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// fetchUpstreamMeta tries each well-known URL and returns the first valid upstream metadata.
// Uses proxyHTTPClient for connection pooling.
func (p *OAuthProxy) fetchUpstreamMeta(urls []string) *upstreamMeta {
	for _, u := range urls {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
		if reqErr != nil {
			p.log.Warn("build upstream AS metadata request", "url", u, "err", reqErr)
			continue
		}
		resp, err := proxyHTTPClient.Do(req)
		if err != nil {
			p.log.Warn("fetch upstream AS metadata", "url", u, "err", err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		if closeErr := resp.Body.Close(); closeErr != nil {
			p.log.Debug("close upstream AS metadata response body", "err", closeErr)
		}
		if readErr != nil || resp.StatusCode != http.StatusOK {
			p.log.Warn("fetch upstream AS metadata", "url", u, "status", resp.StatusCode)
			continue
		}
		um := parseUpstreamMeta(body)
		if um == nil {
			continue
		}
		return um
	}
	return nil
}

// parseUpstreamMeta extracts issuer, authorization_endpoint, and
// token_endpoint from a raw JSON discovery document.
func parseUpstreamMeta(data []byte) *upstreamMeta {
	issuer, ok1 := findStringField(data, "issuer")
	authz, ok2 := findStringField(data, "authorization_endpoint")
	token, ok3 := findStringField(data, "token_endpoint")
	if !ok1 || !ok2 || !ok3 || issuer == "" || authz == "" || token == "" {
		return nil
	}
	return &upstreamMeta{
		Issuer:                issuer,
		AuthorizationEndpoint: authz,
		TokenEndpoint:         token,
	}
}

func findStringField(data []byte, key string) (string, bool) {
	raw, ok := jsonfast.FindField(data, key)
	if !ok {
		return "", false
	}
	return jsonfast.DecodeString(raw)
}

// fetchUpstream iterates p.authorizationServers in order, fetching the first
// valid upstream AS discovery document and storing the authorization and token
// endpoints for later use by the proxy handlers.
func (p *OAuthProxy) fetchUpstream() {
	for _, server := range p.authorizationServers {
		issuer := strings.TrimRight(server, "/")
		urls := []string{
			issuer + "/.well-known/openid-configuration",
			issuer + "/.well-known/oauth-authorization-server",
		}
		um := p.fetchUpstreamMeta(urls)
		if um == nil {
			p.log.Warn("upstream AS metadata unavailable, trying next", "server", server)
			continue
		}
		p.upstreamTokenEndpoint = um.TokenEndpoint
		p.upstreamAuthzEndpoint = um.AuthorizationEndpoint
		p.fetched = true
		p.log.Info("fetched upstream AS metadata",
			"issuer", um.Issuer,
			"authorization_endpoint", um.AuthorizationEndpoint,
			"token_endpoint", um.TokenEndpoint)
		return
	}
	p.log.Error("failed to fetch upstream AS metadata from any configured server")
}
