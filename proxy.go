package authware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
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

// OAuthProxy provides HTTP handlers for the MCP 2025-11-25 OAuth facade.
// It handles AS metadata discovery, Dynamic Client Registration (DCR) shim,
// authorization redirect, and token endpoint proxying. This bridges MCP
// clients that require public-client OAuth with upstream IdPs that don't
// natively support RFC 7591 DCR.
type OAuthProxy struct {
	log                   *slog.Logger
	clientID              string
	clientSecret          string   // upstream IdP client_secret; injected into token requests if non-empty
	requiredScopes        []string // from OAuthRequiredScopes, included in scopes_supported
	upstreamTokenEndpoint string
	upstreamAuthzEndpoint string
	authorizationServers  []string
	// scopesJSON is the pre-serialized "scopes_supported" JSON array,
	// computed once at construction to avoid per-request map+Builder allocations.
	scopesJSON []byte
	// credentials is the pre-built "client_id=...&client_secret=..." byte slice,
	// computed once at construction for use in injectClientCredentials.
	credentials []byte
	once        sync.Once
	fetched     bool // true after once.Do completes successfully
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
		p.once.Do(func() {
			p.fetchUpstream(p.authorizationServers[0])
		})
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

// RegisterHandler returns an http.HandlerFunc implementing a minimal
// RFC 7591 Dynamic Client Registration shim. It accepts any registration
// request and returns the pre-configured upstream IdP client_id.
func (p *OAuthProxy) RegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read and discard the request body (RFC 7591 client metadata).
		if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10)); err != nil {
			p.log.Debug("discard DCR request body", "err", err)
		}
		if err := r.Body.Close(); err != nil {
			p.log.Debug("close DCR request body", "err", err)
		}

		b := jsonfast.Acquire()
		b.BeginObject()
		b.AddStringField("client_id", p.clientID)
		b.AddInt64Field("client_id_issued_at", time.Now().Unix())
		b.AddStringField("token_endpoint_auth_method", "none")
		b.AddRawJSONField("grant_types", []byte(`["authorization_code","refresh_token"]`))
		b.AddRawJSONField("response_types", []byte(`["code"]`))
		b.AddRawJSONField("redirect_uris", []byte(`[]`))
		b.EndObject()
		data := b.Bytes()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write(data); err != nil {
			p.log.Debug("write DCR response", "err", err)
		}
		jsonfast.Release(b)
		p.log.Info("DCR shim: issued client_id", "client_id", p.clientID)
	}
}

// AuthorizeHandler returns an http.HandlerFunc that redirects the user
// to the upstream IdP's authorization endpoint, passing all query
// parameters through. Per the MCP specification (2025-11-25), clients
// use /authorize either from AS metadata or as the default fallback.
// This handler 302-redirects to the real upstream IdP authorize URL.
func (p *OAuthProxy) AuthorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.once.Do(func() {
			p.fetchUpstream(p.authorizationServers[0])
		})
		if p.upstreamAuthzEndpoint == "" {
			http.Error(w, "authorization endpoint not configured", http.StatusBadGateway)
			return
		}
		target := p.upstreamAuthzEndpoint
		if q := r.URL.RawQuery; q != "" {
			target += "?" + q
		}
		p.log.Debug("authorize redirect", "target", target)
		http.Redirect(w, r, target, http.StatusFound)
	}
}

// TokenHandler returns an http.HandlerFunc that proxies token exchange
// requests to the upstream IdP's token endpoint.
func (p *OAuthProxy) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.once.Do(func() {
			p.fetchUpstream(p.authorizationServers[0])
		})
		if p.upstreamTokenEndpoint == "" {
			http.Error(w, "token endpoint not configured", http.StatusBadGateway)
			return
		}
		body, ok := p.readTokenBody(w, r)
		if !ok {
			return
		}
		if p.clientSecret != "" {
			body = p.injectClientCredentials(body)
		}
		p.proxyToken(r.Context(), w, body)
	}
}

// readTokenBody reads and returns the request body up to 64 KiB.
// On read error it writes a 400 response and returns (nil, false).
func (p *OAuthProxy) readTokenBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
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

// injectClientCredentials adds client_id and client_secret to a URL-encoded
// form body for confidential-client token exchange. The MCP client (e.g.
// Claude) sends a public-client request without credentials; the proxy injects
// them before forwarding to the upstream IdP.
//
// Uses pure bytes operations (no string round-trip) and the pre-computed
// p.credentials field to avoid per-call string allocations.
func (p *OAuthProxy) injectClientCredentials(body []byte) []byte {
	// Split in-place: reuse the backing array of parts for the output slice.
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
// token_endpoint from a raw JSON discovery document using jsonfast,
// avoiding encoding/json.Unmarshal and its reflection overhead.
func parseUpstreamMeta(data []byte) *upstreamMeta {
	issuer, ok := jsonfast.FindField(data, "issuer")
	if !ok {
		return nil
	}
	authz, ok := jsonfast.FindField(data, "authorization_endpoint")
	if !ok {
		return nil
	}
	token, ok := jsonfast.FindField(data, "token_endpoint")
	if !ok {
		return nil
	}
	um := &upstreamMeta{
		Issuer:                unquote(issuer),
		AuthorizationEndpoint: unquote(authz),
		TokenEndpoint:         unquote(token),
	}
	if um.Issuer == "" || um.AuthorizationEndpoint == "" || um.TokenEndpoint == "" {
		return nil
	}
	return um
}

// unquote removes surrounding double quotes from a JSON string value.
func unquote(b []byte) string {
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		return string(b[1 : len(b)-1])
	}
	return string(b)
}

// fetchUpstream fetches the upstream IdP's discovery document and stores
// the authorization and token endpoints for later use by the proxy handlers.
func (p *OAuthProxy) fetchUpstream(issuer string) {
	issuer = strings.TrimRight(issuer, "/")
	urls := []string{
		issuer + "/.well-known/openid-configuration",
		issuer + "/.well-known/oauth-authorization-server",
	}

	um := p.fetchUpstreamMeta(urls)
	if um == nil {
		p.log.Error("failed to fetch upstream AS metadata from any well-known URL")
		return
	}

	p.upstreamTokenEndpoint = um.TokenEndpoint
	p.upstreamAuthzEndpoint = um.AuthorizationEndpoint
	p.fetched = true

	p.log.Info("fetched upstream AS metadata",
		"issuer", um.Issuer,
		"authorization_endpoint", um.AuthorizationEndpoint,
		"token_endpoint", um.TokenEndpoint)
}
