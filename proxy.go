package authware

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

const proxyFetchTimeout = 10 * time.Second

// OAuthProxy provides HTTP handlers for the MCP 2025-03-26 OAuth facade.
// It handles AS metadata discovery, Dynamic Client Registration (DCR) shim,
// authorization redirect, and token endpoint proxying. This bridges MCP
// clients that require public-client OAuth with upstream IdPs that don't
// natively support RFC 7591 DCR.
type OAuthProxy struct {
	log                   *slog.Logger
	clientID              string
	upstreamTokenEndpoint string
	upstreamAuthzEndpoint string
	authorizationServers  []string
	once                  sync.Once
	fetched               bool // true after once.Do completes successfully
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
	return &OAuthProxy{
		clientID:             cfg.OAuthClientID,
		authorizationServers: append([]string(nil), cfg.OAuthAuthorizationServers...),
		log:                  log,
	}
}

// ASMetadataHandler returns an http.HandlerFunc that serves
// /.well-known/oauth-authorization-server per RFC 8414 and the MCP
// specification (2025-03-26). It fetches the upstream IdP's discovery
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
		b.AddRawJSONField("scopes_supported", []byte(`["openid","profile","email","offline_access"]`))
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
// parameters through. Per the MCP specification (2025-03-26), clients
// use /authorize either from AS metadata or as the default fallback.
// This handler 302-redirects to the real upstream IdP authorize URL.
func (p *OAuthProxy) AuthorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if p.upstreamTokenEndpoint == "" {
			http.Error(w, "token endpoint not configured", http.StatusBadGateway)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if closeErr := r.Body.Close(); closeErr != nil {
			p.log.Debug("close token request body", "err", closeErr)
		}
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		upstream, err := http.NewRequestWithContext(r.Context(),
			http.MethodPost, p.upstreamTokenEndpoint, strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, "upstream request failed", http.StatusBadGateway)
			return
		}
		upstream.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{Timeout: proxyFetchTimeout}
		resp, err := client.Do(upstream)
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

		for _, h := range []string{"Content-Type", "Cache-Control", "Pragma"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, io.LimitReader(resp.Body, 256<<10)); err != nil {
			p.log.Debug("token proxy: write response", "err", err)
		}

		p.log.Debug("token proxy: forwarded", "status", resp.StatusCode)
	}
}

// upstreamMeta holds the fields we need from an upstream IdP discovery document.
type upstreamMeta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// fetchUpstreamMeta tries each well-known URL and returns the first valid upstream metadata.
func (p *OAuthProxy) fetchUpstreamMeta(urls []string) *upstreamMeta {
	client := &http.Client{Timeout: proxyFetchTimeout}
	for _, u := range urls {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
		if reqErr != nil {
			p.log.Warn("build upstream AS metadata request", "url", u, "err", reqErr)
			continue
		}
		resp, err := client.Do(req)
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
		var um upstreamMeta
		if json.Unmarshal(body, &um) != nil || um.Issuer == "" || um.AuthorizationEndpoint == "" {
			continue
		}
		return &um
	}
	return nil
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
