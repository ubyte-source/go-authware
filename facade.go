package authware

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/internal/reply"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// Protocol values the facade supports.
const (
	grantAuthorizationCode = "authorization_code"
	responseTypeCode       = "code"
	pkceMethodS256         = "S256"
	authMethodNone         = "none"
)

// OAuth error codes the facade answers with.
const (
	codeInvalidRequest        = "invalid_request"
	codeInvalidScope          = "invalid_scope"
	codeUnsupportedGrantType  = "unsupported_grant_type"
	codeUnsupportedResponse   = "unsupported_response_type"
	codeInvalidRedirectURI    = "invalid_redirect_uri"
	codeInvalidClientMetadata = "invalid_client_metadata"
)

// maxFacadeBodyBytes bounds a client request body of the facade.
const maxFacadeBodyBytes = 64 << 10

// Client-visible descriptions shared by the facade endpoints.
const (
	descMalformedParams = "malformed or repeated parameters"
	descUnreadableBody  = "unreadable or oversized body"
	descBadRedirectURI  = "redirect_uri must be an https or loopback http URL"
)

var errUpstreamEndpoint = errors.New("unusable upstream endpoint")

// FacadeConfig enables the authorization server facade when ClientID is set.
type FacadeConfig struct {
	// ClientID (AUTH_OAUTH_FACADE_CLIENT_ID) is the client registered upstream
	// on behalf of every client of the facade.
	ClientID string
	// ClientSecret (AUTH_OAUTH_FACADE_CLIENT_SECRET) authenticates ClientID
	// upstream; empty means a public client.
	ClientSecret secret.Value
	// ScopePrefix (AUTH_OAUTH_FACADE_SCOPE_PREFIX) qualifies scopes sent
	// upstream, such as api://app.
	ScopePrefix string
	// UpstreamResource (AUTH_OAUTH_FACADE_UPSTREAM_RESOURCE) is sent upstream
	// as the resource parameter; empty omits it.
	UpstreamResource string
}

// inUse reports whether any facade setting is present.
func (f *FacadeConfig) inUse() bool {
	return f.ClientID != "" || !f.ClientSecret.IsZero() || f.ScopePrefix != "" || f.UpstreamResource != ""
}

// validate checks the scope prefix and upstream resource, that any facade
// setting comes with a client ID and, with one, that the facade can request
// the required scopes upstream.
func (f *FacadeConfig) validate(p *problems.List, required []string) {
	if f.ScopePrefix != "" {
		p.ScopeToken("facade scope prefix", f.ScopePrefix)
	}
	if f.UpstreamResource != "" && !resourceURI(f.UpstreamResource) {
		p.Addf("facade upstream resource %q is not an absolute URI without a fragment", f.UpstreamResource)
	}
	if f.ClientID == "" {
		if f.inUse() {
			p.Addf("facade settings require a facade client ID")
		}
		return
	}
	policy := newParamPolicy(f, nil)
	for _, s := range required {
		if _, ok := policy.qualifyScope(s); !ok {
			p.Addf("required scope %q names a resource outside the facade scope prefix", s)
		}
	}
}

// resourceURI reports whether s is an absolute URI without a fragment or a
// space, as the resource parameter must be.
func resourceURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && !strings.ContainsAny(s, "# ")
}

// upstream holds the issuer endpoints the facade relays to. The query of the
// authorization endpoint is kept apart so its parameters win over the client's.
type upstream struct {
	authorizeURL   string
	authorizeQuery url.Values
	tokenURL       *url.URL
}

// newUpstream requires both endpoints of md to pass the outbound URL policy,
// and the authorization endpoint to have no fragment, splitting off its
// parameters.
func newUpstream(md *serverMetadata) (upstream, error) {
	token, err := netguard.Check(md.tokenEndpoint, ErrInsecureURL)
	if err != nil {
		return upstream{}, fmt.Errorf("%w: token endpoint: %w", errUpstreamEndpoint, err)
	}
	if _, err = netguard.Check(md.authorizationEndpoint, ErrInsecureURL); err != nil {
		return upstream{}, fmt.Errorf("%w: authorization endpoint: %w", errUpstreamEndpoint, err)
	}
	if strings.Contains(md.authorizationEndpoint, "#") {
		return upstream{}, fmt.Errorf("%w: authorization endpoint has a fragment", errUpstreamEndpoint)
	}
	base, rawQuery, _ := strings.Cut(md.authorizationEndpoint, "?")
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return upstream{}, fmt.Errorf("%w: authorization endpoint query: %w", errUpstreamEndpoint, err)
	}
	return upstream{authorizeURL: base, authorizeQuery: query, tokenURL: token}, nil
}

// derivedUpstream is what newUpstream returns for a metadata; up is shared read-only.
type derivedUpstream struct {
	up  upstream
	err error
}

// facade is an OAuth authorization server for public clients that relays
// to the issuer as one configured upstream client.
type facade struct {
	idp    *issuer
	origin originResolver

	secret secret.Value
	params paramPolicy
}

// newFacade returns the facade of oc, a prepared OAuthConfig with a facade
// client ID, relaying to iss, whose log receives the upstream failures.
func newFacade(oc *OAuthConfig, origin originResolver, iss *issuer) *facade {
	scopes := slices.Clone(oc.RequiredScopes)
	if !slices.Contains(scopes, scopeOfflineAccess) {
		scopes = append(scopes, scopeOfflineAccess)
	}
	return &facade{
		idp:    iss,
		origin: origin,
		secret: oc.Facade.ClientSecret,
		params: newParamPolicy(&oc.Facade, scopes),
	}
}

// endpointError is a facade failure answered as an OAuth JSON error.
type endpointError struct {
	code        string
	description string
	status      int
}

// badRequest reports a client request the facade refuses.
func badRequest(code, description string) *endpointError {
	return &endpointError{code: code, description: description, status: http.StatusBadRequest}
}

// unavailable reports an issuer the facade cannot reach or use.
func unavailable() *endpointError {
	return &endpointError{
		code:        oauthwire.CodeTemporarilyUnavailable,
		description: "authorization server unavailable",
		status:      http.StatusServiceUnavailable,
	}
}

// write answers with e as an OAuth JSON error; a 503 also carries Retry-After.
func (e *endpointError) write(w http.ResponseWriter) {
	if e.status == http.StatusServiceUnavailable {
		w.Header().Set(reply.RetryAfter, retryAfter())
	}
	oauthwire.WriteError(w, e.status, e.code, e.description)
}

// relayTarget rewrites vals with rewrite, the parameter policy of their
// endpoint, and returns the rewritten parameters and the upstream endpoints
// to relay them to.
func (f *facade) relayTarget(ctx context.Context, vals url.Values, rewrite func(url.Values) (url.Values, bool)) (
	url.Values, upstream, *endpointError,
) {
	params, ok := rewrite(vals)
	if !ok {
		return nil, upstream{}, badRequest(codeInvalidScope, "scope names another resource")
	}
	up, err := f.endpoints(ctx, time.Now())
	if err != nil {
		return nil, upstream{}, unavailable()
	}
	return params, up, nil
}

// endpoints returns the upstream endpoints the issuer metadata names at now,
// recorded with that metadata; of the callers that derive them from it, only the
// one that records them logs them when unusable.
func (f *facade) endpoints(ctx context.Context, now time.Time) (upstream, error) {
	md, err := f.idp.metadata.get(ctx, now)
	if err != nil {
		return upstream{}, err
	}
	if d := md.derived.Load(); d != nil {
		return d.up, d.err
	}
	return f.record(ctx, md)
}

// record derives the upstream endpoints of md and returns them, or why they are
// unusable; it records them with md, and logs them when unusable, only when md
// holds no record yet.
func (f *facade) record(ctx context.Context, md *serverMetadata) (upstream, error) {
	up, err := newUpstream(md)
	if md.derived.CompareAndSwap(nil, &derivedUpstream{up: up, err: err}) && err != nil {
		f.idp.log.LogAttrs(ctx, slog.LevelWarn, errPrefix+"upstream endpoints unusable", slog.Any("error", err))
	}
	return up, err
}

// serveMetadata serves the authorization server metadata of the facade,
// whose issuer is the public origin.
func (f *facade) serveMetadata(w http.ResponseWriter, r *http.Request) {
	origin := f.origin.origin(r)
	b := jsonfast.Acquire()
	defer jsonfast.Release(b)
	b.BeginObject()
	b.AddStringField(metaIssuer, origin)
	b.AddStringField(metaAuthorizationEndpoint, origin+pathAuthorize)
	b.AddStringField(metaTokenEndpoint, origin+pathToken)
	b.AddStringField("registration_endpoint", origin+pathRegister)
	b.AddStringArrayField("scopes_supported", f.params.defaults)
	b.AddStringArrayField("response_types_supported", []string{responseTypeCode})
	b.AddStringArrayField("grant_types_supported", []string{grantAuthorizationCode, oauthwire.GrantRefreshToken})
	b.AddStringArrayField("token_endpoint_auth_methods_supported", []string{authMethodNone})
	b.AddStringArrayField("code_challenge_methods_supported", []string{pkceMethodS256})
	b.EndObject()
	f.origin.writeDocument(w, b.Bytes())
}

// validRedirectURI accepts as the redirect URI of a facade client an https or
// loopback http URL without fragment.
func validRedirectURI(raw string) bool {
	_, err := netguard.Check(raw, ErrInsecureURL)
	return err == nil && !strings.Contains(raw, "#")
}
