package authware

import (
	"cmp"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

// Paths served by Mount and advertised in the metadata documents.
const (
	pathRoot             = "/"
	pathResourceMetadata = "/.well-known/oauth-protected-resource"
	pathServerMetadata   = "/.well-known/oauth-authorization-server"
	pathAuthorize        = "/authorize"
	pathRegister         = "/register"
	pathToken            = "/token"
)

// bearerMethodHeader is the only bearer token transport accepted.
const bearerMethodHeader = "header"

// headerOriginalURI carries the request target of an nginx auth_request
// subrequest.
const headerOriginalURI = "X-Original-Uri"

// authenticator checks the credentials of one mode.
type authenticator interface {
	authenticate(r *http.Request) (*Identity, *authError)
	// challengeScheme names the scheme a refusal challenges with, "" for a
	// mode that answers without a challenge.
	challengeScheme() string
	mode() Mode
}

// Gate authenticates requests in the configured mode and guards handlers. Only
// New builds a usable Gate, which is safe for concurrent use.
type Gate struct {
	auth       authenticator
	authServer *facade
	origin     originResolver

	realm    string
	resource ResourceConfig
}

// New builds a Gate from cfg, reporting every configuration problem at once, a nil
// cfg included; each wraps ErrInvalidConfig.
func New(cfg *Config) (*Gate, error) {
	c, err := cfg.prepare()
	if err != nil {
		return nil, err
	}
	g := &Gate{realm: c.Realm}
	switch c.Mode {
	case ModeNone:
		g.auth = newNoneAuthenticator()
	case ModeBearer:
		g.auth = newBearerAuthenticator(c.Bearer, c.Realm)
	case ModeAPIKey:
		g.auth = newAPIKeyAuthenticator(c.APIKey, c.Realm)
	case ModeOAuth:
		oc := &c.OAuth
		iss := sync.OnceValue(func() *issuer { return newIssuer(c) })
		g.auth = newOAuthAuthenticator(oc, oc.keys(iss))
		g.origin = originResolver{public: oc.PublicURL, trustProto: oc.TrustForwardedProto}
		g.resource = oc.Resource
		if oc.Facade.ClientID != "" {
			g.authServer = newFacade(oc, g.origin, iss())
		}
	case ModeMTLS:
		g.auth = newMTLSAuthenticator(c.MTLS)
	}
	return g, nil
}

// Mode returns the configured mode.
func (g *Gate) Mode() Mode { return g.auth.mode() }

// Authenticate checks the credentials of r. Errors match one of the
// ErrMissingCredentials, ErrInvalidCredentials, ErrTokenExpired,
// ErrInsufficientScope or ErrKeysUnavailable sentinels.
func (g *Gate) Authenticate(r *http.Request) (*Identity, error) {
	id, e := g.auth.authenticate(r)
	if e != nil {
		return nil, e
	}
	return id, nil
}

// Middleware passes authenticated requests to next, not nil, their Identity in the
// context; others get the challenge of the mode, resource_metadata in an OAuth one, 403
// in a mode without one, or 503 with Retry-After while the keys are unavailable.
func (g *Gate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, e := g.auth.authenticate(r)
		if e != nil {
			g.deny(w, r, e)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// Require admits requests whose Identity, stored by Middleware, passes
// every check. Without an identity it answers 401, or 403 in a mode without
// a challenge, and 403 on a failed check.
func (g *Gate) Require(checks ...Capability) func(http.Handler) http.Handler {
	checks = slices.Clone(checks)
	missing := g.refusal(failure(ErrMissingCredentials, "no identity", nil))
	denials := make([]*authError, len(checks))
	for i, c := range checks {
		denials[i] = g.refusal(c.denial())
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := IdentityFromContext(r.Context())
			if !ok {
				g.deny(w, r, missing)
				return
			}
			for i, c := range checks {
				if !c.Allow(id) {
					g.deny(w, r, denials[i])
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CheckHandler serves nginx auth_request, never cached: 200 with X-Auth-Subject,
// X-Auth-Method and any X-Auth-Scopes, or the challenge for the X-Original-URI path,
// 403 in a mode without one, or 503 with Retry-After while the keys are unavailable.
func (g *Gate) CheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The answer headers share one array; each slice is capped at its value.
		vals := [4]string{oauthwire.CacheNoStore}
		h := w.Header()
		h["Cache-Control"] = vals[:1:1]
		id, e := g.auth.authenticate(r)
		if e != nil {
			g.denyAt(w, r, e, originalPath)
			return
		}
		vals[1], vals[2] = sanitizeHeaderValue(id.subject), string(id.mode)
		h["X-Auth-Subject"], h["X-Auth-Method"] = vals[1:2:2], vals[2:3:3]
		if len(id.scopes) > 0 {
			vals[3] = sanitizeHeaderValue(strings.Join(id.scopes, " "))
			h["X-Auth-Scopes"] = vals[3:4:4]
		}
		w.WriteHeader(http.StatusOK)
	})
}

// Mount registers on mux, not nil, in ModeOAuth any facade routes and the metadata of
// each path an endpoint path pattern matches, sub-paths included, the bare path naming
// the first; it panics, as ServeMux.Handle does, if a pattern is invalid or conflicts.
func (g *Gate) Mount(mux *http.ServeMux, endpoints ...string) {
	oauth, ok := g.auth.(*oauthAuthenticator)
	if !ok {
		return
	}
	first := ""
	patterns := []string{pathResourceMetadata}
	for i, ep := range endpoints {
		ep = pathRoot + strings.TrimPrefix(ep, pathRoot)
		if i == 0 && ep != pathRoot {
			first = ep
		}
		patterns = append(patterns, pathResourceMetadata+ep, pathResourceMetadata+subPaths(ep))
	}
	slices.Sort(patterns)
	metadata := g.resourceMetadata(first, oauth.required)
	for _, p := range slices.Compact(patterns) {
		mux.Handle("GET "+p, metadata)
	}
	if f := g.authServer; f != nil {
		mux.HandleFunc("GET "+pathServerMetadata, f.serveMetadata)
		mux.HandleFunc("GET "+pathAuthorize, f.serveAuthorize)
		mux.HandleFunc("POST "+pathRegister, f.serveRegister)
		mux.HandleFunc("POST "+pathToken, f.serveToken)
	}
}

// subPaths returns a pattern matching the sub-paths of every path the endpoint pattern
// ep matches: its directory when ep ends in a slash or {$}, ep when it ends in a
// {name...} wildcard, else ep and a slash.
func subPaths(ep string) string {
	i := strings.LastIndexByte(ep, '/') + 1
	switch last := ep[i:]; {
	case last == "" || last == "{$}":
		return ep[:i]
	case strings.HasPrefix(last, "{") && strings.HasSuffix(last, "...}"):
		return ep
	}
	return ep + pathRoot
}

// resourceMetadata serves the metadata of the resource at the requested path
// after the metadata prefix, which scopes protect; the bare prefix describes first.
func (g *Gate) resourceMetadata(first string, scopes []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := g.origin.origin(r)
		resource := g.resource.Identifier
		if resource == "" {
			resource = origin + cmp.Or(describedPath(r.URL.EscapedPath()), first)
		}
		servers := g.resource.AuthorizationServers
		if g.authServer != nil {
			servers = []string{origin}
		}
		b := jsonfast.Acquire()
		defer jsonfast.Release(b)
		b.BeginObject()
		b.AddStringField("resource", resource)
		if len(servers) > 0 {
			b.AddStringArrayField("authorization_servers", servers)
		}
		if len(scopes) > 0 {
			b.AddStringArrayField("scopes_supported", scopes)
		}
		b.AddStringArrayField("bearer_methods_supported", []string{bearerMethodHeader})
		if g.resource.Name != "" {
			b.AddStringField("resource_name", g.resource.Name)
		}
		if g.resource.Documentation != "" {
			b.AddStringField("resource_documentation", g.resource.Documentation)
		}
		b.EndObject()
		g.origin.writeDocument(w, b.Bytes())
	})
}

// describedPath returns the escaped path p after its first two segments, the metadata
// prefix in any escaped form ServeMux matches.
func describedPath(p string) string {
	_, rest, _ := strings.Cut(strings.TrimPrefix(p, pathRoot), pathRoot)
	_, rest, found := strings.Cut(rest, pathRoot)
	if !found {
		return ""
	}
	return pathRoot + rest
}

// refusal returns e or, in a mode whose challenges no request changes, a copy
// of e with its challenge rendered once.
func (g *Gate) refusal(e *authError) *authError {
	if g.auth.mode() == ModeOAuth {
		return e
	}
	d := *e
	d.rendered = challengeHeader(g.auth.challengeScheme(), g.realm, e, "")
	return &d
}

// deny writes the challenge for e; OAuth challenges point at the metadata
// of the requested path.
func (g *Gate) deny(w http.ResponseWriter, r *http.Request, e *authError) {
	g.denyAt(w, r, e, requestPath)
}

// denyAt writes the challenge for e; OAuth challenges point at the metadata
// of the escaped path pathOf reads from r, the bare metadata path for "" or
// "/", read only for an OAuth challenge.
func (g *Gate) denyAt(w http.ResponseWriter, r *http.Request, e *authError, pathOf func(*http.Request) string) {
	metadataURL := ""
	if g.auth.mode() == ModeOAuth && e.challenged() {
		path := pathOf(r)
		if path == pathRoot {
			path = ""
		}
		metadataURL = g.origin.url(r, pathResourceMetadata, path)
	}
	writeChallenge(w, g.auth.challengeScheme(), g.realm, e, metadataURL)
}

// requestPath returns the escaped path of r.
func requestPath(r *http.Request) string { return r.URL.EscapedPath() }

// originalPath returns the escaped path of the request target nginx sends in
// X-Original-URI, or "" when there is none.
func originalPath(r *http.Request) string {
	raw := r.Header.Get(headerOriginalURI)
	if raw == "" {
		return ""
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || !strings.HasPrefix(u.Path, pathRoot) {
		return ""
	}
	return u.EscapedPath()
}
