package authware

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

// Parameters that only the facade names; the token request parameters it
// shares with the credential sources are oauthwire's.
const (
	paramRedirectURI         = "redirect_uri"
	paramCodeVerifier        = "code_verifier"
	paramResponseType        = "response_type"
	paramCodeChallenge       = "code_challenge"
	paramCodeChallengeMethod = "code_challenge_method"
	paramState               = "state"
	paramNonce               = "nonce"
	paramPrompt              = "prompt"
	paramLoginHint           = "login_hint"
	paramCode                = "code"
	paramRequest             = "request"
	paramRequestURI          = "request_uri"
)

// OpenID Connect scopes: an authorization request always asks upstream for
// openid and offline_access, and the facade relays all four unqualified.
const (
	scopeOpenID        = "openid"
	scopeOfflineAccess = "offline_access"
	scopeProfile       = "profile"
	scopeEmail         = "email"
)

var errInvalidParams = errors.New("invalid OAuth parameters")

// paramPolicy rewrites client parameters into the terms of the upstream
// client: its client_id, its qualified scopes and its resource.
type paramPolicy struct {
	clientID         string
	qualifier        string
	upstreamResource string
	defaults         []string
}

// newParamPolicy builds the policy of the facade settings f; defaults are
// the scopes the facade supports, requested when an authorization request
// names none.
func newParamPolicy(f *FacadeConfig, defaults []string) paramPolicy {
	qualifier := f.ScopePrefix
	if qualifier != "" && !strings.HasSuffix(qualifier, "/") {
		qualifier += "/"
	}
	return paramPolicy{
		clientID: f.ClientID, qualifier: qualifier, upstreamResource: f.UpstreamResource, defaults: defaults,
	}
}

// authorize returns the relayed parameters of an authorization request asking
// for openid, offline_access and the requested scopes or, naming none, the
// defaults; it reports false when a scope names another resource.
func (p *paramPolicy) authorize(vals url.Values) (url.Values, bool) {
	requested := scopeTokens(vals.Get(oauthwire.ParamScope))
	if len(requested) == 0 {
		requested = p.defaults
	}
	scope, ok := p.qualify(append([]string{scopeOpenID, scopeOfflineAccess}, requested...))
	if !ok {
		return nil, false
	}
	up := p.allowlisted(vals, paramResponseType, paramRedirectURI, paramState, paramCodeChallenge,
		paramCodeChallengeMethod, paramNonce, paramPrompt, paramLoginHint)
	up.Set(oauthwire.ParamScope, scope)
	return up, true
}

// token returns the upstream parameters of a token request: the relayed ones,
// pinned, with the scope in upstream terms when there is one. It reports false
// when a scope names another resource.
func (p *paramPolicy) token(vals url.Values) (url.Values, bool) {
	up := p.allowlisted(vals, oauthwire.ParamGrantType, paramCode, paramRedirectURI, paramCodeVerifier,
		oauthwire.ParamRefreshToken)
	if !vals.Has(oauthwire.ParamScope) {
		return up, true
	}
	scope, ok := p.qualify(scopeTokens(vals.Get(oauthwire.ParamScope)))
	if !ok {
		return nil, false
	}
	up.Set(oauthwire.ParamScope, scope)
	return up, true
}

// allowlisted returns the parameters of vals that names lists, with client_id
// pinned to the upstream client and resource to the upstream resource when
// there is one.
func (p *paramPolicy) allowlisted(vals url.Values, names ...string) url.Values {
	up := url.Values{oauthwire.ParamClientID: {p.clientID}}
	for _, name := range names {
		if v, ok := vals[name]; ok {
			up[name] = v
		}
	}
	if p.upstreamResource != "" {
		up.Set(oauthwire.ParamResource, p.upstreamResource)
	}
	return up
}

// qualify joins scopes without repeats, each in upstream terms; it reports
// false on the first scope the policy refuses.
func (p *paramPolicy) qualify(scopes []string) (string, bool) {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		q, ok := p.qualifyScope(s)
		if !ok {
			return "", false
		}
		if !slices.Contains(out, q) {
			out = append(out, q)
		}
	}
	return strings.Join(out, " "), true
}

// qualifyScope prefixes a bare API scope with the qualifier. OpenID Connect
// scopes pass unchanged, and so do URI scopes under a set qualifier; every
// other URI scope names another resource and, like a malformed one, is refused.
func (p *paramPolicy) qualifyScope(s string) (string, bool) {
	switch {
	case !syntax.IsScope(s):
		return "", false
	case oidcScope(s) || (p.qualifier != "" && strings.HasPrefix(s, p.qualifier)):
		return s, true
	case uriScope(s):
		return "", false
	}
	return p.qualifier + s, true
}

// uriScope reports whether s names its resource as a URI.
func uriScope(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "urn:")
}

// oidcScope reports whether s is a standard OpenID Connect scope.
func oidcScope(s string) bool {
	switch s {
	case scopeOpenID, scopeOfflineAccess, scopeProfile, scopeEmail:
		return true
	}
	return false
}

// parseParams decodes a query or form body in which every key appears once.
func parseParams(raw string) (url.Values, error) {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidParams, err)
	}
	for k, v := range vals {
		if len(v) > 1 {
			return nil, fmt.Errorf("%w: %q repeated", errInvalidParams, k)
		}
	}
	return vals, nil
}
