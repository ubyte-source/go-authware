package authware

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// ResourceConfig describes the protected resource in its metadata document.
type ResourceConfig struct {
	// Identifier (AUTH_OAUTH_RESOURCE) is the resource URL; empty means origin plus the
	// escaped request path after /.well-known/oauth-protected-resource, or for that bare
	// path the first endpoint unless it is /.
	Identifier string
	// Name (AUTH_OAUTH_RESOURCE_NAME) is the resource_name member.
	Name string
	// Documentation (AUTH_OAUTH_RESOURCE_DOCUMENTATION) is the
	// resource_documentation member.
	Documentation string
	// AuthorizationServers (AUTH_OAUTH_AUTHORIZATION_SERVERS, a list) defaults to
	// Issuer when it is a secure URL; a facade advertises the origin instead
	// and refuses an explicit list.
	AuthorizationServers []string
}

// inUse reports whether any setting of the resource metadata is present.
func (r *ResourceConfig) inUse() bool {
	return r.Identifier != "" || r.Name != "" || r.Documentation != "" || len(r.AuthorizationServers) > 0
}

// OAuthConfig configures ModeOAuth: JWT access tokens checked against an issuer.
type OAuthConfig struct {
	// Issuer (AUTH_OAUTH_ISSUER) must equal the token iss claim byte for byte.
	Issuer string
	// Audience (AUTH_OAUTH_AUDIENCE) must appear in the token aud claim.
	Audience string
	// RequiredScopes (AUTH_OAUTH_REQUIRED_SCOPES, a list) must all be granted
	// to every token.
	RequiredScopes []string
	// JWKSURL (AUTH_OAUTH_JWKS_URL) locates the signing keys; empty discovers
	// them from Issuer.
	JWKSURL string
	// HMACSecret (AUTH_OAUTH_HMAC_SECRET) verifies HS* tokens instead of a
	// JWKS; at least 32 bytes, and 48 or 64 to verify HS384 or HS512.
	HMACSecret secret.Value
	// ClockSkew (AUTH_OAUTH_CLOCK_SKEW) is tolerated on exp, nbf and iat;
	// default 30s.
	ClockSkew time.Duration
	// KeysCacheTTL (AUTH_OAUTH_KEYS_CACHE_TTL) is the lifetime of fetched
	// keys and issuer metadata; default 5m.
	KeysCacheTTL time.Duration
	// FetchTimeout (AUTH_OAUTH_FETCH_TIMEOUT) bounds JWKS, discovery and
	// facade fetches; default 10s.
	FetchTimeout time.Duration
	// PublicURL (AUTH_OAUTH_PUBLIC_URL) is the external origin; it wins over
	// the request.
	PublicURL string
	// Resource describes the protected resource in its metadata document.
	Resource ResourceConfig
	// Facade enables the authorization server facade.
	Facade FacadeConfig
	// RequireAccessTokenType (AUTH_OAUTH_REQUIRE_AT_JWT) accepts only tokens
	// typed at+jwt.
	RequireAccessTokenType bool
	// TrustForwardedProto (AUTH_OAUTH_TRUST_FORWARDED_PROTO) takes the scheme
	// from X-Forwarded-Proto.
	TrustForwardedProto bool
}

// inUse reports whether any OAuth setting is present.
func (o *OAuthConfig) inUse() bool {
	return o.verifierInUse() || o.PublicURL != "" || o.TrustForwardedProto || o.Resource.inUse() ||
		o.Facade.inUse()
}

// verifierInUse reports whether any setting of the token verification is
// present.
func (o *OAuthConfig) verifierInUse() bool {
	return o.Issuer != "" || o.Audience != "" || len(o.RequiredScopes) > 0 || o.JWKSURL != "" ||
		!o.HMACSecret.IsZero() || o.ClockSkew != 0 || o.KeysCacheTTL != 0 || o.FetchTimeout != 0 ||
		o.RequireAccessTokenType
}

// validate checks the claims, the key source, the durations and the metadata.
func (o *OAuthConfig) validate(p *problems.List) {
	if o.Issuer == "" {
		p.Addf("oauth issuer is required")
	}
	if o.Audience == "" {
		p.Addf("oauth audience is required")
	}
	o.validateKeys(p)
	p.Scopes(o.RequiredScopes)
	p.NonNegative("oauth clock skew", o.ClockSkew)
	p.NonNegative("oauth keys cache TTL", o.KeysCacheTTL)
	p.NonNegative("oauth fetch timeout", o.FetchTimeout)
	o.validateAdvertised(p)
	o.Facade.validate(p, o.RequiredScopes)
}

// validateKeys checks the verification key source and the URLs it fetches.
func (o *OAuthConfig) validateKeys(p *problems.List) {
	hmacMode := !o.HMACSecret.IsZero()
	switch {
	case hmacMode && o.JWKSURL != "":
		p.Addf("oauth HMAC secret and JWKS URL are exclusive")
	case hmacMode:
		longEnough(p, "oauth HMAC secret", o.HMACSecret)
	case o.JWKSURL != "":
		checkURL(p, "oauth JWKS URL", o.JWKSURL)
	}
	discovers := !hmacMode && o.JWKSURL == ""
	if o.Issuer != "" && (discovers || o.Facade.ClientID != "") {
		checkURL(p, "oauth issuer", o.Issuer)
	}
}

// validateAdvertised checks the URLs published in metadata documents.
func (o *OAuthConfig) validateAdvertised(p *problems.List) {
	if o.PublicURL != "" {
		checkOrigin(p, o.PublicURL)
	}
	if o.Resource.Identifier != "" {
		checkURL(p, "resource identifier", o.Resource.Identifier)
	}
	if o.Facade.ClientID != "" && len(o.Resource.AuthorizationServers) > 0 {
		p.Addf("authorization servers and facade client ID are exclusive")
	}
	for _, s := range o.Resource.AuthorizationServers {
		checkURL(p, "authorization server", s)
	}
}

// checkURL requires raw, the named URL, to pass the outbound URL policy.
func checkURL(p *problems.List, name, raw string) {
	if _, err := netguard.Check(raw, ErrInsecureURL); err != nil {
		p.Wrap(name, err)
	}
}

// checkOrigin requires raw, the public URL, to pass the outbound URL policy and
// to be an origin as a browser writes it: scheme://host[:port] in lower case,
// with a port only when it is not the default of the scheme.
func checkOrigin(p *problems.List, raw string) {
	u, err := netguard.Check(raw, ErrInsecureURL)
	switch {
	case err != nil:
		p.Wrap("public URL", err)
	case raw != u.Scheme+"://"+strings.ToLower(u.Host) || !canonicalPort(u):
		p.Addf("public URL must be an origin: scheme://host[:port], lower case, without the default port")
	}
}

// canonicalPort accepts a URL without a port, or with one from 1 to 65535 in
// canonical form other than the default of its scheme.
func canonicalPort(u *url.URL) bool {
	port := u.Port()
	if port == "" {
		return !strings.HasSuffix(u.Host, ":")
	}
	n, err := strconv.ParseUint(port, decimalBase, portBits)
	return err == nil && n != 0 && strconv.FormatUint(n, decimalBase) == port && port != netguard.DefaultPort(u.Scheme)
}

const (
	decimalBase = 10
	portBits    = 16
)

// keys returns the resolver of the keys that verify tokens: the HMAC secret,
// or the JWKS reached through the issuer that iss returns.
func (o *OAuthConfig) keys(iss func() *issuer) keyResolver {
	if !o.HMACSecret.IsZero() {
		return newHMACKey([]byte(o.HMACSecret.Reveal()))
	}
	return newKeySource(o, iss())
}

// oauthAuthenticator admits JWT access tokens signed by a key its resolver
// finds: one of the issuer's JWKS or the shared HMAC secret.
type oauthAuthenticator struct {
	resolver keyResolver

	scheme   credentialScheme
	expired  *authError
	unscoped *authError
	refusals []*authError

	policy   claimPolicy
	required []string

	buffers sync.Pool

	accessType bool
}

// newOAuthAuthenticator builds the verifier of oc, a prepared OAuthConfig,
// whose keys come from keys.
func newOAuthAuthenticator(oc *OAuthConfig, keys keyResolver) *oauthAuthenticator {
	return &oauthAuthenticator{
		resolver:   keys,
		scheme:     newCredentialScheme(schemeBearer),
		expired:    failure(ErrTokenExpired, "", nil),
		unscoped:   insufficientScope(oc.RequiredScopes),
		refusals:   invalidTokens(),
		policy:     claimPolicy{iss: oc.Issuer, audience: oc.Audience, skew: oc.ClockSkew},
		required:   oc.RequiredScopes,
		accessType: oc.RequireAccessTokenType,
	}
}

// invalidTokens returns the refusal of each token failure that is one fixed
// value, built once: the bare failures, then the details that wrap them.
func invalidTokens() []*authError {
	causes := []error{
		errTokenTooLarge, errCriticalHeader, errNoKey, errAmbiguousKey, errSignature, errIDToken, errIssuer,
		errAudience, errMissingExpiry, errNotYetValid, errIssuedInFuture, errSegments, errHeaderEncoding,
		errPayloadEncoding, errSignatureEncoding, errNoAlg, errModeAlg, errAccessType, errNoAudience,
		errAudienceType, errScopeType, errExpTime, errNbfTime, errIatTime, errHeaderShape, errAlgNotString,
		errKidNotString, errTypNotString, errClaimsShape, errIssNotString, errSubNotString, errClientIDNotString,
		errAzpNotString, errScopeNotString,
	}
	refusals := make([]*authError, len(causes))
	for i, cause := range causes {
		refusals[i] = failure(ErrInvalidCredentials, tokenText(cause), cause)
	}
	return refusals
}

func (a *oauthAuthenticator) authenticate(r *http.Request) (*Identity, *authError) {
	raw, e := authorizationCredential(r, a.scheme)
	if e != nil {
		return nil, e
	}
	id, err := a.validateToken(r.Context(), raw, time.Now())
	if err != nil {
		return nil, a.tokenFailure(err)
	}
	for _, s := range a.required {
		if !slices.Contains(id.scopes, s) {
			return nil, a.unscoped
		}
	}
	return id, nil
}

func (a *oauthAuthenticator) challengeScheme() string { return a.scheme.name }

func (*oauthAuthenticator) mode() Mode { return ModeOAuth }

// tokenFailure classifies a validation error: unavailable keys pass as they
// failed, an expired token is reported as such, and any other is an invalid
// token described by its tokenError, refused as built once when it is fixed.
func (a *oauthAuthenticator) tokenFailure(err error) *authError {
	if keys, ok := err.(interface{ authFailure() *authError }); ok {
		return keys.authFailure()
	}
	if errors.Is(err, ErrTokenExpired) {
		return a.expired
	}
	// errors.Is(cause, err) holds when err is cause or the failure cause wraps;
	// the bare failures come first, so err meets the refusal of its own value.
	for _, refusal := range a.refusals {
		if errors.Is(refusal.cause, err) {
			return refusal
		}
	}
	return failure(ErrInvalidCredentials, tokenText(err), err)
}

// tokenText returns the client-safe text of the tokenError that err wraps.
func tokenText(err error) string {
	for _, class := range [...]tokenError{
		errMalformedToken, errUnsupportedAlg, errTokenType, errMalformedClaims, errTokenTooLarge, errCriticalHeader,
		errNoKey, errAmbiguousKey, errSignature, errIDToken, errIssuer, errAudience, errMissingExpiry, errNotYetValid,
		errIssuedInFuture,
	} {
		if errors.Is(err, class) {
			return string(class)
		}
	}
	return "invalid token"
}

func (a *oauthAuthenticator) validateToken(ctx context.Context, raw string, now time.Time) (*Identity, error) {
	buf, ok := a.buffers.Get().(*[]byte)
	if !ok {
		buf = new([]byte)
	}
	defer a.buffers.Put(buf)
	tok, err := parseJWS(raw, buf)
	if err != nil {
		return nil, err
	}
	alg := tok.header.alg
	if !a.resolver.accepts(alg) {
		return nil, errModeAlg
	}
	if a.accessType && !tok.header.accessType {
		return nil, errAccessType
	}
	key, err := a.resolver.key(ctx, tok.header.kid, alg, now)
	if err != nil {
		return nil, err
	}
	err = verifySignature(key, alg, tok.signingInput, tok.signature, tok.scratch())
	if err != nil {
		return nil, err
	}
	c, err := a.policy.validateClaims(tok.claims, now)
	if err != nil {
		return nil, err
	}
	return &Identity{mode: ModeOAuth, subject: c.subject, scopes: c.scopes, claims: tok.claims}, nil
}
