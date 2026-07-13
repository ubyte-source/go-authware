package authware

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ubyte-source/go-jsonfast"
)

func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

// requireHTTPS rejects URLs that are neither https:// nor http:// to a
// loopback host. Plaintext delivery of signing material is an attacker-
// controlled substitution risk under MITM.
func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q", errInsecureURLScheme, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", errInsecureURLScheme, raw)
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

const (
	defaultJWKSCacheTTL  = 5 * time.Minute
	defaultJWTClockSkew  = 30 * time.Second
	jwtClockSkewSec      = int64(defaultJWTClockSkew / time.Second)
	jwksNegativeCacheTTL = 30 * time.Second
	jwksForcedRefreshMin = 30 * time.Second
	jwksMaxBodyBytes     = 1 << 20
	rsaMaxModulusBits    = 8192

	// maxJWTSize caps inbound token length to bound DoS via oversized tokens.
	maxJWTSize = 16384

	// maxCombinedBuf sizes the pooled scratch buffer for signature,
	// payload and digest decoded from a maximally-sized JWT.
	maxCombinedBuf = maxJWTSize*3/4 + sha512.Size + 4

	// minRSAExponent and minRSAModulusBits set the floor for accepted
	// RSA keys: smaller values are weak.
	minRSAExponent    = 65537
	minRSAModulusBits = 2048
)

const (
	algHS256 = "HS256"
	algHS384 = "HS384"
	algHS512 = "HS512"
	algRS256 = "RS256"
	algRS384 = "RS384"
	algRS512 = "RS512"
	algES256 = "ES256"
	algES384 = "ES384"
	algES512 = "ES512"
	algPS256 = "PS256"
	algPS384 = "PS384"
	algPS512 = "PS512"
)

const (
	jwkTypeRSA = "RSA"
	jwkTypeEC  = "EC"
	jwkCrvP256 = "P-256"
	jwkCrvP384 = "P-384"
	jwkCrvP521 = "P-521"
)

const (
	typJWT    = "JWT"
	typAtJWT  = "at+jwt"
	typAppJWT = "application/jwt"
	typAppAt  = "application/at+jwt"
)

var _ Authenticator = (*oauthAuthenticator)(nil)

var (
	errNoVerificationKey   = errors.New("no JWT verification key found")
	errOAuthIssuerRequired = errors.New("auth oauth mode requires an issuer")
	errUnsupportedJWTAlg   = errors.New("unsupported JWT algorithm")
	errUnsupportedKeyType  = errors.New("unsupported JWT public key type")
	errUnsupportedCurve    = errors.New("unsupported elliptic curve")
	errJWKSEndpoint        = errors.New("jwks endpoint error")
	errJWKSPayloadInvalid  = errors.New("invalid JWKS payload")
	errRSAExponentWeak     = errors.New("RSA public exponent below minimum (65537)")
	errRSAModulusWeak      = errors.New("RSA modulus below minimum (2048 bits)")
	errRSAModulusTooLarge  = errors.New("RSA modulus exceeds maximum")
	errInsecureURLScheme   = errors.New("URL scheme must be https")
)

var (
	errMalformedJWT       = unauthorisedError("malformed JWT")
	errInvalidJWTHeader   = unauthorisedError("invalid JWT header")
	errInvalidJWTSigEnc   = unauthorisedError("invalid JWT signature encoding")
	errInvalidJWTClaims   = unauthorisedError("invalid JWT claims")
	errMissingBearerToken = unauthorisedError("missing bearer token")
	errInvalidIssuer      = unauthorisedError("invalid token issuer")
	errInvalidAudience    = unauthorisedError("invalid token audience")
	errTokenExpired       = unauthorisedError("token expired")
	errTokenNotYetValid   = unauthorisedError("token not yet valid")
	errTokenFromFuture    = unauthorisedError("token issued in the future")
	errMissingExpClaim    = unauthorisedError("missing exp claim")
	errMalformedTimeClaim = unauthorisedError("malformed JWT time claim")

	errSignatureVerifyFailed = unauthorisedError("invalid JWT signature")
	errUnsupportedAlgAuth    = unauthorisedError("unsupported JWT algorithm")
	errUnsupportedKeyAuth    = unauthorisedError("unsupported JWT public key type")
	errNoKeyAuth             = unauthorisedError("no JWT verification key found")
	errInternalAuth          = unauthorisedError("internal authentication error")
	errCriticalHeader        = unauthorisedError("unsupported critical JWT header")
	errInvalidJWTType        = unauthorisedError("invalid JWT typ header")
)

// keysSnapshot is the immutable JWKS view published via atomic.Pointer.
type keysSnapshot struct {
	keys   map[string]jwkPublicKey
	expiry time.Time
}

// keysFetchCall lets concurrent callers share a single in-flight refresh.
type keysFetchCall struct {
	done chan struct{}
	snap *keysSnapshot
	err  error
}

type oauthAuthenticator struct {
	insufficientScopeErr  error
	keys                  atomic.Pointer[keysSnapshot]
	hmacPools             *[3]sync.Pool
	inflight              atomic.Pointer[keysFetchCall]
	jwksURLAtomic         atomic.Pointer[string]
	httpClient            *http.Client
	audience              string
	jwksURL               string
	resourceDocumentation string
	resourceName          string
	issuer                string
	realm                 string
	resource              string
	hmacSecret            []byte
	requiredScopes        []string
	authorizationServers  []string
	failedUntilNanos      atomic.Int64
	forcedAtNanos         atomic.Int64
	cacheTTL              time.Duration
	skewSec               int64
	refreshMu             sync.Mutex
}

var (
	jwtSHA256Pool = sync.Pool{New: func() any { return sha256.New() }}
	jwtSHA384Pool = sync.Pool{New: func() any { return sha512.New384() }}
	jwtSHA512Pool = sync.Pool{New: func() any { return sha512.New() }}
)

// decodeBuf wraps a byte buffer to avoid the interface boxing that a
// raw []byte would incur in a sync.Pool.
type decodeBuf struct {
	b []byte
}

var combinedPool = sync.Pool{New: func() any {
	return &decodeBuf{b: make([]byte, maxCombinedBuf)}
}}

type jwkPublicKey struct {
	key any
	alg string
}

type jwtHeader struct {
	Alg  string
	Kid  string
	Typ  string
	Crit bool
}

// extractMask records which standard claims have been seen so the
// scanner can short-circuit once every field is in hand.
type extractMask uint16

const (
	maskISS extractMask = 1 << iota
	maskAUD
	maskSUB
	maskClientID
	maskAZP
	maskScope
	maskSCP
	maskEXP
	maskNBF
	maskIAT

	maskAll = maskISS | maskAUD | maskSUB | maskClientID | maskAZP |
		maskScope | maskSCP | maskEXP | maskNBF | maskIAT
)

// jwtClaims holds raw byte slices produced by a single-pass JSON scan
// of the payload. Slices alias the decoded payload buffer.
type jwtClaims struct {
	iss      []byte
	aud      []byte
	sub      []byte
	clientID []byte
	azp      []byte
	scope    []byte
	scp      []byte
	exp      []byte
	nbf      []byte
	iat      []byte
}

// authorizationServersForMode returns a defensive copy of servers when
// running as a resource server; in proxy mode (clientID set) returns
// nil so the metadata document is filled from the request origin.
func authorizationServersForMode(servers []string, clientID string) []string {
	if clientID != "" {
		return nil
	}
	return append([]string(nil), servers...)
}

func newOAuthAuthenticator(cfg *Config, client *http.Client) (Authenticator, error) {
	if cfg.OAuthIssuer == "" {
		return nil, errOAuthIssuerRequired
	}
	servers := cfg.OAuthAuthorizationServers
	if len(servers) == 0 {
		servers = []string{cfg.OAuthIssuer}
	}
	if client == nil {
		if cfg.OAuthHTTPClient != nil {
			client = cfg.OAuthHTTPClient
		} else {
			client = &http.Client{Timeout: 5 * time.Second}
		}
	}
	cacheTTL := cfg.OAuthJWKSCacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultJWKSCacheTTL
	}
	skew := cfg.OAuthClockSkewTolerance
	if skew <= 0 {
		skew = defaultJWTClockSkew
	}
	secret := []byte(cfg.OAuthHMACSecret)
	o := &oauthAuthenticator{
		httpClient:            client,
		realm:                 cfg.Realm,
		issuer:                cfg.OAuthIssuer,
		audience:              cfg.OAuthAudience,
		jwksURL:               cfg.OAuthJWKSURL,
		resource:              cfg.OAuthResource,
		resourceDocumentation: cfg.OAuthResourceDocumentation,
		resourceName:          cfg.OAuthResourceName,
		hmacSecret:            secret,
		requiredScopes:        append([]string(nil), cfg.OAuthRequiredScopes...),
		authorizationServers:  authorizationServersForMode(servers, cfg.OAuthClientID),
		cacheTTL:              cacheTTL,
		skewSec:               int64(skew / time.Second),
	}
	if cfg.OAuthJWKSURL != "" {
		s := cfg.OAuthJWKSURL
		o.jwksURLAtomic.Store(&s)
	}
	if len(secret) > 0 {
		pools := &[3]sync.Pool{}
		pools[0].New = func() any { return hmac.New(sha256.New, secret) }
		pools[1].New = func() any { return hmac.New(sha512.New384, secret) }
		pools[2].New = func() any { return hmac.New(sha512.New, secret) }
		o.hmacPools = pools
	}
	if len(o.requiredScopes) > 0 {
		o.insufficientScopeErr = insufficientScopeError(o.requiredScopes)
	}
	return o, nil
}

func (a *oauthAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	v := r.Header["Authorization"]
	if len(v) == 0 {
		return nil, errMissingBearerToken
	}
	token, ok := parseAuthScheme(v[0], "bearer")
	if !ok {
		return nil, errMissingBearerToken
	}
	subject, scopes, claimsRaw, err := a.validateToken(r.Context(), token, time.Now())
	if err != nil {
		return nil, err
	}
	if !hasRequiredScopes(scopes, a.requiredScopes) {
		return nil, a.insufficientScopeErr
	}
	return &Identity{
		Subject:   subject,
		Method:    ModeOAuth,
		Scopes:    scopes,
		claimsRaw: claimsRaw,
	}, nil
}

func (a *oauthAuthenticator) Challenge(err error, resourceMetadataURL string) (status int, header, message string) {
	return challengeFromError(a.realm, err, resourceMetadataURL)
}

func (a *oauthAuthenticator) Metadata(resource string) *ProtectedResourceMetadata {
	if a.resource != "" {
		resource = a.resource
	}
	if resource == "" {
		return nil
	}
	return &ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   append([]string(nil), a.authorizationServers...),
		ScopesSupported:        append([]string(nil), a.requiredScopes...),
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  a.resourceDocumentation,
		ResourceName:           a.resourceName,
	}
}

// splitJWT splits a raw JWT into its three base64url-encoded parts plus
// the signing input (header.payload).
func splitJWT(data []byte) (header, payload, sig, signingInput []byte, ok bool) {
	dot1 := bytes.IndexByte(data, '.')
	if dot1 < 0 {
		return nil, nil, nil, nil, false
	}
	rest := data[dot1+1:]
	dot2rel := bytes.IndexByte(rest, '.')
	if dot2rel < 0 {
		return nil, nil, nil, nil, false
	}
	dot2 := dot1 + 1 + dot2rel
	if bytes.IndexByte(data[dot2+1:], '.') >= 0 {
		return nil, nil, nil, nil, false
	}
	return data[:dot1], data[dot1+1 : dot2], data[dot2+1:], data[:dot2], true
}

func (a *oauthAuthenticator) validateToken(
	ctx context.Context, token string, now time.Time,
) (subject string, scopes []string, claimsRaw string, err error) {
	if len(token) > maxJWTSize {
		return "", nil, "", errMalformedJWT
	}

	// Zero-allocation byte view of the immutable token; KeepAlive at
	// the end pins the string for the duration of the function.
	//nolint:gosec // immutable string alias; KeepAlive at end.
	data := unsafe.Slice(unsafe.StringData(token), len(token))

	headerBytes, payloadBytes, sigBytes, signingInput, ok := splitJWT(data)
	if !ok {
		return "", nil, "", errMalformedJWT
	}
	header, hdrErr := parseAndValidateHeader(headerBytes)
	if hdrErr != nil {
		return "", nil, "", hdrErr
	}
	subject, scopes, claimsRaw, err = a.verifyAndDecode(ctx, header, payloadBytes, sigBytes, signingInput, now.Unix())
	runtime.KeepAlive(token)
	return subject, scopes, claimsRaw, err
}

func parseAndValidateHeader(headerBytes []byte) (jwtHeader, error) {
	header, err := parseJWTHeader(headerBytes)
	if err != nil {
		return jwtHeader{}, errInvalidJWTHeader
	}
	if header.Crit {
		return jwtHeader{}, errCriticalHeader
	}
	if !validJWTType(header.Typ) {
		return jwtHeader{}, errInvalidJWTType
	}
	return header, nil
}

func (a *oauthAuthenticator) verifyAndDecode(
	ctx context.Context, header jwtHeader, payloadBytes, sigBytes, signingInput []byte, nowUnix int64,
) (subject string, scopes []string, claimsRaw string, err error) {
	sigDecLen := base64.RawURLEncoding.DecodedLen(len(sigBytes))
	payDecLen := base64.RawURLEncoding.DecodedLen(len(payloadBytes))
	needed := sigDecLen + payDecLen + sha512.Size

	db, ok := combinedPool.Get().(*decodeBuf)
	if !ok {
		return "", nil, "", errInternalAuth
	}
	defer combinedPool.Put(db)

	combined := db.b[:needed]
	sigBuf := combined[:sigDecLen]
	payBuf := combined[sigDecLen : sigDecLen+payDecLen]
	sumBuf := combined[sigDecLen+payDecLen:]

	sigLen, decErr := base64.RawURLEncoding.Decode(sigBuf, sigBytes)
	if decErr != nil {
		return "", nil, "", errInvalidJWTSigEnc
	}
	if sigErr := a.verifySignature(ctx, header.Alg, header.Kid, signingInput, sigBuf[:sigLen], sumBuf); sigErr != nil {
		return "", nil, "", sigErr
	}

	n, decErr := base64.RawURLEncoding.Decode(payBuf, payloadBytes)
	if decErr != nil {
		return "", nil, "", errInvalidJWTClaims
	}
	payload := payBuf[:n]
	parsed := extractClaims(payload)
	if vErr := a.validateClaimsFromParsed(&parsed, nowUnix); vErr != nil {
		return "", nil, "", vErr
	}
	return decodeAndDetach(subjectFromClaims(&parsed)), detachScopes(&parsed), string(payload), nil
}

func validJWTType(typ string) bool {
	if typ == "" {
		return true
	}
	switch typ {
	case typJWT, "jwt", typAtJWT, "AT+JWT", typAppJWT, typAppAt:
		return true
	}
	return false
}

// claimsAccumulator bundles the claims-under-construction with its
// presence mask so the extractor closure captures one pointer.
type claimsAccumulator struct {
	c    jwtClaims
	seen extractMask
}

func extractClaims(payload []byte) jwtClaims {
	var acc claimsAccumulator
	jsonfast.IterateFields(payload, func(key, value []byte) bool {
		extractClaimField(&acc, key, value)
		return acc.seen != maskAll
	})
	return acc.c
}

func extractClaimField(acc *claimsAccumulator, key, value []byte) {
	switch len(key) {
	case 5:
		extractClaim3(acc, key, value)
	case 7:
		if string(key) == `"scope"` {
			acc.c.scope = value
			acc.seen |= maskScope
		}
	case 11:
		if string(key) == `"client_id"` {
			acc.c.clientID = value
			acc.seen |= maskClientID
		}
	}
}

// extractClaim3 dispatches three-character JWT claim keys (5 bytes
// including surrounding quotes) by packing the body into a uint32.
func extractClaim3(acc *claimsAccumulator, key, value []byte) {
	packed := uint32(key[1])<<16 | uint32(key[2])<<8 | uint32(key[3])
	switch packed {
	case 'i'<<16 | 's'<<8 | 's':
		acc.c.iss = value
		acc.seen |= maskISS
	case 'i'<<16 | 'a'<<8 | 't':
		acc.c.iat = value
		acc.seen |= maskIAT
	case 'a'<<16 | 'u'<<8 | 'd':
		acc.c.aud = value
		acc.seen |= maskAUD
	case 'a'<<16 | 'z'<<8 | 'p':
		acc.c.azp = value
		acc.seen |= maskAZP
	case 's'<<16 | 'u'<<8 | 'b':
		acc.c.sub = value
		acc.seen |= maskSUB
	case 's'<<16 | 'c'<<8 | 'p':
		acc.c.scp = value
		acc.seen |= maskSCP
	case 'e'<<16 | 'x'<<8 | 'p':
		acc.c.exp = value
		acc.seen |= maskEXP
	case 'n'<<16 | 'b'<<8 | 'f':
		acc.c.nbf = value
		acc.seen |= maskNBF
	}
}

func (a *oauthAuthenticator) validateClaimsFromParsed(c *jwtClaims, nowUnix int64) error {
	if !equalQuotedBytes(c.iss, a.issuer) {
		return errInvalidIssuer
	}
	if a.audience != "" && !containsAudienceRaw(c.aud, a.audience) {
		return errInvalidAudience
	}
	if len(c.exp) == 0 {
		return errMissingExpClaim
	}
	exp, ok := decodeNumericTime(c.exp)
	if !ok {
		return errMalformedTimeClaim
	}
	if nowUnix > exp {
		return errTokenExpired
	}
	if err := a.validateTimeBound(c.nbf, nowUnix, errTokenNotYetValid); err != nil {
		return err
	}
	return a.validateTimeBound(c.iat, nowUnix, errTokenFromFuture)
}

// decodeNumericTime accepts either a JSON integer or fractional number.
func decodeNumericTime(raw []byte) (int64, bool) {
	if v, ok := jsonfast.DecodeInt64(raw); ok {
		return v, true
	}
	if f, ok := jsonfast.DecodeFloat64(raw); ok {
		return int64(f), true
	}
	return 0, false
}

func (a *oauthAuthenticator) validateTimeBound(raw []byte, nowUnix int64, errVal error) error {
	return validateTimeBound(raw, nowUnix, a.skewSec, errVal)
}

// validateTimeBound rejects time claims that are present but malformed
// or further in the future than skewSec allows.
func validateTimeBound(raw []byte, nowUnix, skewSec int64, errVal error) error {
	if len(raw) == 0 {
		return nil
	}
	ts, ok := decodeNumericTime(raw)
	if !ok {
		return errMalformedTimeClaim
	}
	if nowUnix < ts-skewSec {
		return errVal
	}
	return nil
}

// claimStringView returns a zero-allocation string view aliasing the
// pooled decode buffer. Use only for fields that need not be JSON
// unescaped; callers retaining the value MUST detach via decodeAndDetach.
//
//nolint:gosec // zero-alloc view into pooled buffer; detached by callers.
func claimStringView(raw []byte) string {
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return ""
	}
	return unsafe.String(&raw[1], len(raw)-2)
}

// decodeAndDetach returns a JSON-unescaped, detached copy of s when
// escapes are present; otherwise a plain clone of the view.
func decodeAndDetach(s string) string {
	if s == "" {
		return ""
	}
	if strings.IndexByte(s, '\\') < 0 {
		return strings.Clone(s)
	}
	if dec, ok := jsonfast.DecodeString([]byte(`"` + s + `"`)); ok {
		return dec
	}
	return strings.Clone(s)
}

// subjectFromClaims tries "sub", then "client_id", then "azp".
func subjectFromClaims(c *jwtClaims) string {
	if s := claimStringView(c.sub); s != "" {
		return s
	}
	if s := claimStringView(c.clientID); s != "" {
		return s
	}
	return claimStringView(c.azp)
}

// detachScopes resolves the scope set from "scope" (string),
// "scp" (string) or "scp" (array), returning detached storage.
func detachScopes(c *jwtClaims) []string {
	if len(c.scope) >= 2 && c.scope[0] == '"' {
		return decodeScopeString(c.scope)
	}
	if len(c.scp) >= 2 && c.scp[0] == '"' {
		return decodeScopeString(c.scp)
	}
	return scopesFromSCPArray(c.scp)
}

// decodeScopeString unquotes a JSON string and splits it on spaces.
// The owned string serves as the single backing allocation for every
// returned substring. Fast path: when no JSON escapes are present we
// skip jsonfast.DecodeString entirely.
func decodeScopeString(raw []byte) []string {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil
	}
	inner := raw[1 : len(raw)-1]
	if bytes.IndexByte(inner, '\\') < 0 {
		if len(inner) == 0 {
			return nil
		}
		return splitScopesShared(string(inner))
	}
	decoded, ok := jsonfast.DecodeString(raw)
	if !ok || decoded == "" {
		return nil
	}
	return splitScopesShared(decoded)
}

// splitScopesShared splits s on spaces; returned substrings share s.
// One allocation: the slice header.
func splitScopesShared(s string) []string {
	if s == "" {
		return nil
	}
	count := 1
	for i := range len(s) {
		if s[i] == ' ' {
			count++
		}
	}
	out := make([]string, 0, count)
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func scopesFromSCPArray(raw []byte) []string {
	if len(raw) < 2 || raw[0] != '[' {
		return nil
	}
	var scopes []string
	jsonfast.IterateStringArray(raw, func(val string) bool {
		// val aliases the pooled decode buffer; clone before retaining.
		if v := strings.TrimSpace(val); v != "" {
			scopes = append(scopes, strings.Clone(v))
		}
		return true
	})
	return scopes
}

// decodeClaimValue maps a raw JSON value to a Go value: string, int64,
// float64, bool, nil, or the raw JSON text for objects/arrays.
func decodeClaimValue(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	switch raw[0] {
	case '"':
		s, ok := jsonfast.DecodeString(raw)
		if !ok {
			return string(raw)
		}
		return s
	case 't', 'f':
		v, ok := jsonfast.DecodeBool(raw)
		if !ok {
			return string(raw)
		}
		return v
	case 'n':
		return nil
	}
	if n, ok := jsonfast.DecodeInt64(raw); ok {
		return n
	}
	if f, ok := jsonfast.DecodeFloat64(raw); ok {
		return f
	}
	return string(raw)
}

func (a *oauthAuthenticator) verifySignature(
	ctx context.Context, alg, kid string, signingInput, signature, sumBuf []byte,
) error {
	if len(a.hmacSecret) > 0 {
		return a.verifyHMACSignature(alg, signingInput, signature, sumBuf)
	}
	return a.verifyJWKS(ctx, alg, kid, signingInput, signature, sumBuf)
}

func (a *oauthAuthenticator) verifyHMACSignature(alg string, signingInput, signature, sumBuf []byte) error {
	var idx int
	switch alg {
	case algHS256:
		idx = 0
	case algHS384:
		idx = 1
	case algHS512:
		idx = 2
	default:
		return errUnsupportedAlgAuth
	}

	pool := &a.hmacPools[idx]
	mac, ok := pool.Get().(hash.Hash)
	if !ok {
		return errInternalAuth
	}
	mac.Reset()
	if _, err := mac.Write(signingInput); err != nil {
		pool.Put(mac)
		return errInternalAuth
	}
	sum := mac.Sum(sumBuf[:0])
	pool.Put(mac)

	if !hmac.Equal(signature, sum) {
		return errSignatureVerifyFailed
	}
	return nil
}

func (a *oauthAuthenticator) verifyJWKS(
	ctx context.Context, alg, kid string, signingInput, signature, hashBuf []byte,
) error {
	key, err := a.lookupKey(ctx, kid, alg)
	if err != nil {
		return errNoKeyAuth
	}
	hashAlg, digest, err := hashJWT(alg, signingInput, hashBuf)
	if err != nil {
		return errUnsupportedAlgAuth
	}
	switch publicKey := key.(type) {
	case *rsa.PublicKey:
		if err := verifyRSASignature(alg, publicKey, hashAlg, digest, signature); err != nil {
			return errSignatureVerifyFailed
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsaCurveMatchesAlg(publicKey.Curve, alg) {
			return errSignatureVerifyFailed
		}
		if !ecdsa.VerifyASN1(publicKey, digest, signature) {
			return errSignatureVerifyFailed
		}
		return nil
	default:
		return errUnsupportedKeyAuth
	}
}

// ecdsaCurveMatchesAlg pins each ES* algorithm to its mandated curve.
func ecdsaCurveMatchesAlg(curve elliptic.Curve, alg string) bool {
	switch alg {
	case algES256:
		return curve == elliptic.P256()
	case algES384:
		return curve == elliptic.P384()
	case algES512:
		return curve == elliptic.P521()
	}
	return false
}

// jwtHashPool returns the hash function and pooled hasher for alg.
func jwtHashPool(alg string) (crypto.Hash, *sync.Pool) {
	switch alg {
	case algRS256, algPS256, algES256:
		return crypto.SHA256, &jwtSHA256Pool
	case algRS384, algPS384, algES384:
		return crypto.SHA384, &jwtSHA384Pool
	case algRS512, algPS512, algES512:
		return crypto.SHA512, &jwtSHA512Pool
	}
	return 0, nil
}

func hashJWT(alg string, signingInput, buf []byte) (crypto.Hash, []byte, error) {
	hashAlg, pool := jwtHashPool(alg)
	if pool == nil {
		return 0, nil, fmt.Errorf("%w: %q", errUnsupportedJWTAlg, alg)
	}
	h, ok := pool.Get().(hash.Hash)
	if !ok {
		return 0, nil, errInternalAuth
	}
	h.Reset()
	if _, err := h.Write(signingInput); err != nil {
		pool.Put(h)
		return 0, nil, err
	}
	digest := h.Sum(buf[:0])
	pool.Put(h)
	return hashAlg, digest, nil
}

func verifyRSASignature(alg string, key *rsa.PublicKey, hashAlg crypto.Hash, digest, signature []byte) error {
	if alg[0] == 'P' {
		return rsa.VerifyPSS(key, hashAlg, digest, signature, nil)
	}
	return rsa.VerifyPKCS1v15(key, hashAlg, digest, signature)
}

func (a *oauthAuthenticator) lookupKey(ctx context.Context, kid, alg string) (any, error) {
	keys, err := a.currentKeys(ctx)
	if err != nil {
		return nil, err
	}
	if key, ok := findKey(keys, kid, alg); ok {
		return key, nil
	}
	keys, err = a.forceRefreshKeys(ctx)
	if err != nil {
		return nil, err
	}
	if key, ok := findKey(keys, kid, alg); ok {
		return key, nil
	}
	return nil, errNoVerificationKey
}

// findKey resolves the verification key. With kid set, only the keyed
// entry is considered: falling back to other keys would let an attacker
// pin a kid the IdP no longer publishes while signing with the current
// key. With kid empty, the first matching alg wins.
func findKey(keys map[string]jwkPublicKey, kid, alg string) (any, bool) {
	if kid != "" {
		key, ok := keys[kid]
		if !ok {
			return nil, false
		}
		if key.alg != "" && key.alg != alg {
			return nil, false
		}
		return key.key, true
	}
	for _, key := range keys {
		if key.alg == "" || key.alg == alg {
			return key.key, true
		}
	}
	return nil, false
}

// seedKeysForTest pre-populates the JWKS cache. Test-only seam.
func (a *oauthAuthenticator) seedKeysForTest(keys map[string]jwkPublicKey) {
	a.keys.Store(&keysSnapshot{keys: keys, expiry: time.Now().Add(5 * time.Minute)})
}

func (a *oauthAuthenticator) currentKeys(ctx context.Context) (map[string]jwkPublicKey, error) {
	if snap := a.keys.Load(); snap != nil && time.Now().Before(snap.expiry) {
		return snap.keys, nil
	}
	return a.refreshKeys(ctx)
}

// refreshKeys returns the cached snapshot while fresh, else fetches.
func (a *oauthAuthenticator) refreshKeys(ctx context.Context) (map[string]jwkPublicKey, error) {
	if snap := a.keys.Load(); snap != nil && time.Now().Before(snap.expiry) {
		return snap.keys, nil
	}
	return a.fetchKeys(ctx)
}

// forceRefreshKeys refetches even when the snapshot is fresh, at most
// once per jwksForcedRefreshMin so unknown kids cannot hammer the endpoint.
func (a *oauthAuthenticator) forceRefreshKeys(ctx context.Context) (map[string]jwkPublicKey, error) {
	now := time.Now().UnixNano()
	last := a.forcedAtNanos.Load()
	if now-last < int64(jwksForcedRefreshMin) || !a.forcedAtNanos.CompareAndSwap(last, now) {
		if snap := a.keys.Load(); snap != nil {
			return snap.keys, nil
		}
		return nil, errJWKSEndpoint
	}
	return a.fetchKeys(ctx)
}

// fetchKeys joins or starts the single-flight fetch, honoring the
// negative-cache backoff.
func (a *oauthAuthenticator) fetchKeys(ctx context.Context) (map[string]jwkPublicKey, error) {
	if backoff := a.failedUntilNanos.Load(); backoff > 0 && time.Now().UnixNano() < backoff {
		if snap := a.keys.Load(); snap != nil {
			return snap.keys, nil
		}
		return nil, errJWKSEndpoint
	}

	call := a.beginKeysFetch(ctx)
	select {
	case <-call.done:
		if call.err != nil {
			return nil, call.err
		}
		return call.snap.keys, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (a *oauthAuthenticator) beginKeysFetch(ctx context.Context) *keysFetchCall {
	if call := a.inflight.Load(); call != nil {
		return call
	}
	a.refreshMu.Lock()
	if call := a.inflight.Load(); call != nil {
		a.refreshMu.Unlock()
		return call
	}
	call := &keysFetchCall{done: make(chan struct{})}
	a.inflight.Store(call)
	a.refreshMu.Unlock()

	go a.runKeysFetch(ctx, call)
	return call
}

// runKeysFetch performs the fetch shared by every waiter: detached from
// the elected caller's cancellation, bounded by its own timeout.
func (a *oauthAuthenticator) runKeysFetch(ctx context.Context, call *keysFetchCall) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.httpClientTimeout())
	defer cancel()

	snap, err := a.fetchKeysSnapshot(ctx)
	if err == nil {
		a.keys.Store(snap)
		a.failedUntilNanos.Store(0)
		call.snap = snap
	} else {
		a.failedUntilNanos.Store(time.Now().Add(jwksNegativeCacheTTL).UnixNano())
		call.err = err
	}
	a.refreshMu.Lock()
	a.inflight.Store(nil)
	a.refreshMu.Unlock()
	close(call.done)
}

func (a *oauthAuthenticator) httpClientTimeout() time.Duration {
	if a.httpClient != nil && a.httpClient.Timeout > 0 {
		return a.httpClient.Timeout
	}
	return 5 * time.Second
}

func (a *oauthAuthenticator) fetchKeysSnapshot(ctx context.Context) (*keysSnapshot, error) {
	jwksURL, err := a.resolveJWKSURL(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := a.fetchAndParseJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	return &keysSnapshot{keys: keys, expiry: time.Now().Add(a.cacheTTL)}, nil
}

func (a *oauthAuthenticator) resolveJWKSURL(ctx context.Context) (string, error) {
	if p := a.jwksURLAtomic.Load(); p != nil && *p != "" {
		return *p, nil
	}
	oidc, err := discoverOIDC(ctx, a.httpClient, a.issuer)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery: %w", err)
	}
	jwksURL := oidc.JWKSURI
	a.jwksURLAtomic.Store(&jwksURL)
	return jwksURL, nil
}

// fetchAndParseJWKS fetches the JWKS endpoint over https and parses
// the document. Plaintext delivery of public keys is refused.
func (a *oauthAuthenticator) fetchAndParseJWKS(
	ctx context.Context, jwksURL string,
) (keys map[string]jwkPublicKey, err error) {
	if schemeErr := requireHTTPS(jwksURL); schemeErr != nil {
		return nil, fmt.Errorf("JWKS endpoint: %w", schemeErr)
	}

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, http.NoBody)
	if reqErr != nil {
		return nil, reqErr
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", errJWKSEndpoint, resp.StatusCode)
	}
	body, readErr := readAllLimited(resp.Body, jwksMaxBodyBytes)
	if readErr != nil {
		return nil, readErr
	}
	return parseJWKSBytes(body)
}

func parseJWKSBytes(data []byte) (map[string]jwkPublicKey, error) {
	keysRaw, ok := jsonfast.FindField(data, "keys")
	if !ok {
		return nil, errJWKSPayloadInvalid
	}
	keys := make(map[string]jwkPublicKey, 4)
	idx := 0
	var iterErr error
	jsonfast.IterateArray(keysRaw, func(elem []byte) bool {
		key, name, alg, err := parseJWKObject(elem, idx)
		if err != nil {
			iterErr = err
			return false
		}
		keys[name] = jwkPublicKey{key: key, alg: alg}
		idx++
		return true
	})
	if iterErr != nil {
		return nil, iterErr
	}
	return keys, nil
}

type jwkRaw struct {
	kty, kid, alg, crv, n, e, x, y string
}

func parseJWKObject(data []byte, idx int) (key any, name, alg string, err error) {
	r := decodeJWKFields(data)
	key, err = jwkToKey(&r)
	if err != nil {
		return nil, "", "", err
	}
	kid := r.kid
	if kid == "" {
		kid = "key-" + strconv.Itoa(idx)
	}
	return key, kid, r.alg, nil
}

func decodeJWKFields(data []byte) jwkRaw {
	var r jwkRaw
	jsonfast.IterateFields(data, func(rawKey, value []byte) bool {
		decoded, _ := jsonfast.DecodeString(value)
		assignJWKField(&r, string(rawKey), decoded)
		return true
	})
	return r
}

func assignJWKField(r *jwkRaw, field, value string) {
	switch field {
	case `"kty"`:
		r.kty = value
	case `"kid"`:
		r.kid = value
	case `"alg"`:
		r.alg = value
	case `"crv"`:
		r.crv = value
	case `"n"`:
		r.n = value
	case `"e"`:
		r.e = value
	case `"x"`:
		r.x = value
	case `"y"`:
		r.y = value
	}
}

func jwkToKey(r *jwkRaw) (any, error) {
	switch r.kty {
	case jwkTypeRSA:
		return parseRSAKey(r.n, r.e)
	case jwkTypeEC:
		return parseECKey(r.crv, r.x, r.y)
	}
	return nil, fmt.Errorf("%w: %q", errUnsupportedKeyType, r.kty)
}

func parseRSAKey(nVal, eVal string) (*rsa.PublicKey, error) {
	n, err := decodeBase64Int(nVal)
	if err != nil {
		return nil, err
	}
	e, err := decodeBase64Int(eVal)
	if err != nil {
		return nil, err
	}
	exp := e.Int64()
	if exp < minRSAExponent {
		return nil, errRSAExponentWeak
	}
	if n.BitLen() < minRSAModulusBits {
		return nil, errRSAModulusWeak
	}
	if n.BitLen() > rsaMaxModulusBits {
		return nil, errRSAModulusTooLarge
	}
	return &rsa.PublicKey{N: n, E: int(exp)}, nil
}

func parseECKey(crv, xVal, yVal string) (*ecdsa.PublicKey, error) {
	curve, err := ellipticCurve(crv)
	if err != nil {
		return nil, err
	}
	x, err := decodeBase64Int(xVal)
	if err != nil {
		return nil, err
	}
	y, err := decodeBase64Int(yVal)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func ellipticCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case jwkCrvP256:
		return elliptic.P256(), nil
	case jwkCrvP384:
		return elliptic.P384(), nil
	case jwkCrvP521:
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("%w: %q", errUnsupportedCurve, crv)
}

func decodeBase64Int(value string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(decoded), nil
}

// parseJWTHeader base64url-decodes the JOSE header and lifts alg / kid /
// typ / crit. Headers up to 128 bytes after decoding stay on the stack.
func parseJWTHeader(encoded []byte) (jwtHeader, error) {
	decLen := base64.RawURLEncoding.DecodedLen(len(encoded))
	if decLen <= 128 {
		var buf [128]byte
		n, err := base64.RawURLEncoding.Decode(buf[:], encoded)
		if err != nil {
			return jwtHeader{}, err
		}
		return parseHeaderJSON(buf[:n])
	}
	dst := make([]byte, decLen)
	n, err := base64.RawURLEncoding.Decode(dst, encoded)
	if err != nil {
		return jwtHeader{}, err
	}
	return parseHeaderJSON(dst[:n])
}

func parseHeaderJSON(data []byte) (jwtHeader, error) {
	var h jwtHeader
	if raw, ok := jsonfast.FindField(data, "alg"); ok {
		h.Alg = decodeAlg(raw)
	}
	if raw, ok := jsonfast.FindField(data, "kid"); ok {
		h.Kid, _ = jsonfast.DecodeString(raw)
	}
	if raw, ok := jsonfast.FindField(data, "typ"); ok {
		h.Typ = decodeTyp(raw)
	}
	if raw, ok := jsonfast.FindField(data, "crit"); ok {
		h.Crit = critIsNonEmpty(raw)
	}
	if h.Alg == "" {
		return jwtHeader{}, errInvalidJWTHeader
	}
	return h, nil
}

// critIsNonEmpty reports whether raw is a JSON array with at least one
// element; any non-empty crit is rejected because no JOSE header
// extensions are understood.
func critIsNonEmpty(raw []byte) bool {
	if len(raw) < 2 || raw[0] != '[' {
		return false
	}
	for i := 1; i < len(raw)-1; i++ {
		c := raw[i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return c != ']'
		}
	}
	return false
}

// decodeAlg returns one of the twelve interned algorithm constants when
// raw is a quoted standard JWS alg, falling back to a generic decode.
func decodeAlg(raw []byte) string {
	if len(raw) == 7 && raw[0] == '"' && raw[6] == '"' {
		if known := matchKnownAlg(raw[1:6]); known != "" {
			return known
		}
	}
	s, _ := jsonfast.DecodeString(raw)
	return s
}

func matchKnownAlg(v []byte) string {
	_ = v[4]
	switch {
	case v[0] == 'H' && v[1] == 'S':
		return matchAlgVariant(v[4], algHS256, algHS384, algHS512)
	case v[0] == 'R' && v[1] == 'S':
		return matchAlgVariant(v[4], algRS256, algRS384, algRS512)
	case v[0] == 'E' && v[1] == 'S':
		return matchAlgVariant(v[4], algES256, algES384, algES512)
	case v[0] == 'P' && v[1] == 'S':
		return matchAlgVariant(v[4], algPS256, algPS384, algPS512)
	}
	return ""
}

func matchAlgVariant(last byte, s256, s384, s512 string) string {
	switch last {
	case '6':
		return s256
	case '4':
		return s384
	case '2':
		return s512
	}
	return ""
}

// decodeTyp interns the four standard typ values; any other value is
// decoded normally.
func decodeTyp(raw []byte) string {
	if known := internKnownTyp(raw); known != "" {
		return known
	}
	s, _ := jsonfast.DecodeString(raw)
	return s
}

var knownTypes = [...]struct {
	value  string
	rawLen int
}{
	{value: typJWT, rawLen: 5},
	{value: typAtJWT, rawLen: 8},
	{value: typAppJWT, rawLen: 17},
	{value: typAppAt, rawLen: 20},
}

func internKnownTyp(raw []byte) string {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return ""
	}
	body := raw[1 : len(raw)-1]
	for _, kt := range knownTypes {
		if len(raw) == kt.rawLen && asciiEqualFoldRaw(body, kt.value) {
			return kt.value
		}
	}
	return ""
}

func asciiEqualFoldRaw(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := range b {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// equalQuotedBytes compares a raw JSON quoted value against an unquoted
// string, decoding escapes only when present. Not constant time.
func equalQuotedBytes(raw []byte, s string) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	body := raw[1 : len(raw)-1]
	if bytes.IndexByte(body, '\\') < 0 {
		return string(body) == s
	}
	dec, ok := jsonfast.DecodeString(raw)
	return ok && dec == s
}

// quotedBodyEquals compares a JSON string body (escapes intact) against want.
func quotedBodyEquals(body, want string) bool {
	if strings.IndexByte(body, '\\') < 0 {
		return body == want
	}
	dec, ok := jsonfast.DecodeString([]byte(`"` + body + `"`))
	return ok && dec == want
}

// containsAudienceRaw checks audience against a quoted string or a
// JSON array of strings.
func containsAudienceRaw(raw []byte, expected string) bool {
	if len(raw) < 2 {
		return false
	}
	if raw[0] == '"' {
		return equalQuotedBytes(raw, expected)
	}
	if raw[0] == '[' {
		found := false
		jsonfast.IterateStringArray(raw, func(val string) bool {
			if quotedBodyEquals(val, expected) {
				found = true
				return false
			}
			return true
		})
		return found
	}
	return false
}

// hasRequiredScopes reports whether every entry in required appears in have.
func hasRequiredScopes(have, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, req := range required {
		if !slices.Contains(have, req) {
			return false
		}
	}
	return true
}
