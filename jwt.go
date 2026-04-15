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
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ubyte-source/go-jsonfast"
)

const (
	jwksCacheTTL          = 5 * time.Minute
	jwtClockSkewTolerance = 30 * time.Second
	jwtClockSkewSec       = int64(jwtClockSkewTolerance / time.Second)

	// maxJWTSize limits the maximum JWT token length to prevent
	// denial-of-service via oversized tokens.
	maxJWTSize = 16384

	// maxCombinedBuf is the maximum size for the pooled decode buffer.
	// Covers the decoded form of the largest allowed JWT plus HMAC space.
	maxCombinedBuf = maxJWTSize*3/4 + sha512.Size + 4
)

var _ Authenticator = (*oauthAuthenticator)(nil)

var (
	errNoVerificationKey   = errors.New("no JWT verification key found")
	errOAuthIssuerRequired = errors.New("auth oauth mode requires an issuer")
	errUnsupportedJWTAlg   = errors.New("unsupported JWT algorithm")
	errUnsupportedKeyType  = errors.New("unsupported JWT public key type")
	errUnsupportedCurve    = errors.New("unsupported elliptic curve")
	errJWKSEndpoint        = errors.New("jwks endpoint error")
)

// Pre-allocated auth errors returned on the JWT validation hot path.
var (
	errMalformedJWT       = unauthorizedError("malformed JWT")
	errInvalidJWTHeader   = unauthorizedError("invalid JWT header")
	errInvalidJWTSigEnc   = unauthorizedError("invalid JWT signature encoding")
	errInvalidJWTClaims   = unauthorizedError("invalid JWT claims")
	errMissingBearerToken = unauthorizedError("missing bearer token")
	errInvalidIssuer      = unauthorizedError("invalid token issuer")
	errInvalidAudience    = unauthorizedError("invalid token audience")
	errTokenExpired       = unauthorizedError("token expired")
	errTokenNotYetValid   = unauthorizedError("token not yet valid")
	errTokenFromFuture    = unauthorizedError("token issued in the future")
)

// Pre-allocated auth errors for signature verification.
var (
	errSignatureVerifyFailed = unauthorizedError("invalid JWT signature")
	errUnsupportedAlgAuth    = unauthorizedError("unsupported JWT algorithm")
	errUnsupportedKeyAuth    = unauthorizedError("unsupported JWT public key type")
	errNoKeyAuth             = unauthorizedError("no JWT verification key found")
	errInternalAuth          = unauthorizedError("internal authentication error")
)

type oauthAuthenticator struct {
	// 8-byte pointer fields first.
	httpClient *http.Client
	keys       map[string]jwkPublicKey
	// hmacPools is non-nil only in HMAC mode; 0=HS256, 1=HS384, 2=HS512.
	// A pointer avoids embedding 3×40-byte sync.Pool values inline.
	hmacPools            *[3]sync.Pool
	insufficientScopeErr error // pre-computed; avoids strings.Join + alloc per rejection
	// 16-byte string fields.
	resource              string
	realm                 string
	issuer                string
	audience              string
	jwksURL               string
	resourceDocumentation string
	resourceName          string
	// 24-byte slice fields.
	hmacSecret           []byte
	authorizationServers []string
	// Pointer-bearing fields before value fields to minimize the GC pointer bitmap.
	keysExpiry     time.Time
	requiredScopes []string
	// Non-pointer fields after all pointer fields.
	// Lock ordering: mu guards keys+keysExpiry; refreshMu serializes JWKS fetches.
	mu        sync.RWMutex
	refreshMu sync.Mutex
}

// Hash pools for asymmetric (RSA/EC) signature verification.
var (
	jwtSHA256Pool = sync.Pool{New: func() any { return sha256.New() }}
	jwtSHA384Pool = sync.Pool{New: func() any { return sha512.New384() }}
	jwtSHA512Pool = sync.Pool{New: func() any { return sha512.New() }}
)

// decodeBuf is a pooled byte buffer; the struct wrapper avoids interface boxing.
type decodeBuf struct {
	b []byte
}

var combinedPool = sync.Pool{New: func() any {
	return &decodeBuf{b: make([]byte, maxCombinedBuf)}
}}

var (
	jwtKeyAlg = []byte(`"alg":"`)
	jwtKeyKid = []byte(`"kid":"`)
)

type jwkPublicKey struct {
	key any
	alg string
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

// jwtClaims holds raw byte slices from a single-pass JSON scan of the payload.
// All slices alias the decoded payload buffer — zero-copy extraction.
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

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// authorizationServersForMode returns a defensive copy of servers in
// non-proxy mode, or nil in proxy mode (clientID set) so the transport
// fills authorization_servers from the request origin at runtime.
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
		client = &http.Client{Timeout: 5 * time.Second}
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

func (a *oauthAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	v := r.Header["Authorization"]
	if len(v) == 0 {
		return Identity{}, errMissingBearerToken
	}

	token, ok := bearerToken(v[0])
	if !ok {
		return Identity{}, errMissingBearerToken
	}

	now := time.Now()

	subject, scopes, err := a.validateToken(r.Context(), token, now)
	if err != nil {
		return Identity{}, err
	}

	if !hasRequiredScopes(scopes, a.requiredScopes) {
		return Identity{}, a.insufficientScopeErr
	}

	return Identity{
		Subject: subject,
		Method:  ModeOAuth,
		Scopes:  scopes,
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
	// When authorizationServers is nil the MCP server IS the authorization
	// server (proxy mode).  Leave the field empty so the transport fills it
	// from the request origin (it cannot be known at config time).
	servers := append([]string(nil), a.authorizationServers...)
	return &ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   servers,
		ScopesSupported:        append([]string(nil), a.requiredScopes...),
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  a.resourceDocumentation,
		ResourceName:           a.resourceName,
	}
}

// splitJWT splits a raw JWT byte slice into its three base64url-encoded parts
// and the signingInput (header.payload). Returns false if the token doesn't
// have exactly three dot-separated segments.
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

// validateToken validates a JWT and returns the subject and scopes.
func (a *oauthAuthenticator) validateToken(
	ctx context.Context, token string, now time.Time,
) (subject, scopes string, retErr error) {
	if len(token) > maxJWTSize {
		return "", "", errMalformedJWT
	}

	//nolint:gosec // G103: read-only alias of immutable string backing memory.
	data := unsafe.Slice(unsafe.StringData(token), len(token))

	headerBytes, payloadBytes, sigBytes, signingInput, ok := splitJWT(data)
	if !ok {
		return "", "", errMalformedJWT
	}

	header, err := parseJWTHeaderDirect(headerBytes)
	if err != nil {
		return "", "", errInvalidJWTHeader
	}

	// Combined buffer: signature decode + payload decode + HMAC sum space.
	sigDecLen := base64.RawURLEncoding.DecodedLen(len(sigBytes))
	payDecLen := base64.RawURLEncoding.DecodedLen(len(payloadBytes))
	needed := sigDecLen + payDecLen + sha512.Size

	db, ok := combinedPool.Get().(*decodeBuf)
	if !ok {
		return "", "", errInternalAuth
	}
	combined := db.b[:needed]
	sigBuf := combined[:sigDecLen]
	payBuf := combined[sigDecLen : sigDecLen+payDecLen]
	sumBuf := combined[sigDecLen+payDecLen:]

	sigLen, err := base64.RawURLEncoding.Decode(sigBuf, sigBytes)
	if err != nil {
		combinedPool.Put(db)
		return "", "", errInvalidJWTSigEnc
	}

	if sigErr := a.verifySignature(ctx, header.Alg, header.Kid, signingInput, sigBuf[:sigLen], sumBuf); sigErr != nil {
		combinedPool.Put(db)
		return "", "", sigErr
	}

	n, err := base64.RawURLEncoding.Decode(payBuf, payloadBytes)
	if err != nil {
		combinedPool.Put(db)
		return "", "", errInvalidJWTClaims
	}

	claims := extractClaims(payBuf[:n])

	if err := a.validateClaimsFromParsed(&claims, now.Unix()); err != nil {
		combinedPool.Put(db)
		return "", "", err
	}

	// Copy claims before returning the pooled buffer.
	subject, scopes = copyClaims(
		subjectFromClaims(&claims),
		scopesFromClaims(&claims),
	)
	combinedPool.Put(db)

	return subject, scopes, nil
}

// extractClaims performs a single-pass JSON scan of the payload,
// extracting all needed JWT claims as raw byte slices.
func extractClaims(payload []byte) jwtClaims {
	var c jwtClaims
	jsonfast.IterateFields(payload, func(key, value []byte) bool {
		extractClaimField(&c, key, value)
		return true
	})
	return c
}

// extractClaimField dispatches a single key-value pair to the appropriate
// jwtClaims field based on the quoted key length and content.
func extractClaimField(c *jwtClaims, key, value []byte) {
	switch len(key) {
	case 5: // 2 quotes + 3 chars: iss, aud, sub, exp, nbf, iat, azp, scp
		extractClaim3(c, key, value)
	case 7: // 2 quotes + 5 chars: "scope"
		if string(key) == `"scope"` {
			c.scope = value
		}
	case 11: // 2 quotes + 9 chars: "client_id"
		if string(key) == `"client_id"` {
			c.clientID = value
		}
	}
}

// extractClaim3 handles 3-character JWT claim keys (enclosed in quotes = 5 bytes).
func extractClaim3(c *jwtClaims, key, value []byte) {
	// BCE hint: proves key[0..4] are in-bounds, eliminating the three bounds
	// checks below. The caller guarantees len(key) == 5 (case 5 in extractClaimField).
	_ = key[4]
	// Pack the 3-char key into a uint32 for a flat switch.
	packed := uint32(key[1])<<16 | uint32(key[2])<<8 | uint32(key[3])
	switch packed {
	case 'i'<<16 | 's'<<8 | 's':
		c.iss = value
	case 'i'<<16 | 'a'<<8 | 't':
		c.iat = value
	case 'a'<<16 | 'u'<<8 | 'd':
		c.aud = value
	case 'a'<<16 | 'z'<<8 | 'p':
		c.azp = value
	case 's'<<16 | 'u'<<8 | 'b':
		c.sub = value
	case 's'<<16 | 'c'<<8 | 'p':
		c.scp = value
	case 'e'<<16 | 'x'<<8 | 'p':
		c.exp = value
	case 'n'<<16 | 'b'<<8 | 'f':
		c.nbf = value
	}
}

// validateClaimsFromParsed validates JWT claims from pre-extracted raw fields.
// nowUnix is the current time as a Unix timestamp to avoid time.Time construction.
func (a *oauthAuthenticator) validateClaimsFromParsed(c *jwtClaims, nowUnix int64) error {
	if !equalQuotedBytes(c.iss, a.issuer) {
		return errInvalidIssuer
	}

	if a.audience != "" && !containsAudienceRaw(c.aud, a.audience) {
		return errInvalidAudience
	}

	exp, ok := parseJSONNumber(c.exp)
	if !ok || nowUnix > exp {
		return errTokenExpired
	}

	if err := validateTimeBound(c.nbf, nowUnix, errTokenNotYetValid); err != nil {
		return err
	}

	return validateTimeBound(c.iat, nowUnix, errTokenFromFuture)
}

// validateTimeBound checks that a JWT time claim (nbf or iat) is not
// too far in the future, accounting for clock skew.
func validateTimeBound(raw []byte, nowUnix int64, errVal error) error {
	if len(raw) == 0 {
		return nil
	}
	ts, ok := parseJSONNumber(raw)
	if ok && nowUnix < ts-jwtClockSkewSec {
		return errVal
	}
	return nil
}

// claimStringView returns a zero-allocation string view of a raw JSON string value.
// WARNING: the returned string is backed by the pooled decode buffer and must not
// outlive it — copy the value before returning the buffer to the pool.
//
//nolint:gosec // unsafe.String intentional: zero-alloc view into heap-allocated combined buffer
func claimStringView(raw []byte) string {
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return ""
	}

	return unsafe.String(&raw[1], len(raw)-2)
}

// subjectFromClaims extracts the subject identifier from pre-extracted claims.
// Tries "sub", then "client_id", then "azp".
func subjectFromClaims(c *jwtClaims) string {
	if s := claimStringView(c.sub); s != "" {
		return s
	}

	if s := claimStringView(c.clientID); s != "" {
		return s
	}

	return claimStringView(c.azp)
}

// scopesFromClaims extracts scopes from pre-extracted claims.
// Handles "scope" (space-separated string) and "scp" (string or array).
func scopesFromClaims(c *jwtClaims) string {
	if s := claimStringView(c.scope); s != "" {
		return s
	}
	if s := claimStringView(c.scp); s != "" {
		return s
	}
	return scopesFromSCPArray(c.scp)
}

// scopesFromSCPArray parses the scp claim when it is a JSON array of strings.
func scopesFromSCPArray(raw []byte) string {
	if len(raw) < 2 || raw[0] != '[' {
		return ""
	}
	var b strings.Builder
	jsonfast.IterateStringArray(raw, func(val string) bool {
		v := strings.TrimSpace(val)
		if v == "" {
			return true
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(v)
		return true
	})
	return b.String()
}

// copyClaims copies subject and scopes into a single owned allocation,
// detaching them from the pooled buffer.
func copyClaims(sub, scp string) (subOut, scpOut string) {
	sLen := len(sub)
	total := sLen + len(scp)
	if total == 0 {
		return "", ""
	}
	buf := make([]byte, total)
	copy(buf, sub)
	copy(buf[sLen:], scp)
	all := string(buf)
	return all[:sLen], all[sLen:]
}

// apiKeyToken extracts the token from an "ApiKey <token>" Authorization header.
func apiKeyToken(header string) (string, bool) {
	if len(header) <= 7 || header[6] != ' ' {
		return "", false
	}
	if header[0]|0x20 != 'a' || header[1]|0x20 != 'p' || header[2]|0x20 != 'i' ||
		header[3]|0x20 != 'k' || header[4]|0x20 != 'e' || header[5]|0x20 != 'y' {
		return "", false
	}
	return header[7:], true
}

func (a *oauthAuthenticator) verifySignature(
	ctx context.Context, alg, kid string, signingInput, signature, sumBuf []byte,
) error {
	if len(a.hmacSecret) > 0 {
		return a.verifyHMACSignature(alg, signingInput, signature, sumBuf)
	}

	return a.verifyJWKS(ctx, alg, kid, signingInput, signature, sumBuf)
}

// verifyHMACSignature verifies a JWT with a pooled HMAC instance.
// sumBuf provides pre-allocated space for the digest.
func (a *oauthAuthenticator) verifyHMACSignature(alg string, signingInput, signature, sumBuf []byte) error {
	var idx int

	switch alg {
	case "HS256":
		idx = 0
	case "HS384":
		idx = 1
	case "HS512":
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
		if !ecdsa.VerifyASN1(publicKey, digest, signature) {
			return errSignatureVerifyFailed
		}

		return nil
	default:
		return errUnsupportedKeyAuth
	}
}

func hashJWT(alg string, signingInput, buf []byte) (crypto.Hash, []byte, error) {
	var hashAlg crypto.Hash
	switch alg {
	case "RS256", "PS256", "ES256":
		hashAlg = crypto.SHA256
	case "RS384", "PS384", "ES384":
		hashAlg = crypto.SHA384
	case "RS512", "PS512", "ES512":
		hashAlg = crypto.SHA512
	default:
		return 0, nil, fmt.Errorf("%w: %q", errUnsupportedJWTAlg, alg)
	}
	var pool *sync.Pool
	switch hashAlg {
	case crypto.SHA256:
		pool = &jwtSHA256Pool
	case crypto.SHA384:
		pool = &jwtSHA384Pool
	default: // crypto.SHA512
		pool = &jwtSHA512Pool
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
	keys, err = a.refreshKeys(ctx)
	if err != nil {
		return nil, err
	}
	if key, ok := findKey(keys, kid, alg); ok {
		return key, nil
	}
	return nil, errNoVerificationKey
}

func findKey(keys map[string]jwkPublicKey, kid, alg string) (any, bool) {
	if kid != "" {
		if key, ok := keys[kid]; ok && (key.alg == "" || key.alg == alg) {
			return key.key, true
		}
	}
	for _, key := range keys {
		if key.alg == "" || key.alg == alg {
			return key.key, true
		}
	}
	return nil, false
}

func (a *oauthAuthenticator) currentKeys(ctx context.Context) (map[string]jwkPublicKey, error) {
	a.mu.RLock()
	keys := a.keys
	expiry := a.keysExpiry
	a.mu.RUnlock()
	if len(keys) == 0 || time.Now().After(expiry) {
		return a.refreshKeys(ctx)
	}
	return keys, nil
}

func (a *oauthAuthenticator) refreshKeys(ctx context.Context) (_ map[string]jwkPublicKey, err error) {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()

	a.mu.RLock()
	if len(a.keys) > 0 && time.Now().Before(a.keysExpiry) {
		keys := a.keys
		a.mu.RUnlock()
		return keys, nil
	}
	a.mu.RUnlock()

	if a.jwksURL == "" {
		oidc, oidcErr := discoverOIDC(ctx, a.httpClient, a.issuer)
		if oidcErr != nil {
			return nil, fmt.Errorf("OIDC discovery: %w", oidcErr)
		}
		a.jwksURL = oidc.JWKSURI
	}

	keys, err := a.fetchAndParseJWKS(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.keys = keys
	a.keysExpiry = time.Now().Add(jwksCacheTTL)
	a.mu.Unlock()
	return keys, nil
}

// fetchAndParseJWKS fetches the JWKS endpoint and parses the key set.
func (a *oauthAuthenticator) fetchAndParseJWKS(ctx context.Context) (_ map[string]jwkPublicKey, err error) {
	//nolint:gosec // G107: a.jwksURL is operator-configured, never derived from request input
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, a.jwksURL, http.NoBody)
	if reqErr != nil {
		return nil, reqErr
	}
	resp, err := a.httpClient.Do(req) //nolint:gosec // G704: operator-configured jwksURL, not user input
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
	var set jwkSet
	if decodeErr := json.NewDecoder(resp.Body).Decode(&set); decodeErr != nil {
		return nil, decodeErr
	}
	return parseJWKS(set)
}

func parseJWKS(set jwkSet) (map[string]jwkPublicKey, error) {
	keys := make(map[string]jwkPublicKey, len(set.Keys))
	for idx := range set.Keys {
		item := &set.Keys[idx]
		key, err := parseJWK(item)
		if err != nil {
			return nil, err
		}
		name := item.Kid
		if name == "" {
			name = fmt.Sprintf("key-%d", idx)
		}
		keys[name] = jwkPublicKey{key: key, alg: item.Alg}
	}
	return keys, nil
}

func parseJWK(item *jwk) (any, error) {
	switch item.Kty {
	case "RSA":
		return parseRSAKey(item)
	case "EC":
		return parseECKey(item)
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedKeyType, item.Kty)
	}
}

func parseRSAKey(item *jwk) (*rsa.PublicKey, error) {
	n, err := decodeBase64Int(item.N)
	if err != nil {
		return nil, err
	}
	e, err := decodeBase64Int(item.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseECKey(item *jwk) (*ecdsa.PublicKey, error) {
	curve, err := ellipticCurve(item.Crv)
	if err != nil {
		return nil, err
	}
	x, err := decodeBase64Int(item.X)
	if err != nil {
		return nil, err
	}
	y, err := decodeBase64Int(item.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func ellipticCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedCurve, crv)
	}
}

func decodeBase64Int(value string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(decoded), nil
}

// parseJWTHeaderDirect base64url-decodes the JWT header and extracts alg/kid
// via direct byte scan, avoiding json.Unmarshal.
func parseJWTHeaderDirect(encoded []byte) (jwtHeader, error) {
	n := base64.RawURLEncoding.DecodedLen(len(encoded))
	if n > 128 {
		return parseJWTHeaderSlow(encoded)
	}
	var buf [128]byte
	n, err := base64.RawURLEncoding.Decode(buf[:], encoded)
	if err != nil {
		return jwtHeader{}, err
	}
	raw := buf[:n]
	h := jwtHeader{
		Alg: algFromBytes(raw, jwtKeyAlg),
		Kid: jsonStringValue(raw, jwtKeyKid),
	}
	if h.Alg != "" {
		return h, nil
	}
	return parseJWTHeaderSlow(encoded)
}

// parseJWTHeaderSlow is the json.Unmarshal fallback for non-standard JWT headers.
func parseJWTHeaderSlow(encoded []byte) (jwtHeader, error) {
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawURLEncoding.Decode(dst, encoded)
	if err != nil {
		return jwtHeader{}, err
	}
	var h jwtHeader
	if err := json.Unmarshal(dst[:n], &h); err != nil {
		return jwtHeader{}, err
	}
	return h, nil
}

// algFromBytes extracts the algorithm field from raw JSON header bytes.
// Returns a constant string for known JWS algorithms (zero-alloc).
func algFromBytes(data, key []byte) string {
	i := bytes.Index(data, key)
	if i < 0 {
		return ""
	}
	start := i + len(key)
	if start >= len(data) {
		return ""
	}
	end := bytes.IndexByte(data[start:], '"')
	if end < 0 {
		return ""
	}
	val := data[start : start+end]
	if len(val) == 5 {
		if s := matchKnownAlg(val); s != "" {
			return s
		}
	}
	return string(val)
}

func matchKnownAlg(v []byte) string {
	// BCE hint: proves v[0..4] are in-bounds, eliminating all per-case checks.
	// The caller (algFromBytes) guarantees len(v) == 5.
	_ = v[4]
	switch {
	case v[0] == 'H' && v[1] == 'S':
		return matchAlgVariant(v[4], "HS256", "HS384", "HS512")
	case v[0] == 'R' && v[1] == 'S':
		return matchAlgVariant(v[4], "RS256", "RS384", "RS512")
	case v[0] == 'E' && v[1] == 'S':
		return matchAlgVariant(v[4], "ES256", "ES384", "ES512")
	case v[0] == 'P' && v[1] == 'S':
		return matchAlgVariant(v[4], "PS256", "PS384", "PS512")
	default:
		return ""
	}
}

func matchAlgVariant(last byte, s256, s384, s512 string) string {
	switch last {
	case '6':
		return s256
	case '4':
		return s384
	case '2':
		return s512
	default:
		return ""
	}
}

// jsonStringValue extracts a simple "key":"value" pair from flat JSON.
// Returns "" if not found or the value contains escape sequences.
func jsonStringValue(data, key []byte) string {
	i := bytes.Index(data, key)
	if i < 0 {
		return ""
	}
	start := i + len(key)
	if start >= len(data) {
		return ""
	}
	end := bytes.IndexByte(data[start:], '"')
	if end < 0 {
		return ""
	}
	val := data[start : start+end]
	if bytes.IndexByte(val, '\\') >= 0 {
		return ""
	}
	return string(val)
}

// parseJSONNumber parses a raw JSON number into int64.
// Zero-alloc for pure integer values (the common case for JWT timestamps).
func parseJSONNumber(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			//nolint:gosec // G103: b is a sub-slice of decoded payload, outlives this call.
			s := unsafe.String(unsafe.SliceData(b), len(b))
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return 0, false
			}
			return int64(f), true
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

// equalQuotedBytes checks if a raw JSON quoted value equals the given
// unquoted string, without allocation.
// string(raw[1:len(raw)-1]) == s is compiled to a direct memcmp (no alloc).
func equalQuotedBytes(raw []byte, s string) bool {
	return len(raw) == len(s)+2 && raw[0] == '"' && raw[len(raw)-1] == '"' &&
		string(raw[1:len(raw)-1]) == s
}

// containsAudienceRaw checks audience from raw JSON value.
// Handles both string and array forms.
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
			if val == expected {
				found = true
				return false
			}
			return true
		})
		return found
	}
	return false
}

func bearerToken(header string) (string, bool) {
	if len(header) <= 7 || header[6] != ' ' {
		return "", false
	}
	// ASCII case-fold per RFC 7235 §2.1.
	if header[0]|0x20 != 'b' || header[1]|0x20 != 'e' || header[2]|0x20 != 'a' ||
		header[3]|0x20 != 'r' || header[4]|0x20 != 'e' || header[5]|0x20 != 'r' {
		return "", false
	}
	return header[7:], true
}

func hasRequiredScopes(have string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	if have == "" {
		return false
	}
	for _, req := range required {
		if !containsScope(have, req) {
			return false
		}
	}
	return true
}

// containsScope checks whether the space-separated scopes string contains scope.
func containsScope(scopes, scope string) bool {
	for scopes != "" {
		if idx := strings.IndexByte(scopes, ' '); idx >= 0 {
			if scopes[:idx] == scope {
				return true
			}

			scopes = scopes[idx+1:]
		} else {
			return scopes == scope
		}
	}

	return false
}
