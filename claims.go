package authware

import (
	"fmt"
	"math"
	"time"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
)

// maxNumericDate is the largest time claim accepted, in seconds: 2^53.
const maxNumericDate = 1 << 53

const (
	claimIss      = "iss"
	claimAud      = "aud"
	claimExp      = "exp"
	claimNbf      = "nbf"
	claimIat      = "iat"
	claimSub      = "sub"
	claimClientID = "client_id"
	claimAzp      = "azp"
	claimScope    = "scope"
	claimScp      = "scp"
	claimRoles    = "roles"
	claimNonce    = "nonce"
	claimAtHash   = "at_hash"
	claimCHash    = "c_hash"
)

const (
	errMalformedClaims = tokenError("malformed JWT claims")
	errIssuer          = tokenError("invalid token issuer")
	errAudience        = tokenError("invalid token audience")
	errMissingExpiry   = tokenError("missing exp claim")
	errNotYetValid     = tokenError("token not yet valid")
	errIssuedInFuture  = tokenError("token issued in the future")
	errIDToken         = tokenError("ID token not accepted")
)

// Claim failure details, built once.
var (
	errNoAudience        = fmt.Errorf("%w: no aud", errAudience)
	errAudienceType      = fmt.Errorf("%w: aud is neither a string nor an array of strings", errMalformedClaims)
	errScopeType         = fmt.Errorf("%w: scp is neither a string nor an array of strings", errMalformedClaims)
	errExpTime           = fmt.Errorf("%w: exp is not a time", errMalformedClaims)
	errNbfTime           = fmt.Errorf("%w: nbf is not a time", errMalformedClaims)
	errIatTime           = fmt.Errorf("%w: iat is not a time", errMalformedClaims)
	errClaimsShape       = jsonobj.Refusal(errMalformedClaims)
	errIssNotString      = jsonobj.NotString(errMalformedClaims, claimIss)
	errSubNotString      = jsonobj.NotString(errMalformedClaims, claimSub)
	errClientIDNotString = jsonobj.NotString(errMalformedClaims, claimClientID)
	errAzpNotString      = jsonobj.NotString(errMalformedClaims, claimAzp)
	errScopeNotString    = jsonobj.NotString(errMalformedClaims, claimScope)
)

// claimPolicy is what an access token must satisfy.
type claimPolicy struct {
	iss      string
	audience string
	skew     time.Duration
}

// tokenClaims are the claims of a validated token.
type tokenClaims struct {
	subject string
	scopes  []string
}

// rawClaims holds the JSON text of the claims validation reads, empty when
// absent, and flags for the ID token markers.
type rawClaims struct {
	iss      string
	aud      string
	exp      string
	nbf      string
	iat      string
	sub      string
	clientID string
	azp      string
	scope    string
	scp      string
	idToken  bool
	nonce    bool
	authz    bool
}

// validateClaims parses payload, a UTF-8 JSON object with unique member
// names, and checks it against p at now.
func (p *claimPolicy) validateClaims(payload string, now time.Time) (tokenClaims, error) {
	var raw rawClaims
	if err := jsonobj.Iterate(payload, errClaimsShape, raw.set); err != nil {
		return tokenClaims{}, err
	}
	if raw.idToken || (raw.nonce && !raw.authz) {
		return tokenClaims{}, errIDToken
	}
	if err := p.checkIdentity(&raw); err != nil {
		return tokenClaims{}, err
	}
	if err := p.checkTimes(&raw, now); err != nil {
		return tokenClaims{}, err
	}
	subject, err := raw.subject()
	if err != nil {
		return tokenClaims{}, err
	}
	scopes, err := raw.scopes()
	if err != nil {
		return tokenClaims{}, err
	}
	return tokenClaims{subject: subject, scopes: scopes}, nil
}

// set records one payload member: an ID token or authorization marker, or
// the value of a claim validation reads.
func (c *rawClaims) set(name, value string) error {
	switch name {
	case claimAtHash, claimCHash:
		c.idToken = true
	case claimNonce:
		c.nonce = true
	case claimRoles:
		c.authz = true
	case claimScope:
		c.authz, c.scope = true, value
	case claimScp:
		c.authz, c.scp = true, value
	default:
		c.setValue(name, value)
	}
	return nil
}

// setValue records the value of an identity or time claim.
func (c *rawClaims) setValue(name, value string) {
	switch name {
	case claimIss:
		c.iss = value
	case claimAud:
		c.aud = value
	case claimExp:
		c.exp = value
	case claimNbf:
		c.nbf = value
	case claimIat:
		c.iat = value
	case claimSub:
		c.sub = value
	case claimClientID:
		c.clientID = value
	case claimAzp:
		c.azp = value
	}
}

// checkIdentity requires iss to equal the issuer and aud, a string or an
// array of strings, to contain the audience.
func (p *claimPolicy) checkIdentity(c *rawClaims) error {
	iss, err := claimString(c.iss, errIssNotString)
	if err != nil {
		return err
	}
	if iss != p.iss {
		return errIssuer
	}
	if c.aud == "" {
		return errNoAudience
	}
	found, ok := holdsString(c.aud, p.audience)
	if !ok {
		return errAudienceType
	}
	if !found {
		return errAudience
	}
	return nil
}

// holdsString reports whether raw, a string or an array of strings, holds s,
// compared without decoding; ok is false when raw is neither.
func holdsString(raw, s string) (found, ok bool) {
	if jsonfast.KindOf(raw) == jsonfast.KindString {
		return jsonfast.EqualString(raw, s), true
	}
	err := jsonfast.IterateArray(raw, func(elem string) error {
		if jsonfast.KindOf(elem) != jsonfast.KindString {
			return errMalformedClaims
		}
		found = found || jsonfast.EqualString(elem, s)
		return nil
	})
	return found && err == nil, err == nil
}

// checkTimes requires exp and applies the skew to exp, nbf and iat.
func (p *claimPolicy) checkTimes(c *rawClaims, now time.Time) error {
	if c.exp == "" {
		return errMissingExpiry
	}
	exp, err := numericDate(c.exp, errExpTime)
	switch {
	case err != nil:
		return err
	case now.After(exp.Add(p.skew)):
		return ErrTokenExpired
	}
	limit := now.Add(p.skew)
	if err := notAfter(c.nbf, errNbfTime, limit, errNotYetValid); err != nil {
		return err
	}
	return notAfter(c.iat, errIatTime, limit, errIssuedInFuture)
}

// notAfter fails with fail when the time claim in raw is present and lies
// after limit, and with malformed when it is no time.
func notAfter(raw string, malformed error, limit time.Time, fail error) error {
	if raw == "" {
		return nil
	}
	t, err := numericDate(raw, malformed)
	if err != nil {
		return err
	}
	if t.After(limit) {
		return fail
	}
	return nil
}

// numericDate decodes raw, a time claim, a JSON number from 0 to 2^53
// seconds; any other value fails with malformed.
func numericDate(raw string, malformed error) (time.Time, error) {
	v, ok := jsonfast.DecodeFloat64(raw)
	if !ok || v < 0 || v > maxNumericDate {
		return time.Time{}, malformed
	}
	sec, frac := math.Modf(v)
	return time.Unix(int64(sec), int64(frac*float64(time.Second))), nil
}

// subject returns the first non-empty of sub, client_id and azp.
func (c *rawClaims) subject() (string, error) {
	for _, claim := range [...]struct {
		raw       string
		notString error
	}{{c.sub, errSubNotString}, {c.clientID, errClientIDNotString}, {c.azp, errAzpNotString}} {
		s, err := claimString(claim.raw, claim.notString)
		if err != nil {
			return "", err
		}
		if s != "" {
			return s, nil
		}
	}
	return "", nil
}

// scopes returns the tokens of scope, a space-separated string, or else of
// scp, such a string or an array of strings.
func (c *rawClaims) scopes() ([]string, error) {
	if c.scope != "" {
		s, err := claimString(c.scope, errScopeNotString)
		if err != nil {
			return nil, err
		}
		return scopeTokens(s), nil
	}
	if c.scp == "" {
		return nil, nil
	}
	var tokens []string
	ok := eachString(c.scp, func(s string) { tokens = append(tokens, scopeTokens(s)...) })
	if !ok {
		return nil, errScopeType
	}
	return tokens, nil
}

// claimString decodes raw, a claim that must be a string when present, or
// returns notString.
func claimString(raw string, notString error) (string, error) {
	if raw == "" {
		return "", nil
	}
	s, ok := jsonfast.DecodeString(raw)
	if !ok {
		return "", notString
	}
	return s, nil
}

// eachString calls fn with raw when it is a string, or with each element of
// raw, an array of strings, each decoded; it reports false when raw is neither,
// maybe after fn saw the elements before the fault.
func eachString(raw string, fn func(s string)) bool {
	if s, ok := jsonfast.DecodeString(raw); ok {
		fn(s)
		return true
	}
	return jsonfast.IterateArray(raw, func(elem string) error {
		s, ok := jsonfast.DecodeString(elem)
		if !ok {
			return errMalformedClaims
		}
		fn(s)
		return nil
	}) == nil
}
