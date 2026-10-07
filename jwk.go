package authware

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

// JWK member names, the use and the key operation verification needs.
const (
	memberKty    = "kty"
	memberUse    = "use"
	memberCrv    = "crv"
	memberKeyOps = "key_ops"
	memberN      = "n"
	memberE      = "e"
	memberX      = "x"
	memberY      = "y"
	useSig       = "sig"
	opVerify     = "verify"
)

// RSA key bounds in bits: the modulus, and the odd exponent from 3 to 2^31-1.
const (
	minRSABits         = 2048
	maxRSABits         = 8192
	minRSAExponentBits = 2
	maxRSAExponentBits = 31
)

var (
	errInvalidJWKS = errors.New("invalid JWKS")
	errUnusableKey = errors.New("unusable JWK")
	errJWKSShape   = jsonobj.Refusal(errInvalidJWKS)
	errKeyShape    = jsonobj.Refusal(errUnusableKey)
)

// The refusals of a JWKS and of its keys that name no value of the document.
var (
	errKeysNotArray     = fmt.Errorf("%w: keys is not an array", errInvalidJWKS)
	errNoUsableKey      = fmt.Errorf("%w: no usable key", errInvalidJWKS)
	errKeyOpsNotStrings = fmt.Errorf("%w: key_ops is not an array of strings", errUnusableKey)
	errKeyOpsNoVerify   = fmt.Errorf("%w: key_ops without verify", errUnusableKey)
	errParamN           = notBase64url(memberN)
	errParamE           = notBase64url(memberE)
	errParamX           = notBase64url(memberX)
	errParamY           = notBase64url(memberY)
)

const (
	errNoKey        = tokenError("no JWT verification key found")
	errAmbiguousKey = tokenError("ambiguous JWT verification key")
)

// jwk is a usable verification key of a JWKS.
type jwk struct {
	kid     string
	algName string
	key     verificationKey
}

// jwkSet holds the usable keys of a JWKS in document order, indexed by kid.
type jwkSet struct {
	keys  []*jwk
	byKid map[string][]*jwk
}

// match returns the one key that verifies alg: among the keys named kid when
// kid is set, else among all keys. A JWK alg, when present, must equal alg.
func (s *jwkSet) match(kid string, alg algorithm) (verificationKey, error) {
	candidates := s.keys
	if kid != "" {
		candidates = s.byKid[kid]
	}
	var found verificationKey
	for _, k := range candidates {
		if !k.key.fits(alg) || (k.algName != "" && k.algName != alg.name) {
			continue
		}
		if found != nil {
			return nil, errAmbiguousKey
		}
		found = k.key
	}
	if found == nil {
		return nil, errNoKey
	}
	return found, nil
}

// parseJWKS parses a JWK Set, skipping keys it cannot use; a set without a
// usable key is an error that joins the reasons of every skipped key.
func parseJWKS(data string) (*jwkSet, error) {
	var keys string
	err := jsonobj.Iterate(data, errJWKSShape, func(name, value string) error {
		if name == "keys" {
			keys = value
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	set := &jwkSet{byKid: make(map[string][]*jwk)}
	var skipped []error
	err = jsonfast.IterateArray(keys, func(elem string) error {
		k, unusable := parseJWK(elem)
		if unusable != nil {
			skipped = append(skipped, unusable)
			return nil
		}
		set.keys = append(set.keys, k)
		if k.kid != "" {
			set.byKid[k.kid] = append(set.byKid[k.kid], k)
		}
		return nil
	})
	if err != nil {
		return nil, errKeysNotArray
	}
	if len(set.keys) == 0 {
		return nil, errors.Join(append([]error{errNoUsableKey}, skipped...)...)
	}
	return set, nil
}

// jwkMembers holds the decoded string members of one JWK that verification
// reads.
type jwkMembers struct {
	kty     string
	kid     string
	algName string
	crv     string
	n       string
	e       string
	x       string
	y       string
}

// parseJWK builds the verification key of data, one JWK of a document that
// parseJWKS accepted, or reports why the key cannot verify signatures. The key
// keeps copies of kid and alg, not the document.
func parseJWK(data string) (*jwk, error) {
	var m jwkMembers
	if err := jsonobj.Iterate(data, errKeyShape, m.set); err != nil {
		return nil, err
	}
	key, err := m.key()
	if err != nil {
		return nil, err
	}
	if a, known := lookupAlgorithm(m.algName); m.algName != "" && (!known || !key.fits(a)) {
		return nil, fmt.Errorf("%w: alg %q does not fit the key", errUnusableKey, m.algName)
	}
	return &jwk{kid: strings.Clone(m.kid), algName: strings.Clone(m.algName), key: key}, nil
}

// set records one JWK member, refusing a use other than sig and key_ops
// without verify; members that verification does not read are ignored.
func (m *jwkMembers) set(name, value string) error {
	switch name {
	case memberKeyOps:
		return checkOps(value)
	case memberUse:
		return checkUse(value)
	}
	dst := m.field(name)
	if dst == nil {
		return nil
	}
	s, err := jsonobj.String(name, value, errUnusableKey)
	if err != nil {
		return err
	}
	*dst = s
	return nil
}

// field returns where the named member is kept, nil for a member that
// verification does not read.
func (m *jwkMembers) field(name string) *string {
	switch name {
	case memberKty:
		return &m.kty
	case memberKid:
		return &m.kid
	case memberAlg:
		return &m.algName
	case memberCrv:
		return &m.crv
	case memberN:
		return &m.n
	case memberE:
		return &m.e
	case memberX:
		return &m.x
	case memberY:
		return &m.y
	}
	return nil
}

// checkUse requires use to be the string sig.
func checkUse(value string) error {
	if !jsonfast.EqualString(value, useSig) {
		return fmt.Errorf("%w: use %s", errUnusableKey, value)
	}
	return nil
}

// checkOps requires key_ops to be an array of strings holding verify,
// compared without decoding.
func checkOps(value string) error {
	verify := false
	err := jsonfast.IterateArray(value, func(op string) error {
		if jsonfast.KindOf(op) != jsonfast.KindString {
			return errUnusableKey
		}
		verify = verify || jsonfast.EqualString(op, opVerify)
		return nil
	})
	switch {
	case err != nil:
		return errKeyOpsNotStrings
	case !verify:
		return errKeyOpsNoVerify
	}
	return nil
}

// key decodes the key material of the JWK kty.
func (m *jwkMembers) key() (verificationKey, error) {
	switch keyKind(m.kty) {
	case kindRSA:
		return parseRSAKey(m.n, m.e)
	case kindEC:
		return parseECKey(m.crv, m.x, m.y)
	case kindOKP:
		return parseEdKey(m.crv, m.x)
	default:
		return nil, fmt.Errorf("%w: kty %q", errUnusableKey, m.kty)
	}
}

// parseRSAKey accepts a modulus of 2048 to 8192 bits and an odd exponent
// from 3 to 2^31-1.
func parseRSAKey(n, e string) (verificationKey, error) {
	nb, err := keyParam(n, errParamN)
	if err != nil {
		return nil, err
	}
	eb, err := keyParam(e, errParamE)
	if err != nil {
		return nil, err
	}
	modulus, exponent := new(big.Int).SetBytes(nb), new(big.Int).SetBytes(eb)
	if bits := modulus.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, fmt.Errorf("%w: RSA modulus of %d bits", errUnusableKey, bits)
	}
	if bits := exponent.BitLen(); bits < minRSAExponentBits || bits > maxRSAExponentBits || exponent.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: RSA exponent %s", errUnusableKey, exponent)
	}
	return &rsaKey{rsaPub: &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}}, nil
}

// parseECKey accepts a point on P-256, P-384 or P-521 with full-length
// coordinates: the parser fixes the point length, so equal lengths make both
// coordinates full.
func parseECKey(crv, x, y string) (verificationKey, error) {
	var curve elliptic.Curve
	switch crv {
	case crvP256:
		curve = elliptic.P256()
	case crvP384:
		curve = elliptic.P384()
	case crvP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("%w: crv %q", errUnusableKey, crv)
	}
	xb, err := keyParam(x, errParamX)
	if err != nil {
		return nil, err
	}
	yb, err := keyParam(y, errParamY)
	if err != nil {
		return nil, err
	}
	if len(xb) != len(yb) {
		return nil, fmt.Errorf("%w: EC coordinates of %d and %d bytes", errUnusableKey, len(xb), len(yb))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, xb...), yb...))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnusableKey, err)
	}
	// The curve's own name equals crv but is no view of the document.
	return &ecKey{ecPub: pub, crv: curve.Params().Name}, nil
}

// parseEdKey accepts a 32-byte Ed25519 public key.
func parseEdKey(crv, x string) (verificationKey, error) {
	if crv != crvEd25519 {
		return nil, fmt.Errorf("%w: crv %q", errUnusableKey, crv)
	}
	xb, err := keyParam(x, errParamX)
	if err != nil {
		return nil, err
	}
	if len(xb) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 key of %d bytes", errUnusableKey, len(xb))
	}
	return &edKey{edPub: ed25519.PublicKey(xb)}, nil
}

// keyParam decodes a base64url key parameter, refusing other text with
// notBase64.
func keyParam(value string, notBase64 error) ([]byte, error) {
	b, ok := syntax.AppendSegment(nil, value)
	if !ok {
		return nil, notBase64
	}
	return b, nil
}

// notBase64url refuses the key parameter name holding no base64url text.
func notBase64url(name string) error {
	return fmt.Errorf("%w: parameter %s is not base64url", errUnusableKey, name)
}
