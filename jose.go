package authware

import (
	"crypto"
	"fmt"
	"slices"
	"strings"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

// maxTokenSize bounds the encoded token; it is checked before any decoding.
const maxTokenSize = 16 << 10

const (
	errTokenTooLarge  = tokenError("token too large")
	errMalformedToken = tokenError("malformed token")
	errUnsupportedAlg = tokenError("unsupported JWT algorithm")
	errCriticalHeader = tokenError("unsupported critical JWT header")
	errTokenType      = tokenError("invalid JWT typ header")
)

// Token format details, built once.
var (
	errSegments          = fmt.Errorf("%w: not three segments", errMalformedToken)
	errHeaderEncoding    = fmt.Errorf("%w: header is not base64url", errMalformedToken)
	errPayloadEncoding   = fmt.Errorf("%w: payload is not base64url", errMalformedToken)
	errSignatureEncoding = fmt.Errorf("%w: signature is not base64url", errMalformedToken)
	errNoAlg             = fmt.Errorf("%w: no alg", errMalformedToken)
	errModeAlg           = fmt.Errorf("%w: not verified in this mode", errUnsupportedAlg)
	errAccessType        = fmt.Errorf("%w: at+jwt required", errTokenType)
	errHeaderShape       = jsonobj.Refusal(errMalformedToken)
	errAlgNotString      = jsonobj.NotString(errMalformedToken, memberAlg)
	errKidNotString      = jsonobj.NotString(errMalformedToken, memberKid)
	errTypNotString      = jsonobj.NotString(errMalformedToken, memberTyp)
)

const (
	algRS256 = "RS256"
	algRS384 = "RS384"
	algRS512 = "RS512"
	algPS256 = "PS256"
	algPS384 = "PS384"
	algPS512 = "PS512"
	algES256 = "ES256"
	algES384 = "ES384"
	algES512 = "ES512"
	algEdDSA = "EdDSA"
	algHS256 = "HS256"
	algHS384 = "HS384"
	algHS512 = "HS512"
)

// Byte lengths of the two integers of an ECDSA signature, per curve.
const (
	sizeP256 = 32
	sizeP384 = 48
	sizeP521 = 66
)

// Curve names, as JWK crv members spell them.
const (
	crvP256    = "P-256"
	crvP384    = "P-384"
	crvP521    = "P-521"
	crvEd25519 = "Ed25519"
)

// JOSE header member names; alg and kid also name JWK members.
const (
	memberAlg  = "alg"
	memberKid  = "kid"
	memberTyp  = "typ"
	memberCrit = "crit"
)

// keyKind is the key type an algorithm verifies with, the kty member of a JWK
// of that type; the zero kind names none, so the zero algorithm fits no key.
type keyKind string

// Key kinds, as kty spells them.
const (
	kindRSA keyKind = "RSA"
	kindEC  keyKind = "EC"
	kindOKP keyKind = "OKP"
	kindOct keyKind = "oct"
)

// algorithm binds a JWS alg to its key kind, curve and hash; size is the
// byte length of each ECDSA signature integer.
type algorithm struct {
	name  string
	kind  keyKind
	curve string
	size  int
	hash  crypto.Hash
	pss   bool
}

// lookupAlgorithm returns the accepted JWS algorithm named exactly name.
func lookupAlgorithm(name string) (algorithm, bool) {
	switch name {
	case algRS256, algRS384, algRS512:
		return algorithm{name: name, kind: kindRSA, hash: sha2(name)}, true
	case algPS256, algPS384, algPS512:
		return algorithm{name: name, kind: kindRSA, hash: sha2(name), pss: true}, true
	case algHS256, algHS384, algHS512:
		return algorithm{name: name, kind: kindOct, hash: sha2(name)}, true
	case algES256:
		return algorithm{name: name, kind: kindEC, curve: crvP256, size: sizeP256, hash: sha2(name)}, true
	case algES384:
		return algorithm{name: name, kind: kindEC, curve: crvP384, size: sizeP384, hash: sha2(name)}, true
	case algES512:
		return algorithm{name: name, kind: kindEC, curve: crvP521, size: sizeP521, hash: sha2(name)}, true
	case algEdDSA:
		return algorithm{name: name, kind: kindOKP, curve: crvEd25519}, true
	}
	return algorithm{}, false
}

// sha2 returns the SHA-2 hash whose digest bits, 256, 384 or 512, end name.
func sha2(name string) crypto.Hash {
	switch {
	case strings.HasSuffix(name, "384"):
		return crypto.SHA384
	case strings.HasSuffix(name, "512"):
		return crypto.SHA512
	}
	return crypto.SHA256
}

// joseHeader is the part of a JOSE header that verification reads.
type joseHeader struct {
	alg algorithm
	kid string
	// accessType marks typ at+jwt or application/at+jwt.
	accessType bool
}

// jws is a compact token with its segments decoded: the claims are read only
// once the signature is verified.
type jws struct {
	header       joseHeader
	claims       string
	signature    []byte
	signingInput []byte
}

// parseJWS decodes the segments of raw and parses its header. The signing
// input, the decoded segments and the scratch share *buf, grown in place and
// aliased by the jws; the header and the claims are one string copied from it.
func parseJWS(raw string, buf *[]byte) (jws, error) {
	if len(raw) > maxTokenSize {
		return jws{}, errTokenTooLarge
	}
	parts, ok := syntax.SplitJWS(raw)
	if !ok {
		return jws{}, errSegments
	}
	// The signing input comes first; decoding shrinks every segment, so
	// len(raw) more bytes hold the three decoded ones.
	n := len(parts.Header) + 1 + len(parts.Payload)
	*buf = slices.Grow((*buf)[:0], n+len(raw)+verifyScratch)
	input := append(*buf, raw[:n]...)
	header, ok := syntax.AppendSegment(input[len(input):], parts.Header)
	if !ok {
		return jws{}, errHeaderEncoding
	}
	payload, ok := syntax.AppendSegment(header[len(header):], parts.Payload)
	if !ok {
		return jws{}, errPayloadEncoding
	}
	signature, ok := syntax.AppendSegment(payload[len(payload):], parts.Signature)
	if !ok {
		return jws{}, errSignatureEncoding
	}
	text := string(header[:len(header)+len(payload)])
	h, err := parseHeader(text[:len(header)])
	if err != nil {
		return jws{}, err
	}
	return jws{header: h, claims: text[len(header):], signature: signature, signingInput: input}, nil
}

// scratch returns the empty room of verifyScratch bytes after the signature,
// where the verification works.
func (t *jws) scratch() []byte { return t.signature[len(t.signature):] }

// parseHeader parses a decoded JOSE header, a UTF-8 JSON object. Any crit
// member rejects the token; key-carrying members such as jku, x5u, jwk and
// x5c are ignored.
func parseHeader(data string) (joseHeader, error) {
	var h joseHeader
	if err := jsonobj.Iterate(data, errHeaderShape, h.set); err != nil {
		return joseHeader{}, err
	}
	if h.alg.name == "" {
		return joseHeader{}, errNoAlg
	}
	return h, nil
}

func (h *joseHeader) set(name, value string) error {
	switch name {
	case memberCrit:
		return errCriticalHeader
	case memberAlg:
		return h.setAlg(value)
	case memberKid:
		return h.setKid(value)
	case memberTyp:
		return h.setType(value)
	}
	return nil
}

// setAlg accepts the value of alg when it names a supported algorithm.
func (h *joseHeader) setAlg(value string) error {
	name, ok := jsonfast.DecodeString(value)
	if !ok {
		return errAlgNotString
	}
	alg, known := lookupAlgorithm(name)
	if !known {
		return fmt.Errorf("%w: %q", errUnsupportedAlg, name)
	}
	h.alg = alg
	return nil
}

// setKid records the value of kid, a string.
func (h *joseHeader) setKid(value string) error {
	kid, ok := jsonfast.DecodeString(value)
	if !ok {
		return errKidNotString
	}
	h.kid = kid
	return nil
}

// setType accepts the value of typ when it is JWT or the access token type,
// each also as its media type under application/, case-insensitively.
func (h *joseHeader) setType(value string) error {
	typ, ok := jsonfast.DecodeString(value)
	if !ok {
		return errTypNotString
	}
	switch {
	case strings.EqualFold(typ, "jwt"), strings.EqualFold(typ, "application/jwt"):
	case strings.EqualFold(typ, "at+jwt"), strings.EqualFold(typ, "application/at+jwt"):
		h.accessType = true
	default:
		return fmt.Errorf("%w: %q", errTokenType, typ)
	}
	return nil
}
