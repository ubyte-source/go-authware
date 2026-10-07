package authware

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/keyedmac"
)

const errSignature = tokenError("invalid JWT signature")

type verificationKey interface {
	// fits reports whether alg verifies with the key.
	fits(alg algorithm) bool
	// verify checks sig over input under alg, which fits the key; scratch is
	// empty room of verifyScratch bytes for the digest and the DER signature.
	verify(alg algorithm, input, sig, scratch []byte) bool
}

// verifyScratch is the room verify needs after the decoded token: a digest
// and a DER signature.
const verifyScratch = sha512.Size + derSignatureSize

// verifySignature checks sig over input with key under alg, in scratch; a
// key that alg does not fit verifies nothing.
func verifySignature(key verificationKey, alg algorithm, input, sig, scratch []byte) error {
	if !key.fits(alg) || !key.verify(alg, input, sig, scratch) {
		return errSignature
	}
	return nil
}

// hmacKey is a shared HMAC secret of size bytes with a keyed MAC per hash.
type hmacKey struct {
	sha256 *keyedmac.MAC
	sha384 *keyedmac.MAC
	sha512 *keyedmac.MAC
	size   int
}

func newHMACKey(secret []byte) *hmacKey {
	return &hmacKey{
		sha256: keyedmac.New(sha256.New, secret),
		sha384: keyedmac.New(sha512.New384, secret),
		sha512: keyedmac.New(sha512.New, secret),
		size:   len(secret),
	}
}

// fits accepts an HMAC algorithm whose hash size the secret length reaches.
func (k *hmacKey) fits(alg algorithm) bool {
	return alg.kind == kindOct && k.size >= alg.hash.Size()
}

func (k *hmacKey) verify(alg algorithm, input, sig, scratch []byte) bool {
	return hmac.Equal(sig, k.mac(alg.hash).Sum(scratch, input))
}

func (k *hmacKey) mac(h crypto.Hash) *keyedmac.MAC {
	switch h {
	case crypto.SHA384:
		return k.sha384
	case crypto.SHA512:
		return k.sha512
	default:
		return k.sha256
	}
}

// accepts reports whether k fits alg, as the key resolver of the HMAC mode.
func (k *hmacKey) accepts(alg algorithm) bool { return k.fits(alg) }

// key returns k itself, the one key of the HMAC mode.
func (k *hmacKey) key(context.Context, string, algorithm, time.Time) (verificationKey, error) {
	return k, nil
}

type rsaKey struct {
	rsaPub *rsa.PublicKey
}

func (*rsaKey) fits(alg algorithm) bool { return alg.kind == kindRSA }

// verify checks PKCS #1 v1.5, or PSS with a salt as long as the hash.
func (k *rsaKey) verify(alg algorithm, input, sig, scratch []byte) bool {
	sum := digest(alg.hash, input, scratch)
	if alg.pss {
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		return rsa.VerifyPSS(k.rsaPub, alg.hash, sum, sig, opts) == nil
	}
	return rsa.VerifyPKCS1v15(k.rsaPub, alg.hash, sum, sig) == nil
}

// maxDERBody is the longest body of a DER signature: the two INTEGERs of a
// P-521 signature, each a tag, a length and up to 67 bytes.
const maxDERBody = 2 * (2 + sizeP521 + 1)

// DER framing: a SEQUENCE header of up to derHeader bytes around a body of
// up to maxDERBody; highBit makes a length the long form and an INTEGER
// negative.
const (
	derHeader        = 3
	derSignatureSize = derHeader + maxDERBody
	derSequence      = 0x30
	derInteger       = 0x02
	highBit          = 0x80
)

// encodeDER writes the big-endian integers r and s, each one to sizeP521
// bytes, as the ASN.1 SEQUENCE that VerifyASN1 reads into the array of room,
// empty with derSignatureSize bytes of capacity, and returns it.
func encodeDER(room, r, s []byte) []byte {
	der := room[:derHeader]
	body := appendDERInteger(appendDERInteger(der[derHeader:], r), s)
	n := min(len(body), maxDERBody)
	if n < highBit {
		der[1], der[2] = derSequence, byte(n)
		return der[1 : derHeader+n]
	}
	der[0], der[1], der[2] = derSequence, highBit|1, byte(n)
	return der[:derHeader+n]
}

// appendDERInteger appends the ASN.1 INTEGER of the unsigned big-endian v,
// one to sizeP521 bytes, in its shortest form.
func appendDERInteger(b, v []byte) []byte {
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	n := min(len(v), sizeP521)
	if v[0]&highBit != 0 {
		return append(append(b, derInteger, byte(n+1), 0), v[:n]...)
	}
	return append(append(b, derInteger, byte(n)), v[:n]...)
}

type ecKey struct {
	ecPub *ecdsa.PublicKey
	crv   string
}

func (k *ecKey) fits(alg algorithm) bool { return alg.kind == kindEC && alg.curve == k.crv }

// verify checks a fixed-length R||S signature.
func (k *ecKey) verify(alg algorithm, input, sig, scratch []byte) bool {
	if len(sig) != 2*alg.size {
		return false
	}
	sum := digest(alg.hash, input, scratch)
	return ecdsa.VerifyASN1(k.ecPub, sum, encodeDER(sum[len(sum):], sig[:alg.size], sig[alg.size:]))
}

type edKey struct {
	edPub ed25519.PublicKey
}

func (*edKey) fits(alg algorithm) bool { return alg.kind == kindOKP }

func (k *edKey) verify(_ algorithm, input, sig, _ []byte) bool {
	return ed25519.Verify(k.edPub, input, sig)
}

// digest appends the h digest of input to dst; h is SHA-256, SHA-384 or
// SHA-512, the hashes of the RSA and ECDSA algorithms.
func digest(h crypto.Hash, input, dst []byte) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384(input)
		return append(dst, d[:]...)
	case crypto.SHA512:
		d := sha512.Sum512(input)
		return append(dst, d[:]...)
	default:
		d := sha256.Sum256(input)
		return append(dst, d[:]...)
	}
}
