package authware

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/keyedmac"
)

// verifyCase pairs an alg with a signing key and the key that verifies it.
type verifyCase struct {
	algName  string
	signer   any
	verifier verificationKey
}

// verifyCases covers every alg of the table with fitting keys.
func verifyCases(tb testing.TB) []verifyCase {
	tb.Helper()
	priv, mac := testRSAKey(), []byte(testWideSecret)
	ec256, ec384, ec521 := mustECKey(tb, elliptic.P256()), mustECKey(tb, elliptic.P384()), mustECKey(tb,
		elliptic.P521())
	ed := mustEdKey(tb)
	rsaPub, hmacPub := &rsaKey{rsaPub: &priv.PublicKey}, newHMACKey(mac)
	return []verifyCase{
		{algES256, ec256, &ecKey{ecPub: &ec256.PublicKey, crv: crvP256}},
		{algES384, ec384, &ecKey{ecPub: &ec384.PublicKey, crv: crvP384}},
		{algES512, ec521, &ecKey{ecPub: &ec521.PublicKey, crv: crvP521}},
		{algEdDSA, ed, &edKey{edPub: ed25519.PublicKey(ed[ed25519.SeedSize:])}},
		{algHS256, mac, hmacPub}, {algHS384, mac, hmacPub}, {algHS512, mac, hmacPub},
		{algRS256, priv, rsaPub}, {algRS384, priv, rsaPub}, {algRS512, priv, rsaPub},
		{algPS256, priv, rsaPub}, {algPS384, priv, rsaPub}, {algPS512, priv, rsaPub},
	}
}

// Literals of the verification tests: the rounds a verification repeats, a
// byte a digest keeps before it and the sign bit of a DER integer.
const (
	verifyRounds = 3
	prefixByte   = 7
	signBit      = 0x80
)

func TestVerifySignature(t *testing.T) {
	for _, tc := range verifyCases(t) {
		alg := mustAlgorithm(t, tc.algName)
		sig := signInput(t, tc.algName, tc.signer, testInput)
		if err := verifySignature(tc.verifier, alg, []byte(testInput), sig, verifyRoom()); err != nil {
			t.Errorf("verifySignature(%s, verifyRoom()) = %v, want nil", tc.algName, err)
		}
		if err := verifySignature(tc.verifier, alg, []byte(testInput+"x"), sig, verifyRoom()); !errors.Is(err,
			errSignature) {
			t.Errorf("verifySignature(%s, other input, verifyRoom()) = %v, want errSignature", tc.algName, err)
		}
		if len(sig) == 0 {
			t.Fatalf("signInput(%s) = empty, want a signature", tc.algName)
		}
		sig[len(sig)/2] ^= 1
		err := verifySignature(tc.verifier, alg, []byte(testInput), sig, verifyRoom())
		if !errors.Is(err, errSignature) {
			t.Errorf("verifySignature(%s, altered signature, verifyRoom()) = %v, want errSignature", tc.algName, err)
		}
	}
}

func TestVerifySignatureCrossAlgorithm(t *testing.T) {
	cases := verifyCases(t)
	for _, signed := range cases {
		sig := signInput(t, signed.algName, signed.signer, testInput)
		for _, claimed := range cases {
			if claimed.algName == signed.algName {
				continue
			}
			alg := mustAlgorithm(t, claimed.algName)
			err := verifySignature(signed.verifier, alg, []byte(testInput), sig, verifyRoom())
			if !errors.Is(err, errSignature) {
				t.Errorf("verifySignature(%s signature as %s, verifyRoom()) = %v, want errSignature", signed.algName,
					claimed.algName, err)
			}
		}
	}
}

// TestVerifySignatureUnfitKey signs with each key type a signature that its
// verify accepts under an algorithm of another kind or curve, so only the fit
// check refuses it.
func TestVerifySignatureUnfitKey(t *testing.T) {
	priv, mac, ed := testRSAKey(), []byte(testLongSecret), mustEdKey(t)
	p256 := mustECKey(t, elliptic.P256())
	sum384 := sha512.Sum384([]byte(testInput))
	onP256, err := signRS(p256, sum384[:], sizeP384)
	if err != nil {
		t.Fatalf("signRS = %v, want a signature", err)
	}
	tests := []struct {
		key     verificationKey
		claimed string
		sig     []byte
	}{
		{newHMACKey(mac), algRS256, signInput(t, algHS256, mac, testInput)},
		{&rsaKey{rsaPub: &priv.PublicKey}, algHS256, signInput(t, algRS256, priv, testInput)},
		{&ecKey{ecPub: &p256.PublicKey, crv: crvP256}, algES384, onP256},
		{&edKey{edPub: ed25519.PublicKey(ed[ed25519.SeedSize:])}, algHS256, signInput(t, algEdDSA, ed, testInput)},
	}
	for _, tc := range tests {
		alg := mustAlgorithm(t, tc.claimed)
		if !tc.key.verify(alg, []byte(testInput), tc.sig, verifyRoom()) {
			t.Fatalf("%T.verify(%s, verifyRoom()) = false, want a signature only the fit check refuses", tc.key,
				tc.claimed)
		}
		if err := verifySignature(tc.key, alg, []byte(testInput), tc.sig, verifyRoom()); !errors.Is(err, errSignature) {
			t.Errorf("verifySignature(%T, %s, verifyRoom()) = %v, want errSignature", tc.key, tc.claimed, err)
		}
	}
}

func TestVerificationKeyFits(t *testing.T) {
	cases := verifyCases(t)
	for _, key := range cases {
		own := mustAlgorithm(t, key.algName)
		for _, other := range cases {
			alg := mustAlgorithm(t, other.algName)
			want := alg.kind == own.kind && alg.curve == own.curve
			if got := key.verifier.fits(alg); got != want {
				t.Errorf("fits(key of %s, %s) = %v, want %v", key.algName, alg.name, got, want)
			}
		}
	}
	if (&ecKey{crv: crvEd25519}).fits(mustAlgorithm(t, algEdDSA)) {
		t.Error("fits(EC key on Ed25519, EdDSA) = true, want false")
	}
}

func TestHMACKeyVerify(t *testing.T) {
	const input = "The quick brown fox jumps over the lazy dog"
	sig, err := hex.DecodeString("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
	if err != nil {
		t.Fatalf("DecodeString = %v, want the vector", err)
	}
	k := newHMACKey([]byte("key"))
	for i := range verifyRounds {
		if !k.verify(mustAlgorithm(t, algHS256), []byte(input), sig, verifyRoom()) {
			t.Fatalf("verify(HS256 test vector) #%d = false, want true", i)
		}
		if k.verify(mustAlgorithm(t, algHS384), []byte(input), sig, verifyRoom()) {
			t.Fatalf("verify(HS256 test vector as HS384) #%d = true, want false", i)
		}
	}
}

// TestHMACKeyVerifyAllocs pins the pooled MAC state and the caller's scratch:
// a verification allocates nothing.
func TestHMACKeyVerifyAllocs(t *testing.T) {
	k, alg, input, room := newHMACKey([]byte("key")), mustAlgorithm(t, algHS256), []byte(testInput), verifyRoom()
	mac := hmac.New(sha256.New, []byte("key"))
	_, _ = mac.Write(input)
	sig := mac.Sum(nil)
	assertAllocs(t, 0, func() {
		if !k.verify(alg, input, sig, room) {
			t.Fatal("verify = false, want true")
		}
	})
}

func TestNewHMACKey(t *testing.T) {
	secret := []byte(testWideSecret)
	k := newHMACKey(secret)
	for h, want := range map[crypto.Hash]*keyedmac.MAC{
		crypto.SHA256: k.sha256, crypto.SHA384: k.sha384, crypto.SHA512: k.sha512,
	} {
		mac := hmac.New(h.New, secret)
		_, _ = mac.Write([]byte(testInput))
		if got := k.mac(h); got != want || !bytes.Equal(got.Sum(nil, []byte(testInput)), mac.Sum(nil)) {
			t.Errorf("mac(%v) = %p, want %p, the HMAC of the secret under %v", h, got, want, h)
		}
	}
	if k.size != len(secret) {
		t.Fatalf("size = %d, want %d", k.size, len(secret))
	}
}

// TestHMACKeyFits binds each HMAC algorithm to a secret at least as long as
// its hash: 32, 48 or 64 bytes.
func TestHMACKeyFits(t *testing.T) {
	for size, fitting := range map[int][]string{
		sha256.Size - 1: nil, sha256.Size: {algHS256}, sha512.Size384 - 1: {algHS256}, sha512.Size384: {algHS256,
			algHS384},
		sha512.Size - 1: {algHS256, algHS384}, sha512.Size: {algHS256, algHS384, algHS512},
	} {
		k := newHMACKey(make([]byte, size))
		for _, name := range []string{algHS256, algHS384, algHS512, algRS256, algES256, algEdDSA} {
			alg, want := mustAlgorithm(t, name), slices.Contains(fitting, name)
			if fits, accepts := k.fits(alg), k.accepts(alg); fits != want || accepts != want {
				t.Errorf("%d-byte secret: fits(%s) = %v, accepts = %v, want %v", size, name, fits, accepts, want)
			}
		}
	}
}

func TestHMACKeyKey(t *testing.T) {
	k := newHMACKey([]byte(testLongSecret))
	if got, err := k.key(t.Context(), "any", algorithm{}, time.Unix(testUnix, 0)); got != k || err != nil {
		t.Fatalf("key = %v, %v, want the HMAC key itself", got, err)
	}
}

func TestRSAKeyVerify(t *testing.T) {
	priv := testRSAKey()
	k := &rsaKey{rsaPub: &priv.PublicKey}
	sum := sha256.Sum256([]byte(testInput))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	maxSalt, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, sum[:], opts)
	if err != nil {
		t.Fatalf("SignPSS = %v, want a signature", err)
	}
	ps256 := mustAlgorithm(t, algPS256)
	if k.verify(ps256, []byte(testInput), maxSalt, verifyRoom()) {
		t.Error("verify(PSS with a salt longer than the hash) = true, want false")
	}
	if !k.verify(ps256, []byte(testInput), signInput(t, algPS256, priv, testInput), verifyRoom()) {
		t.Error("verify(PSS with a hash-length salt) = false, want true")
	}
}

// TestRSAKeyVerifyScratch checks that verify leaves the digest of the input
// in the caller's room, for PKCS #1 v1.5 and PSS.
func TestRSAKeyVerifyScratch(t *testing.T) {
	priv := testRSAKey()
	k, input := &rsaKey{rsaPub: &priv.PublicKey}, []byte(testInput)
	sum := sha256.Sum256(input)
	for _, name := range []string{algRS256, algPS256} {
		room := verifyRoom()
		if !k.verify(mustAlgorithm(t, name), input, signInput(t, name, priv, testInput), room) {
			t.Fatalf("verify(%s) = false, want true", name)
		}
		if got := room[:sha256.Size]; !bytes.Equal(got, sum[:]) {
			t.Errorf("room after verify(%s) = %x, want the digest %x", name, got, sum)
		}
	}
}

func TestECKeyVerify(t *testing.T) {
	k256, k521 := mustECKey(t, elliptic.P256()), mustECKey(t, elliptic.P521())
	key256, key521 := &ecKey{ecPub: &k256.PublicKey, crv: crvP256}, &ecKey{ecPub: &k521.PublicKey, crv: crvP521}
	es256, es512 := mustAlgorithm(t, algES256), mustAlgorithm(t, algES512)
	sum := sha256.Sum256([]byte(testInput))
	der, err := ecdsa.SignASN1(rand.Reader, k256, sum[:])
	if err != nil {
		t.Fatalf("SignASN1 = %v, want a signature", err)
	}
	sig256, sig521 := signInput(t, algES256, k256, testInput), signInput(t, algES512, k521, testInput)
	input := []byte(testInput)
	if !key256.verify(es256, input, sig256, verifyRoom()) || !key521.verify(es512, input, sig521, verifyRoom()) {
		t.Fatal("verify(canonical R||S) = false, want true")
	}
	// padS inserts a zero byte before S, which keeps its value.
	padS := func(sig []byte) []byte { return slices.Concat(sig[:len(sig)/2], []byte{0}, sig[len(sig)/2:]) }
	for name, tc := range map[string]struct {
		key *ecKey
		alg algorithm
		sig []byte
	}{
		"DER":            {key256, es256, der},
		"short":          {key256, es256, []byte{1}},
		"empty":          {key256, es256, nil},
		"zero R and S":   {key256, es256, make([]byte, 64)},
		"S padded":       {key256, es256, padS(sig256)},
		"R padded":       {key256, es256, slices.Concat([]byte{0}, sig256)},
		"ES512 S padded": {key521, es512, padS(sig521)},
		"ES512 R padded": {key521, es512, slices.Concat([]byte{0}, sig521)},
	} {
		if tc.key.verify(tc.alg, []byte(testInput), tc.sig, verifyRoom()) {
			t.Errorf("verify(%s) = true, want false", name)
		}
	}
}

// TestECKeyVerifyScratch checks that verify leaves the digest of the input
// in the caller's room and the DER signature of R||S after it.
func TestECKeyVerifyScratch(t *testing.T) {
	priv := mustECKey(t, elliptic.P256())
	k, alg := &ecKey{ecPub: &priv.PublicKey, crv: crvP256}, mustAlgorithm(t, algES256)
	input, sig, room := []byte(testInput), signInput(t, algES256, priv, testInput), verifyRoom()
	if len(sig) != 2*sizeP256 || !k.verify(alg, input, sig, room) {
		t.Fatalf("verify(ES256 signature of %d bytes) = false, want true", len(sig))
	}
	sum := sha256.Sum256(input)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:sizeP256]),
		new(big.Int).SetBytes(sig[sizeP256:])})
	got := room[:cap(room)]
	if err != nil || !bytes.Equal(got[:sha256.Size], sum[:]) || !bytes.Contains(got[sha256.Size:], der) {
		t.Errorf("room after verify = %x, want the digest %x, then the DER signature %x (%v)", got, sum, der, err)
	}
}

func TestEdKeyVerify(t *testing.T) {
	ed := mustEdKey(t)
	k := &edKey{edPub: ed25519.PublicKey(ed[ed25519.SeedSize:])}
	alg, sig := mustAlgorithm(t, algEdDSA), signInput(t, algEdDSA, ed, testInput)
	verified := []bool{k.verify(alg, []byte(testInput), sig, verifyRoom()),
		k.verify(alg, []byte("x"), sig, verifyRoom())}
	if !slices.Equal(verified, []bool{true, false}) {
		t.Fatalf("verify(signed input, other input) = %v, want [true false]", verified)
	}
}

func TestDigest(t *testing.T) {
	sum256, sum384, sum512 := sha256.Sum256([]byte(testInput)), sha512.Sum384([]byte(testInput)),
		sha512.Sum512([]byte(testInput))
	for h, want := range map[crypto.Hash][]byte{
		crypto.SHA256: sum256[:], crypto.SHA384: sum384[:], crypto.SHA512: sum512[:],
	} {
		dst := append(make([]byte, 0, 1+sha512.Size), prefixByte)
		if got := digest(h, []byte(testInput), dst); !bytes.Equal(got[1:], want) || got[0] != prefixByte ||
			&got[0] != &dst[0] {
			t.Errorf("digest(%v) = %x, want 07 then %x, appended in place", h, got, want)
		}
	}
}

// FuzzVerifySignature verifies input and signature bytes under every
// algorithm against the standard library alone: ECDSA through big.Int
// integers, HMAC through a fresh MAC and the others through their packages.
func FuzzVerifySignature(f *testing.F) {
	cases := verifyCases(f)
	for i, tc := range cases {
		sig := signInput(f, tc.algName, tc.signer, testInput)
		f.Add(uint8(i), []byte(testInput), sig)
		f.Add(uint8(i), []byte(testInput+"."), sig)
	}
	f.Fuzz(func(t *testing.T, pick uint8, input, sig []byte) {
		tc := cases[int(pick)%len(cases)]
		alg := mustAlgorithm(t, tc.algName)
		var want error
		if !referenceVerify(tc.signer, alg, input, sig) {
			want = errSignature
		}
		if got := verifySignature(tc.verifier, alg, input, sig, verifyRoom()); !errors.Is(got, want) {
			t.Fatalf("verifySignature(%s, %x, %x, verifyRoom()) = %v, want %v", tc.algName, input, sig, got, want)
		}
	})
}

// referenceVerify reports whether sig signs input under alg with the public
// half of signer, a signing key of verifyCases.
func referenceVerify(signer any, alg algorithm, input, sig []byte) bool {
	var sum []byte
	if alg.hash != 0 {
		h := alg.hash.New()
		_, _ = h.Write(input)
		sum = h.Sum(nil)
	}
	switch k := signer.(type) {
	case []byte:
		mac := hmac.New(alg.hash.New, k)
		_, _ = mac.Write(input)
		return hmac.Equal(sig, mac.Sum(nil))
	case *rsa.PrivateKey:
		if alg.pss {
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
			return rsa.VerifyPSS(&k.PublicKey, alg.hash, sum, sig, opts) == nil
		}
		return rsa.VerifyPKCS1v15(&k.PublicKey, alg.hash, sum, sig) == nil
	case *ecdsa.PrivateKey:
		r, s := new(big.Int).SetBytes(sig[:len(sig)/2]), new(big.Int).SetBytes(sig[len(sig)/2:])
		return len(sig) == 2*alg.size && ecdsa.Verify(&k.PublicKey, sum, r, s)
	case ed25519.PrivateKey:
		return ed25519.Verify(ed25519.PublicKey(k[ed25519.SeedSize:]), input, sig)
	}
	return false
}

func TestEncodeDER(t *testing.T) {
	ff := bytes.Repeat([]byte{0xFF}, sizeP521)
	// Bodies of 0x80 and 0x7F bytes: the shortest long-form and longest short-form length.
	b62, b61 := slices.Concat([]byte{0x7F}, ff[:61]), slices.Concat([]byte{0x7F}, ff[:60])
	for _, tc := range []struct{ r, s []byte }{
		{b62, b62},
		{b62, b61},
		{[]byte{0}, []byte{0}},
		{make([]byte, sizeP256), []byte{1}},
		{[]byte{0, 0, signBit - 1}, []byte{0, signBit}},
		{ff[:sizeP256], ff[:sizeP256]},
		{ff[:sizeP384], ff[:sizeP384]},
		{ff[:sizeP384], []byte{1}},
		{ff, ff},
		{slices.Concat([]byte{1}, ff[1:]), []byte{signBit}},
	} {
		want, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(tc.r), new(big.Int).SetBytes(tc.s)})
		room := make([]byte, 0, derSignatureSize)
		got := encodeDER(room, tc.r, tc.s)
		// A short-form header of two bytes starts one byte into the room.
		start := 1
		if err == nil && want[1] >= signBit {
			start = 0
		}
		if err != nil || !bytes.Equal(got, want) || &got[0] != &room[:derSignatureSize][start] {
			t.Errorf("encodeDER(%x, %x) = %x, want %x at %d in the room (%v)", tc.r, tc.s, got, want, start, err)
		}
	}
}

func FuzzEncodeDER(f *testing.F) {
	f.Add([]byte{0}, []byte{0x80})
	f.Add(bytes.Repeat([]byte{0xFF}, sizeP521), []byte{0, 0, 1})
	f.Fuzz(func(t *testing.T, r, s []byte) {
		if len(r) == 0 || len(r) > sizeP521 || len(s) == 0 || len(s) > sizeP521 {
			return
		}
		want, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)})
		if got := encodeDER(make([]byte, 0, derSignatureSize), r, s); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encodeDER(%x, %x) = %x, want %x (%v)", r, s, got, want, err)
		}
	})
}
