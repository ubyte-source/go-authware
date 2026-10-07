package authware

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"
)

const (
	ktyOct = "oct"
	kidR1  = "r1"
)

// Documented spellings of the JWK members that restrict a key's use.
const (
	testMemberUse    = "use"
	testMemberKeyOps = "key_ops"
)

// The RSA key sizes and the smallest public exponent a JWK may carry.
const (
	wantMinRSABits = 2048
	wantMaxRSABits = 8192
	wantMinE       = 3
)

// withMembers returns a copy of model with members replaced; a nil value
// removes the member.
func withMembers(model, members map[string]any) map[string]any {
	out := maps.Clone(model)
	for k, v := range members {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

func b64Int(v int64) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(v).Bytes())
}

// kindOf returns the key kind of the type of k, or none for another type.
func kindOf(k verificationKey) keyKind {
	switch k.(type) {
	case *rsaKey:
		return kindRSA
	case *ecKey:
		return kindEC
	case *edKey:
		return kindOKP
	case *hmacKey:
		return kindOct
	}
	return ""
}

func TestParseJWK(t *testing.T) {
	enc := base64.RawURLEncoding
	rsaJWK := publicJWK(t, testRSAKey(), map[string]any{memberKid: "r"})
	ecJWK := publicJWK(t, mustECKey(t, elliptic.P256()), nil)
	edJWK := publicJWK(t, mustEdKey(t), nil)
	tests := []struct {
		name    string
		members map[string]any
		kind    keyKind
	}{
		{"RSA", rsaJWK, kindRSA},
		{"RSA sig PS384", withMembers(rsaJWK, map[string]any{testMemberUse: "sig", memberAlg: algPS384}), kindRSA},
		{"key_ops verify", withMembers(rsaJWK, map[string]any{testMemberKeyOps: []string{"sign", opVerify}}), kindRSA},
		{"e 3", withMembers(rsaJWK, map[string]any{memberE: b64Int(3)}), kindRSA},
		{"e 2^31-1", withMembers(rsaJWK, map[string]any{memberE: b64Int(1<<31 - 1)}), kindRSA},
		{"2048 bits", withMembers(rsaJWK, map[string]any{memberN: enc.EncodeToString(bytes.Repeat([]byte{0xff}, 256))}),
			kindRSA},
		{"8192 bits", withMembers(rsaJWK, map[string]any{memberN: enc.EncodeToString(bytes.Repeat([]byte{0xff},
			1024))}),
			kindRSA},
		{"RSA with crv", withMembers(rsaJWK, map[string]any{memberCrv: crvP256, memberAlg: algRS256}), kindRSA},
		{"extra members", withMembers(rsaJWK, map[string]any{"x5c": []string{"ignored"}, "ext": true}), kindRSA},
		{"EC", ecJWK, kindEC},
		{"EC ES256", withMembers(ecJWK, map[string]any{memberAlg: algES256}), kindEC},
		{"OKP", edJWK, kindOKP},
		{"OKP EdDSA", withMembers(edJWK, map[string]any{memberAlg: algEdDSA}), kindOKP},
	}
	for _, tc := range tests {
		k, err := parseJWK(mustJSON(t, tc.members))
		if err != nil || kindOf(k.key) != tc.kind || k.kid != stringMember(tc.members, memberKid) ||
			k.algName != stringMember(tc.members, memberAlg) {
			t.Errorf("%s: parseJWK = %+v, %v, want a key of kind %s", tc.name, k, err, tc.kind)
		}
	}
}

func TestParseJWKRejects(t *testing.T) {
	enc := base64.RawURLEncoding
	rsaJWK := publicJWK(t, testRSAKey(), nil)
	ecPriv := mustECKey(t, elliptic.P256())
	ecJWK := publicJWK(t, ecPriv, nil)
	point, err := ecPriv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("Bytes = %v, want the point", err)
	}
	edJWK := publicJWK(t, mustEdKey(t), nil)
	uneven := []string{enc.EncodeToString(point[1:32]), enc.EncodeToString(point[32:])}
	over := make([]byte, 1024)
	tests := []struct {
		name    string
		members map[string]any
	}{
		{"use enc", withMembers(rsaJWK, map[string]any{testMemberUse: "enc"})},
		{"use empty", withMembers(rsaJWK, map[string]any{testMemberUse: ""})},
		{"use number", withMembers(rsaJWK, map[string]any{testMemberUse: 1})},
		{"key_ops encrypt", withMembers(rsaJWK, map[string]any{testMemberKeyOps: []string{"encrypt"}})},
		{"key_ops empty", withMembers(rsaJWK, map[string]any{testMemberKeyOps: []string{}})},
		{"key_ops string", withMembers(rsaJWK, map[string]any{testMemberKeyOps: opVerify})},
		{"key_ops number", withMembers(rsaJWK, map[string]any{testMemberKeyOps: []any{opVerify, 1}})},
		{"RSA ES256", withMembers(rsaJWK, map[string]any{memberAlg: algES256})},
		{"RSA HS256", withMembers(rsaJWK, map[string]any{memberAlg: algHS256})},
		{"RSA-OAEP", withMembers(rsaJWK, map[string]any{memberAlg: "RSA-OAEP"})},
		{"2047 bits", withMembers(rsaJWK, map[string]any{
			memberN: enc.EncodeToString(slices.Concat([]byte{0x7f}, bytes.Repeat([]byte{0xff}, 255))),
		})},
		{"8193 bits", withMembers(rsaJWK, map[string]any{memberN: enc.EncodeToString(slices.Concat([]byte{1}, over))})},
		{"e 1", withMembers(rsaJWK, map[string]any{memberE: b64Int(1)})},
		{"e even", withMembers(rsaJWK, map[string]any{memberE: b64Int(65536)})},
		{"e 2^31+1", withMembers(rsaJWK, map[string]any{memberE: b64Int(1<<31 + 1)})},
		{"e empty", withMembers(rsaJWK, map[string]any{memberE: ""})},
		{"n number", withMembers(rsaJWK, map[string]any{memberN: 5})},
		{"n padded", withMembers(rsaJWK, map[string]any{memberN: stringMember(rsaJWK, memberN) + "="})},
		{"e padded", withMembers(rsaJWK, map[string]any{memberE: "AQAB="})},
		{"no kty", withMembers(rsaJWK, map[string]any{testMemberKty: nil})},
		{"symmetric", withMembers(rsaJWK, map[string]any{testMemberKty: ktyOct, "k": "c2VjcmV0"})},
		{"P-256 ES384", withMembers(ecJWK, map[string]any{memberAlg: algES384})},
		{"wrong curve", withMembers(ecJWK, map[string]any{memberCrv: crvP384})},
		{"secp256k1", withMembers(ecJWK, map[string]any{memberCrv: "secp256k1"})},
		{"coordinates split unevenly", withMembers(ecJWK, map[string]any{memberX: uneven[0], "y": uneven[1]})},
		{"x padded", withMembers(ecJWK, map[string]any{memberX: stringMember(ecJWK, memberX) + "="})},
		{"y padded", withMembers(ecJWK, map[string]any{memberY: stringMember(ecJWK, memberY) + "="})},
		{"off curve", withMembers(ecJWK, map[string]any{memberY: ecJWK[memberX]})},
		{"Ed448", withMembers(edJWK, map[string]any{memberCrv: "Ed448"})},
		{"Ed25519 31 bytes", withMembers(edJWK, map[string]any{memberX: enc.EncodeToString(make([]byte, 31))})},
		{"Ed25519 padded", withMembers(edJWK, map[string]any{memberX: stringMember(edJWK, memberX) + "="})},
		{"OKP ES256", withMembers(edJWK, map[string]any{memberAlg: algES256})},
	}
	for _, tc := range tests {
		if k, err := parseJWK(mustJSON(t, tc.members)); k != nil || !errors.Is(err, errUnusableKey) {
			t.Errorf("%s: parseJWK = %+v, %v, want nil, errUnusableKey", tc.name, k, err)
		}
	}
}

// TestParseJWKNamesTheFault reports the member that makes a key unusable.
func TestParseJWKNamesTheFault(t *testing.T) {
	rsaJWK := publicJWK(t, testRSAKey(), nil)
	ecJWK := publicJWK(t, mustECKey(t, elliptic.P256()), nil)
	edJWK := publicJWK(t, mustEdKey(t), nil)
	padded := func(key map[string]any, member string) map[string]any {
		return withMembers(key, map[string]any{member: stringMember(key, member) + "="})
	}
	for _, tc := range []struct {
		members map[string]any
		want    string
		refusal error // the refusal built once, or errUnusableKey for a text built per call
	}{
		{padded(rsaJWK, memberN), "unusable JWK: parameter n is not base64url", errParamN},
		{padded(rsaJWK, memberE), "unusable JWK: parameter e is not base64url", errParamE},
		{withMembers(rsaJWK, map[string]any{memberN: 5}), "unusable JWK: n is not a string", errUnusableKey},
		{padded(ecJWK, memberX), "unusable JWK: parameter x is not base64url", errParamX},
		{padded(ecJWK, memberY), "unusable JWK: parameter y is not base64url", errParamY},
		{padded(edJWK, memberX), "unusable JWK: parameter x is not base64url", errParamX},
	} {
		k, err := parseJWK(mustJSON(t, tc.members))
		if k != nil || !errors.Is(err, errUnusableKey) || !errors.Is(err, tc.refusal) || err.Error() != tc.want {
			t.Errorf("parseJWK = %+v, %v, want nil, %q", k, err, tc.want)
		}
	}
	for doc, tc := range map[string]struct {
		want    string
		refusal error // the refusal built once, which wraps errInvalidJWKS
	}{
		`{"keys":[],"keys":[]}`: {"invalid JWKS: not one UTF-8 JSON object nested at most 32 deep in which no " +
			"object repeats a name", errJWKSShape},
		`{"keys":"x"}`: {"invalid JWKS: keys is not an array", errKeysNotArray},
	} {
		if set, err := parseJWKS(doc); set != nil || !errors.Is(err, tc.refusal) || err.Error() != tc.want {
			t.Errorf("parseJWKS(%s) = %+v, %v, want nil, %q", doc, set, err, tc.want)
		}
	}
}

// TestParseECKeyKeepsTheCurveFault keeps the reason the curve refuses a point
// off it as an error beside errUnusableKey.
func TestParseECKeyKeepsTheCurveFault(t *testing.T) {
	one := make([]byte, sizeP256)
	one[len(one)-1] = 1
	_, cause := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, one, one))
	coordinate := base64.RawURLEncoding.EncodeToString(one)
	k, err := parseECKey(crvP256, coordinate, coordinate)
	var tree interface{ Unwrap() []error }
	if cause == nil || k != nil || !errors.Is(err, errUnusableKey) || !errors.As(err, &tree) ||
		!slices.ContainsFunc(tree.Unwrap(), func(e error) bool { return e.Error() == cause.Error() }) {
		t.Fatalf("parseECKey(the point 1,1) = %v, %v, want nil, errUnusableKey and %v", k, err, cause)
	}
}

func TestParseECKeyRejects(t *testing.T) {
	full := base64.RawURLEncoding.EncodeToString(make([]byte, sizeP256))
	short := base64.RawURLEncoding.EncodeToString(make([]byte, sizeP256-1))
	for _, tc := range []struct{ crv, x, y string }{
		{"P-192", full, full}, {crvP256, "%", full}, {crvP256, full, "%"}, {crvP256, full, short},
	} {
		if k, err := parseECKey(tc.crv, tc.x, tc.y); k != nil || !errors.Is(err, errUnusableKey) {
			t.Errorf("parseECKey(%s, %s, %s) = %v, %v, want nil, errUnusableKey", tc.crv, tc.x, tc.y, k, err)
		}
	}
}

func TestParseJWKMalformed(t *testing.T) {
	n := stringMember(publicJWK(t, testRSAKey(), nil), memberN)
	for _, doc := range []string{
		`{"kty":"RSA","kty":"EC","n":"` + n + `","e":"AQAB"}`,
		`{"kty":"RSA","n":"` + n + `","e":"AQAB"} x`,
		`"RSA"`,
	} {
		if k, err := parseJWK(doc); k != nil || !errors.Is(err, errUnusableKey) {
			t.Errorf("parseJWK(%.30s) = %+v, %v, want nil, errUnusableKey", doc, k, err)
		}
	}
}

func TestParseJWKKeys(t *testing.T) {
	rsaPriv, ecPriv, edPriv := testRSAKey(), mustECKey(t, elliptic.P384()), mustEdKey(t)
	for _, tc := range []struct {
		priv any
		want func(verificationKey) bool
	}{
		{rsaPriv, func(k verificationKey) bool {
			p, ok := k.(*rsaKey)
			return ok && p.rsaPub.Equal(&rsaPriv.PublicKey)
		}},
		{ecPriv, func(k verificationKey) bool {
			p, ok := k.(*ecKey)
			return ok && p.ecPub.Equal(&ecPriv.PublicKey) && p.crv == crvP384
		}},
		{edPriv, func(k verificationKey) bool { p, ok := k.(*edKey); return ok && p.edPub.Equal(edPriv.Public()) }},
	} {
		k, err := parseJWK(mustJSON(t, publicJWK(t, tc.priv, nil)))
		if err != nil || !tc.want(k.key) {
			t.Errorf("parseJWK(%T) = %+v, %v, want its public key", tc.priv, k, err)
		}
	}
}

func TestCheckOps(t *testing.T) {
	for _, raw := range []string{`["` + escape('v') + `erify"]`, `["sign","verify"]`, `["verify","sign"]`} {
		if err := checkOps(raw); err != nil {
			t.Errorf("checkOps(%s) = %v, want nil", raw, err)
		}
	}
	const notArray, noVerify = "key_ops is not an array of strings", "key_ops without verify"
	once := map[string]error{notArray: errKeyOpsNotStrings, noVerify: errKeyOpsNoVerify}
	for raw, reason := range map[string]string{
		`"verify"`: notArray, `["verify",1]`: notArray, `[1,"verify"]`: notArray, jsonNull: notArray,
		`[ ]`: noVerify, `["sign"]`: noVerify, `["verif"]`: noVerify, `["verify "]`: noVerify,
	} {
		if err := checkOps(raw); err == nil || !errors.Is(err, once[reason]) || !errors.Is(err, errUnusableKey) ||
			!strings.HasSuffix(err.Error(), reason) {
			t.Errorf("checkOps(%s) = %v, want errUnusableKey: %s, built once", raw, err, reason)
		}
	}
}

// edJWKAllocs is what parsing an Ed25519 JWK without kid and alg costs.
const edJWKAllocs = 3

// TestParseJWKCopiesKidAndAlg parses one Ed25519 key with and without kid and
// alg: the two copies that free the JWKS are the only difference.
func TestParseJWKCopiesKidAndAlg(t *testing.T) {
	ed := mustEdKey(t)
	bare := mustJSON(t, publicJWK(t, ed, nil))
	named := mustJSON(t, publicJWK(t, ed, map[string]any{memberKid: "a key id of 24 bytes..", memberAlg: algEdDSA}))
	for doc, want := range map[string]float64{bare: edJWKAllocs, named: edJWKAllocs + 2} {
		assertAllocs(t, want, func() {
			if _, err := parseJWK(doc); err != nil {
				t.Fatalf("parseJWK(%s) = %v, want a key", doc, err)
			}
		})
	}
}

func TestParseJWKS(t *testing.T) {
	good := publicJWK(t, testRSAKey(), map[string]any{memberKid: "a"})
	second := publicJWK(t, mustEdKey(t), nil)
	enc := withMembers(good, map[string]any{testMemberUse: "enc"})
	set, err := parseJWKS(string(jwksDocument(t, enc, good, map[string]any{testMemberKty: ktyOct}, second)))
	if err != nil || len(set.keys) != 2 || kindOf(set.keys[0].key) != kindRSA || kindOf(set.keys[1].key) != kindOKP ||
		len(set.byKid["a"]) != 1 || set.byKid["a"][0] != set.keys[0] || len(set.byKid) != 1 {
		t.Fatalf("parseJWKS = %+v, %v, want the RSA key under kid a and the OKP key", set, err)
	}
}

func TestParseJWKSInvalid(t *testing.T) {
	good := publicJWK(t, testRSAKey(), nil)
	encKey := withMembers(good, map[string]any{testMemberUse: "enc"})
	set, err := parseJWKS(string(jwksDocument(t, encKey, map[string]any{testMemberKty: ktyOct})))
	if set != nil || !errors.Is(err, errNoUsableKey) || !errors.Is(err, errInvalidJWKS) ||
		!errors.Is(err, errUnusableKey) {
		t.Errorf("parseJWKS(no usable key) = %+v, %v, want nil, errInvalidJWKS joining errUnusableKey", set, err)
	}
	for _, doc := range []string{
		`{}`, `{"keys":{}}`, `{"keys":"x"}`, jsonEmptyArray, `{"keys":[]}`, `{"keys":[]} x`, `{"keys":[],"keys":[]}`,
		`{"keys":[` + mustJSON(t, good) + `}`,
	} {
		if set, err := parseJWKS(doc); set != nil || !errors.Is(err, errInvalidJWKS) {
			t.Errorf("parseJWKS(%.40s) = %+v, %v, want nil, errInvalidJWKS", doc, set, err)
		}
	}
}

func TestJWKSetMatch(t *testing.T) {
	rsa1 := publicJWK(t, testRSAKey(), map[string]any{memberKid: kidR1})
	rsa2 := publicJWK(t, testRSAKey2(), map[string]any{memberKid: "r2", memberAlg: algRS256})
	ec := publicJWK(t, mustECKey(t, elliptic.P384()), map[string]any{memberKid: "e"})
	noKid := publicJWK(t, mustEdKey(t), nil)
	twin := withMembers(rsa2, map[string]any{memberKid: kidR1, memberAlg: nil})
	tests := []struct {
		keys []map[string]any
		kid  string
		alg  string
		want error
		pick int
	}{
		{[]map[string]any{rsa1, rsa2}, kidR1, algRS256, nil, 0},
		{[]map[string]any{rsa1, rsa2}, "r2", algRS256, nil, 1},
		{[]map[string]any{rsa1, rsa2}, kidR1, algPS512, nil, 0},
		{[]map[string]any{rsa1, rsa2}, "r2", algPS256, errNoKey, 0},
		{[]map[string]any{rsa1, rsa2}, "r3", algRS256, errNoKey, 0},
		{[]map[string]any{rsa1, ec}, "e", algES256, errNoKey, 0},
		{[]map[string]any{rsa1, ec}, "e", algES384, nil, 1},
		{[]map[string]any{rsa1, ec}, kidR1, algES384, errNoKey, 0},
		{[]map[string]any{rsa1, ec, noKid}, "", algES384, nil, 1},
		{[]map[string]any{rsa1, ec, noKid}, "", algEdDSA, nil, 2},
		{[]map[string]any{rsa1, ec, noKid}, "x", algEdDSA, errNoKey, 0},
		{[]map[string]any{rsa1, rsa2}, "", algRS256, errAmbiguousKey, 0},
		{[]map[string]any{rsa1, rsa2}, "", algRS384, nil, 0},
		{[]map[string]any{rsa1, twin}, kidR1, algRS256, errAmbiguousKey, 0},
	}
	for _, tc := range tests {
		set, err := parseJWKS(string(jwksDocument(t, tc.keys...)))
		if err != nil {
			t.Fatalf("parseJWKS = %v, want a set", err)
		}
		var want verificationKey
		if tc.want == nil {
			want = set.keys[tc.pick].key
		}
		if k, err := set.match(tc.kid, mustAlgorithm(t, tc.alg)); !errors.Is(err, tc.want) || k != want {
			t.Errorf("match(%q, %s) = %+v, %v; want %+v, %v", tc.kid, tc.alg, k, err, want, tc.want)
		}
	}
}

func TestKeyParam(t *testing.T) {
	tests := []struct {
		value string
		want  []byte
		err   error
	}{
		{"AQAB", []byte{1, 0, 1}, nil},
		{"", []byte{}, nil},
		{"AQAB=", nil, errUnusableKey},
		{"AQ+B", nil, errUnusableKey},
		{"AB", nil, errUnusableKey},
	}
	for _, tc := range tests {
		got, err := keyParam(tc.value, errParamN)
		if !errors.Is(err, tc.err) || tc.err != nil && !errors.Is(err, errParamN) || !bytes.Equal(got, tc.want) {
			t.Errorf("keyParam(%q) = %x, %v; want %x, %v", tc.value, got, err, tc.want, tc.err)
		}
	}
}

// stringMember returns the named member of m when it is a string.
func stringMember(m map[string]any, name string) string {
	if s, ok := m[name].(string); ok {
		return s
	}
	return ""
}

// referenceJWK is the kid and alg of a JWK that parseJWKS must keep.
type referenceJWK struct {
	kid, algName string
}

// FuzzParseJWKS checks every document against referenceJWKS: the keys of a
// set it keeps, in order with their kid and alg, else errInvalidJWKS.
func FuzzParseJWKS(f *testing.F) {
	f.Add(string(jwksDocument(f, publicJWK(f, testRSAKey(), map[string]any{memberKid: "a", memberAlg: algRS256}))))
	f.Add(string(jwksDocument(f, publicJWK(f, mustECKey(f, elliptic.P256()), map[string]any{testMemberUse: "sig"}))))
	f.Add(string(jwksDocument(f, publicJWK(f, mustEdKey(f), map[string]any{testMemberKeyOps: []string{opVerify}}))))
	f.Add(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + strings.Repeat("A", 43) + `"}],"KEYS":[]}`)
	f.Add(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","x":"` + strings.Repeat("A", 43) + `"},` +
		`{"kty":"OKP","crv":"Ed25519","kid":"a","alg":"ES256","x":"` + strings.Repeat("A", 43) + `"}]}`)
	f.Add(`{"keys":[{"kty":"OKP","kty":"RSA"}],"x":` + "\"\\udc00\"}")
	f.Add(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + strings.Repeat("A", 43) + `"},{"":"","":""}]}`)
	f.Add(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + strings.Repeat("A", 43) + `"}],` +
		`"x":1e400,"y":[{"a":-1E+999}]}`)
	f.Fuzz(func(t *testing.T, doc string) {
		set, err := parseJWKS(doc)
		want, usable := referenceJWKS(doc)
		if !usable {
			if set != nil || !errors.Is(err, errInvalidJWKS) {
				t.Fatalf("parseJWKS(%q) = %+v, %v; want errInvalidJWKS", doc, set, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("parseJWKS(%q) = %v, want the keys %+v", doc, err, want)
		}
		checkKeptKeys(t, set, want)
	})
}

// referenceJWKS returns the kid and alg of each key of doc that referenceKey
// finds usable, and false for a doc that is no strict JSON object, whose keys
// is no array, or that holds no usable key.
func referenceJWKS(doc string) ([]referenceJWK, bool) {
	var keys json.RawMessage
	err := strictMembers(doc, func(name string, value json.RawMessage) error {
		if name == "keys" {
			keys = value
		}
		return nil
	})
	var elems []json.RawMessage
	if err != nil || !opens(keys, '[') || json.Unmarshal(keys, &elems) != nil {
		return nil, false
	}
	var want []referenceJWK
	for _, raw := range elems {
		if k, usable := referenceKey(raw); usable {
			want = append(want, k)
		}
	}
	return want, len(want) > 0
}

// checkKeptKeys requires set to keep exactly the keys of want, in document
// order with their kid and alg, each usable and indexed by its kid.
func checkKeptKeys(t *testing.T, set *jwkSet, want []referenceJWK) {
	t.Helper()
	if len(set.keys) != len(want) || len(want) == 0 {
		t.Fatalf("parseJWKS kept %d keys, want %d", len(set.keys), len(want))
	}
	named := 0
	for i, k := range set.keys {
		checkUsableKey(t, k)
		if k.kid != want[i].kid || k.algName != want[i].algName ||
			k.kid != "" && !slices.Contains(set.byKid[k.kid], k) {
			t.Fatalf("parseJWKS key %d = %+v, want kid %q, alg %q, indexed by its kid", i, k, want[i].kid,
				want[i].algName)
		}
		if k.kid != "" {
			named++
		}
	}
	if indexed := indexedKeys(set); indexed != named {
		t.Fatalf("parseJWKS indexed %d keys by kid, want %d", indexed, named)
	}
}

// indexedKeys counts the keys set indexes by kid.
func indexedKeys(set *jwkSet) int {
	n := 0
	for _, byKid := range set.byKid {
		n += len(byKid)
	}
	return n
}

// referenceKey reports, through encoding/json and crypto, whether parseJWKS
// must keep the JWK raw, and its kid and alg.
func referenceKey(raw json.RawMessage) (referenceJWK, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || !referenceUse(m) {
		return referenceJWK{}, false
	}
	str, ok := referenceStrings(m)
	if !ok {
		return referenceJWK{}, false
	}
	kind, crv, ok := referenceMaterial(str)
	if alg := str[memberAlg]; !ok || alg != "" && !referenceFits(alg, kind, crv) {
		return referenceJWK{}, false
	}
	return referenceJWK{kid: str[memberKid], algName: str[memberAlg]}, true
}

// referenceStrings decodes the members of m that verification reads, each a
// JSON string when present.
func referenceStrings(m map[string]json.RawMessage) (map[string]string, bool) {
	str := make(map[string]string)
	for _, name := range []string{testMemberKty, memberKid, memberAlg, memberCrv, memberN, memberE, memberX, memberY} {
		v, present := m[name]
		if !present {
			continue
		}
		var decoded string
		if !opens(v, '"') || json.Unmarshal(v, &decoded) != nil {
			return nil, false
		}
		str[name] = decoded
	}
	return str, true
}

// referenceUse reports whether use, when present, is sig and key_ops, when
// present, an array of strings holding verify.
func referenceUse(m map[string]json.RawMessage) bool {
	var use string
	if v, present := m[testMemberUse]; present && (!opens(v, '"') || json.Unmarshal(v, &use) != nil || use != useSig) {
		return false
	}
	v, present := m[testMemberKeyOps]
	return !present || referenceOps(v)
}

// referenceOps reports whether v is an array of strings holding verify.
func referenceOps(v json.RawMessage) bool {
	var elems []json.RawMessage
	if !opens(v, '[') || json.Unmarshal(v, &elems) != nil {
		return false
	}
	verify := false
	for _, e := range elems {
		var op string
		if !opens(e, '"') || json.Unmarshal(e, &op) != nil {
			return false
		}
		verify = verify || op == opVerify
	}
	return verify
}

// opens reports whether the JSON value v starts with c: a string for '"', an
// array for '['.
func opens(v json.RawMessage, c byte) bool { return len(v) > 0 && v[0] == c }

// referenceMaterial returns the kind and curve of the key material in str
// when crypto accepts it within the JWK rules.
func referenceMaterial(str map[string]string) (keyKind, string, bool) {
	switch str[testMemberKty] {
	case "RSA":
		return kindRSA, "", referenceRSA(str)
	case "EC":
		return kindEC, str[memberCrv], referenceEC(str)
	case "OKP":
		x, ok := referenceParam(str[memberX])
		return kindOKP, crvEd25519, str[memberCrv] == crvEd25519 && ok && len(x) == ed25519.PublicKeySize
	}
	return "", "", false
}

// referenceParam decodes a key parameter in strict base64url on one line.
func referenceParam(value string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return b, err == nil && !strings.ContainsAny(value, "\r\n")
}

// referenceRSA reports whether str holds a modulus of 2048 to 8192 bits and
// an odd exponent from 3 to 2^31-1.
func referenceRSA(str map[string]string) bool {
	n, okN := referenceParam(str[memberN])
	e, okE := referenceParam(str[memberE])
	modulus, exponent := new(big.Int).SetBytes(n), new(big.Int).SetBytes(e)
	bits := modulus.BitLen()
	return okN && okE && bits >= wantMinRSABits && bits <= wantMaxRSABits && exponent.Cmp(big.NewInt(wantMinE)) >= 0 &&
		exponent.Cmp(big.NewInt(1<<31-1)) <= 0 && exponent.Bit(0) == 1
}

// referenceEC reports whether str holds a point of equal-length coordinates
// on its NIST curve.
func referenceEC(str map[string]string) bool {
	curves := map[string]elliptic.Curve{crvP256: elliptic.P256(), crvP384: elliptic.P384(), crvP521: elliptic.P521()}
	curve, known := curves[str[memberCrv]]
	x, okX := referenceParam(str[memberX])
	y, okY := referenceParam(str[memberY])
	if !known || !okX || !okY || len(x) != len(y) {
		return false
	}
	_, err := ecdsa.ParseUncompressedPublicKey(curve, slices.Concat([]byte{4}, x, y))
	return err == nil
}

// referenceFits reports whether the JWS alg verifies with a key of kind on
// crv.
func referenceFits(alg string, kind keyKind, crv string) bool {
	switch alg {
	case algRS256, algRS384, algRS512, algPS256, algPS384, algPS512:
		return kind == kindRSA
	case algES256:
		return kind == kindEC && crv == crvP256
	case algES384:
		return kind == kindEC && crv == crvP384
	case algES512:
		return kind == kindEC && crv == crvP521
	case algEdDSA:
		return kind == kindOKP
	}
	return false
}

// checkUsableKey fails unless k is a key parseJWK may return.
func checkUsableKey(t *testing.T, k *jwk) {
	t.Helper()
	kind, crv, ok := usableKey(k.key)
	if !ok {
		t.Fatalf("parseJWKS key = %+v, want usable key material", k)
	}
	if k.algName != "" && !referenceFits(k.algName, kind, crv) {
		t.Fatalf("parseJWKS key = %+v, want an alg that fits its kind and curve", k)
	}
}

// usableKey returns the kind and curve of k when its material meets the
// JWK rules.
func usableKey(k verificationKey) (keyKind, string, bool) {
	switch key := k.(type) {
	case *rsaKey:
		bits := key.rsaPub.N.BitLen()
		return kindRSA, "", bits >= wantMinRSABits && bits <= wantMaxRSABits && key.rsaPub.E >= wantMinE &&
			key.rsaPub.E%2 == 1
	case *ecKey:
		return kindEC, key.crv, key.ecPub.Params().Name == key.crv && strings.HasPrefix(key.crv, "P-")
	case *edKey:
		return kindOKP, crvEd25519, len(key.edPub) == ed25519.PublicKeySize
	}
	return "", "", false
}
