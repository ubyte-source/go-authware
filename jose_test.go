package authware

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The coordinate sizes of the curves, and where a line break splits a
// signature.
const (
	p256Bytes = 32
	p384Bytes = 48
	p521Bytes = 66
	breakAt   = 4
)

func TestKeyKindZeroFitsNoKey(t *testing.T) {
	for _, key := range []verificationKey{&rsaKey{}, &ecKey{}, &edKey{}, &hmacKey{}} {
		if key.fits(algorithm{}) {
			t.Errorf("%T fits the zero algorithm, want no key to", key)
		}
	}
}

func TestLookupAlgorithm(t *testing.T) {
	for _, want := range []algorithm{
		{name: algRS256, kind: kindRSA, hash: crypto.SHA256},
		{name: algRS384, kind: kindRSA, hash: crypto.SHA384},
		{name: algRS512, kind: kindRSA, hash: crypto.SHA512},
		{name: algPS256, kind: kindRSA, hash: crypto.SHA256, pss: true},
		{name: algPS384, kind: kindRSA, hash: crypto.SHA384, pss: true},
		{name: algPS512, kind: kindRSA, hash: crypto.SHA512, pss: true},
		{name: algES256, kind: kindEC, curve: crvP256, size: p256Bytes, hash: crypto.SHA256},
		{name: algES384, kind: kindEC, curve: crvP384, size: p384Bytes, hash: crypto.SHA384},
		{name: algES512, kind: kindEC, curve: crvP521, size: p521Bytes, hash: crypto.SHA512},
		{name: algEdDSA, kind: kindOKP, curve: crvEd25519},
		{name: algHS256, kind: kindOct, hash: crypto.SHA256},
		{name: algHS384, kind: kindOct, hash: crypto.SHA384},
		{name: algHS512, kind: kindOct, hash: crypto.SHA512},
	} {
		if got, ok := lookupAlgorithm(want.name); !ok || got != want {
			t.Errorf("lookupAlgorithm(%q) = %+v, %v; want %+v", want.name, got, ok, want)
		}
	}
	for _, name := range []string{"", "none", "hs256", "HSxx6", "HS256 ", "RSA-OAEP", crvEd25519, "ES256K"} {
		if got, ok := lookupAlgorithm(name); ok || got != (algorithm{}) {
			t.Errorf("lookupAlgorithm(%q) = %+v, %v, want no algorithm", name, got, ok)
		}
	}
}

const hs256Header = `{"alg":"HS256"}`

// TestParseJWSSplitFailure refuses a token that is not three segments before
// decoding any of them.
func TestParseJWSSplitFailure(t *testing.T) {
	head := segment(hs256Header)
	for _, raw := range []string{head + jwsSeparator + segment(emptyObject), head + ".." + segment(emptyObject) + "."} {
		if tok, err := parseJWS(raw, new([]byte)); !reflect.ValueOf(tok).IsZero() || !errors.Is(err, errSegments) {
			t.Errorf("parseJWS(%q) = %+v, %v, want the zero token, errSegments", raw, tok, err)
		}
	}
}

func TestParseJWS(t *testing.T) {
	head, sig := segment(hs256Header), segment(strings.Repeat("s", p256Bytes))
	fill := func(size int) string {
		return head + jwsSeparator + strings.Repeat("A", size-len(head)-len(sig)-2) + jwsSeparator + sig
	}
	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"max size", fill(tokenLimit), nil},
		{"over max size", fill(tokenLimit + 1), errTokenTooLarge},
		{"one dot", head + jwsSeparator + segment(emptyObject), errMalformedToken},
		{"three dots", head + ".." + sig + jwsSeparator, errMalformedToken},
		{"line break", head + jwsSeparator + segment(emptyObject) + jwsSeparator + sig[:breakAt] + "\n" + sig[breakAt:],
			errSignatureEncoding},
		{"padding", head + jwsSeparator + segment(emptyObject) + jwsSeparator + sig + "=", errSignatureEncoding},
		{"std alphabet", head + jwsSeparator + segment(emptyObject) + ".ab+/", errMalformedToken},
		{"signature padding bits", head + jwsSeparator + segment(emptyObject) + ".AB", errMalformedToken},
		{"payload padding bits", head + ".AB." + sig, errPayloadEncoding},
		{"payload line break", head + ".e30\n." + sig, errPayloadEncoding},
		{"header padding", "e30=." + segment(emptyObject) + jwsSeparator + sig, errHeaderEncoding},
		{"empty header", jwsSeparator + segment(emptyObject) + jwsSeparator + sig, errMalformedToken},
		{"empty signature", head + jwsSeparator + segment(emptyObject) + jwsSeparator, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := parseJWS(tc.token, new([]byte))
			if !errors.Is(err, tc.want) {
				t.Fatalf("parseJWS = %v, want %v", err, tc.want)
			}
			if err != nil && !reflect.ValueOf(tok).IsZero() {
				t.Fatalf("parseJWS = %+v, %v, want the zero token with the error", tok, err)
			}
			refusal := (&oauthAuthenticator{}).tokenFailure
			if err != nil && !errors.Is(err, errTokenTooLarge) && refusal(err).msg != string(errMalformedToken) {
				t.Fatalf("parseJWS = %v, want a refusal the client reads as %q", err, errMalformedToken)
			}
			if err == nil {
				checkSegments(t, &tok, tc.token)
			}
		})
	}
}

// checkSegments fails t unless tok holds the decoded segments of raw, an HS256
// token.
func checkSegments(t *testing.T, tok *jws, raw string) {
	t.Helper()
	parts := strings.Split(raw, jwsSeparator)
	payload, perr := base64.RawURLEncoding.DecodeString(parts[1])
	signature, serr := base64.RawURLEncoding.DecodeString(parts[2])
	if perr != nil || serr != nil || string(tok.signingInput) != parts[0]+jwsSeparator+parts[1] ||
		tok.claims != string(payload) || !bytes.Equal(tok.signature, signature) || tok.header.alg.name != algHS256 {
		t.Fatalf("parseJWS = %+v, want the decoded segments of %q", tok, raw)
	}
}

// TestParseJWSBuffer decodes tokens of different sizes into one buffer: the
// signing input, the segments and the scratch sit back to back in its array,
// and the claims are a copy.
func TestParseJWSBuffer(t *testing.T) {
	mac := []byte(testLongSecret)
	long := signToken(t, algHS512, mac, "k", claimsWith(map[string]any{claimSub: strings.Repeat("u", 900)}))
	short := signToken(t, algHS256, mac, "", testClaims())
	buf := new([]byte)
	for _, raw := range []string{long, short, long} {
		tok, err := parseJWS(raw, buf)
		if err != nil {
			t.Fatalf("parseJWS(%.20q) = %v, want a token", raw, err)
		}
		checkBackToBack(t, raw, &tok, (*buf)[:cap(*buf)])
	}
	// A buffer that holds the input and the segments but not the scratch grows.
	*buf = make([]byte, 0, strings.LastIndexByte(short, '.')+len(short))
	tok, err := parseJWS(short, buf)
	if err != nil {
		t.Fatalf("parseJWS(%.20q) = %v, want a token", short, err)
	}
	checkBackToBack(t, short, &tok, (*buf)[:cap(*buf)])
}

// checkBackToBack requires tok, parsed from raw into whole, to hold the
// signing input, the signature and the scratch back to back in whole, and the
// claims as a copy that outlives a change of whole.
func checkBackToBack(t *testing.T, raw string, tok *jws, whole []byte) {
	t.Helper()
	parts := strings.Split(raw, jwsSeparator)
	header, herr := base64.RawURLEncoding.DecodeString(parts[0])
	payload, perr := base64.RawURLEncoding.DecodeString(parts[1])
	at := len(tok.signingInput) + len(header) + len(payload)
	if herr != nil || perr != nil || string(tok.signingInput) != parts[0]+jwsSeparator+parts[1] ||
		&tok.signingInput[0] != &whole[0] || &tok.signature[0] != &whole[at] {
		t.Fatalf("parseJWS(%.20q) = %+v, want the input and the segments back to back in the buffer", raw, tok)
	}
	if room := tok.scratch(); len(room) != 0 || cap(room) < verifyScratch ||
		&room[:1][0] != &whole[at+len(tok.signature)] {
		t.Fatalf("scratch = %d of %d bytes, want empty room of %d after the signature", len(room), cap(room),
			verifyScratch)
	}
	whole[at-1] ^= 1
	if tok.claims != string(payload) {
		t.Fatalf("claims after the buffer changed = %q, want the copy %q", tok.claims, payload)
	}
}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		header     string
		want       error
		kid        string
		accessType bool
	}{
		{`{"alg":"HS256"}`, nil, "", false},
		{`{"alg":"RS256","kid":"k` + escape('\u00e9') + `"}`, nil, "k\u00e9", false},
		{`{"alg":"ES256","typ":"JWT"}`, nil, "", false},
		{`{"alg":"ES256","typ":"jwt"}`, nil, "", false},
		{`{"alg":"ES256","typ":"at+jwt"}`, nil, "", true},
		{`{"alg":"ES256","typ":"AT+JWT"}`, nil, "", true},
		{`{"alg":"ES256","typ":"application/at+jwt"}`, nil, "", true},
		{`{"alg":"HS256","jku":"https://evil.example","x5u":"x","jwk":{},"x5c":[]}`, nil, "", false},
		{`{"alg":"ES256","typ":"application/jwt"}`, nil, "", false},
		{`{"alg":"ES256","typ":"Application/JWT"}`, nil, "", false},
		{`{"alg":"ES256","typ":"application/jose"}`, errTokenType, "", false},
		{`{"alg":"ES256","typ":"applİcation/jwt"}`, errTokenType, "", false},
		{`{"alg":"ES256","typ":"application/at+jwt+x"}`, errTokenType, "", false},
		{`{"alg":"ES256","typ":""}`, errTokenType, "", false},
		{`{"alg":"ES256","typ":1}`, errTypNotString, "", false},
		{`{"alg":"HS256","crit":[]}`, errCriticalHeader, "", false},
		{`{"alg":"HS256","crit":["exp"]}`, errCriticalHeader, "", false},
		{`{"alg":"HS256","crit":"x"}`, errCriticalHeader, "", false},
		{`{"crit":{},"alg":"HS256"}`, errCriticalHeader, "", false},
		{`{"alg":"none"}`, errUnsupportedAlg, "", false},
		{`{"alg":"HSxx6"}`, errUnsupportedAlg, "", false},
		{`{"kid":"k"}`, errMalformedToken, "", false},
		{`{"alg":5}`, errAlgNotString, "", false},
		{`{"alg":"HS256","kid":7}`, errKidNotString, "", false},
		{`{"alg":"HS256","alg":"HS256"}`, errHeaderShape, "", false},
		{`{"alg":"HS256","` + escape('a') + `lg":"none"}`, errHeaderShape, "", false},
		{`{"alg":"HS256"}x`, errHeaderShape, "", false},
		{`{"alg":"HS256"`, errHeaderShape, "", false},
		{`["alg","HS256"]`, errHeaderShape, "", false},
		{`{"alg":"HS256","kid":"` + "\xff" + `"}`, errHeaderShape, "", false},
	}
	for _, tc := range tests {
		h, err := parseHeader(tc.header)
		if !errors.Is(err, tc.want) {
			t.Errorf("parseHeader(%s) = %v, want %v", tc.header, err, tc.want)
			continue
		}
		if err != nil && h != (joseHeader{}) {
			t.Errorf("parseHeader(%s) = %+v, %v, want the zero header with the error", tc.header, h, err)
		}
		if err == nil && (h.kid != tc.kid || h.accessType != tc.accessType) {
			t.Errorf("parseHeader(%s) = %+v, want kid %q and access type %v", tc.header, h, tc.kid, tc.accessType)
		}
	}
	var h joseHeader
	assertAllocs(t, 0, func() {
		if err := h.setType(`"Application/AT+JWT"`); err != nil || !h.accessType {
			t.Fatalf("setType(Application/AT+JWT) = %v with access type %v, want nil and true", err, h.accessType)
		}
	})
}

// FuzzParseHeader checks every decoded header against referenceHeader: the
// alg, kid and access type of a header it accepts, else its refusal class.
func FuzzParseHeader(f *testing.F) {
	for _, s := range []string{
		`{"alg":"HS256"}`, `{"alg":"RS256","kid":"a","typ":"at+jwt"}`, `{"alg":"ES256","crit":[]}`,
		`{"alg":"EdDSA","typ":"JWT","x5u":"u"}`, `{"alg":"PS512","kid":"😀"}`, `{"typ":"x","alg":"HS256"}`,
		`{"crit":1,"alg":` + "\xff}", `{"alg":"none"}`, `{"alg":"ES256","typ":"applİcation/jwt"}`,
		`{"alg":"HS256","x":{"a":1,"a":1}}`, `{"alg":"HS256","x":1e400,"y":[{"a":-1E+999}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseHeader(string(data))
		want, wantErr := referenceHeader(string(data))
		got := referenceJOSE{algName: h.alg.name, kid: h.kid, accessType: h.accessType}
		if !errors.Is(err, wantErr) || (wantErr == nil) != (err == nil) || got != want {
			t.Fatalf("parseHeader(%q) = %+v, %v; want %+v, %v", data, got, err, want, wantErr)
		}
	})
}

// FuzzParseJWS checks every token against referenceJWS: the strict
// base64url segments and the header of a token it accepts, else its refusal
// class.
func FuzzParseJWS(f *testing.F) {
	f.Add(segment(`{"alg":"HS256"}`) + jwsSeparator + segment(`{}`) + jwsSeparator + segment("sig"))
	f.Add("a.b.c")
	f.Add(segment(`{"alg":"EdDSA"}`) + "..")
	f.Add(segment(`{"alg":"HS256","crit":[]}`) + ".e30.AB")
	f.Add(segment(`{"alg":"HS256","typ":"x"}`) + ".e30=.")
	f.Fuzz(func(t *testing.T, raw string) {
		tok, err := parseJWS(raw, new([]byte))
		want, wantErr := referenceJWS(raw)
		got := referenceToken{
			jose:   referenceJOSE{algName: tok.header.alg.name, kid: tok.header.kid, accessType: tok.header.accessType},
			claims: tok.claims, sigText: string(tok.signature), signedAs: string(tok.signingInput),
		}
		if !errors.Is(err, wantErr) || (wantErr == nil) != (err == nil) || got != want {
			t.Fatalf("parseJWS(%q) = %+v, %v; want %+v, %v", raw, got, err, want, wantErr)
		}
	})
}

func BenchmarkLookupAlgorithm(b *testing.B) {
	if a, ok := lookupAlgorithm(algHS512); !ok || a.name != algHS512 {
		b.Fatalf("lookupAlgorithm(%q) = %+v, %v, want %s", algHS512, a, ok, algHS512)
	}
	b.ReportAllocs()
	for b.Loop() {
		lookupAlgorithm(algHS512)
	}
}
