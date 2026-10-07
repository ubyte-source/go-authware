package authware

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// verifiedTokenAllocs is what a verified token costs past pooled buffers, MAC
// states and cached keys: the header and claims text, the identity, its scopes.
const verifiedTokenAllocs = 3

// testInput is the signing input of the verification tests.
const testInput = "header.payload"

const jwsSeparator = "."

// The shortest PKCE verifier and the last success status.
const (
	minVerifier = 43
	lastSuccess = 299
)

// Leak check of TestMain: the module whose frames mark a goroutine as ours,
// the bytes of every stack it reads, how often it yields to goroutines that
// are ending, and the blank line between two stacks.
const (
	modulePath = "github.com/ubyte-source/go-authware/v2"
	stackBytes = 1 << 20
	leakRounds = 100
	stackGap   = "\n\n"
)

// TestMain runs the tests, then fails the run when a goroutine running code
// of this module outlives them.
func TestMain(m *testing.M) {
	code := m.Run()
	if stray := strayGoroutines(); code == 0 && stray != "" {
		code = 1
		if _, err := fmt.Fprintf(os.Stderr, "goroutines left by the tests:\n%s\n", stray); err != nil {
			code = 2
		}
	}
	os.Exit(code)
}

// strayGoroutines returns the stacks of the goroutines that run code of this
// module once those ending had leakRounds chances to finish, or "".
func strayGoroutines() string {
	stray := moduleStacks()
	for i := 0; i < leakRounds && stray != ""; i++ {
		runtime.Gosched()
		stray = moduleStacks()
	}
	return stray
}

// moduleStacks returns the stacks of the goroutines but the caller's whose
// frames name this module, or "".
func moduleStacks() string {
	buf := make([]byte, stackBytes)
	_, others, _ := strings.Cut(string(buf[:runtime.Stack(buf, true)]), stackGap)
	var ours []string
	for stack := range strings.SplitSeq(others, stackGap) {
		if strings.Contains(stack, modulePath) {
			ours = append(ours, stack)
		}
	}
	return strings.Join(ours, stackGap)
}

// allocRuns is how many runs assertAllocs averages.
const allocRuns = 100

// raceEnabled reports whether the test binary runs the race detector.
func raceEnabled() bool {
	info, _ := debug.ReadBuildInfo()
	return info != nil &&
		slices.Contains(info.Settings, debug.BuildSetting{Key: "-race", Value: strconv.FormatBool(true)})
}

// assertAllocs fails t unless f allocates want times per run, averaged over
// allocRuns runs. The race detector changes allocation counts and drops pooled
// items, so under it f runs once, unchecked.
func assertAllocs(t *testing.T, want float64, f func()) {
	t.Helper()
	if raceEnabled() {
		f()
		return
	}
	if got := testing.AllocsPerRun(allocRuns, f); got != want {
		t.Errorf("allocs per run = %.0f, want %.0f", got, want)
	}
}

// Literals of the fixtures: an hour, the digits that name a SHA-2 size, the
// repeats of a PKCE seed and JSON numbers Claim decodes.
const (
	hourSeconds = 3600
	hashDigits  = 3
	seedRepeats = 32
	claimSmall  = 12
	claimKilo   = 1000.0
	claimHuge   = 1e20
)

const headerChallenge = "WWW-Authenticate"

var (
	// errNoRoute is the failure of an in-memory transport for an unknown host.
	errNoRoute = errors.New("test: no route")
	// errUpstream is a failure of an upstream connection or body.
	errUpstream = errors.New("test: upstream failed")
)

// statusError stands, in error tables, for a refused answer of that status.
type statusError int

func (s statusError) Error() string { return "status " + strconv.Itoa(int(s)) }

// refusedStatus finds the status of a refused answer in an error text.
var refusedStatus = regexp.MustCompile(`answer refused: status (\d+)`)

// errorMatches is errors.Is, except that a statusError want matches a refused
// answer of that status.
func errorMatches(err, want error) bool {
	var status statusError
	if !errors.As(want, &status) {
		return errors.Is(err, want)
	}
	if !errors.Is(err, errRefusedAnswer) {
		return false
	}
	m := refusedStatus.FindStringSubmatch(err.Error())
	return len(m) > 1 && m[1] == strconv.Itoa(int(status))
}

const (
	testJWKSPath   = "/jwks"
	testLongSecret = "0123456789abcdef0123456789abcdef"
	testWideSecret = testLongSecret + testLongSecret
	testUser       = "user"
	testAdmin      = "admin"
	testRead       = "read"
	testWrite      = "write"
	testReadW      = "read write"
	testClientID   = "client-id"
	testIssuerURL  = "https://issuer.example.com"
	testJWKSURL    = "https://issuer.example.com/jwks"
	testHTTPS      = "https://example.com"
	testTypeJSON   = "application/json"
	testMCPServer  = "mcp-server"
	testCN         = "client"
	testAdminDN    = "CN=admin,O=corp"
	testNameIssuer = "internal-svc"
	testPublicURL  = "https://public.example"
	testAPIOrigin  = "http://api.example"
)

// Documented spellings of claim and JWK member names, discovery paths and an
// OAuth error code.
const (
	testClaimNbf            = "nbf"
	testClaimNonce          = "nonce"
	testMemberKty           = "kty"
	testOpenIDConfiguration = "/.well-known/openid-configuration"
	testServerMetadata      = "/.well-known/oauth-authorization-server"
	testInvalidScope        = "invalid_scope"
)

// recorded returns the problems p holds, in the order recorded.
func recorded(p *problems.List) []error {
	var joined interface{ Unwrap() []error }
	if !errors.As(p.Err(), &joined) {
		return nil
	}
	return joined.Unwrap()
}

// newReq builds a request bound to the test context.
func newReq(tb testing.TB, method, target string, body io.Reader) *http.Request {
	tb.Helper()
	return httptest.NewRequestWithContext(tb.Context(), method, target, body)
}

// withDefaults gives the empty settings of c their defaults, without validating c.
func withDefaults(c *Config) *Config {
	c.applyDefaults()
	return c
}

// newTestOAuth builds the authenticator of oc, prepared with client as its HTTP
// client; it fails tb when oc is invalid.
func newTestOAuth(tb testing.TB, oc *OAuthConfig, client *http.Client) *oauthAuthenticator {
	tb.Helper()
	cfg, err := (&Config{Mode: ModeOAuth, OAuth: *oc, HTTPClient: client}).prepare()
	if err != nil {
		tb.Fatalf("prepare = %v, want a valid config", err)
	}
	prepared := &cfg.OAuth
	return newOAuthAuthenticator(prepared, prepared.keys(func() *issuer { return newIssuer(cfg) }))
}

func mustGate(tb testing.TB, cfg *Config) *Gate {
	tb.Helper()
	g, err := New(cfg)
	if err != nil {
		tb.Fatalf("New = %v, want a Gate", err)
	}
	return g
}

// The claims of scoped: their names, the level, the ratio and the team, a
// string as long as a typical claim value.
const (
	claimLvl   = "lvl"
	claimRatio = "ratio"
	claimTeam  = "team"
	claimOn    = "on"
	lvl        = 5
	ratio      = 0.5
	testTeam   = "platform-engineering"
)

// scoped returns an OAuth identity of testUser granted scopes, with a numeric,
// a fractional, a string and a boolean claim.
func scoped(scopes ...string) *Identity {
	claims := `{"` + claimLvl + `":5,"` + claimRatio + `":0.5,"` + claimTeam + `":"` + testTeam + `","` + claimOn +
		`":true}`
	return &Identity{mode: ModeOAuth, subject: testUser, scopes: scopes, claims: claims}
}

// scopeTokenPattern matches an OAuth scope-token: '!' and the visible ASCII
// from '#' to '~' but backslash, at least once.
var scopeTokenPattern = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)

// scopeToken reports whether s is an OAuth scope-token.
func scopeToken(s string) bool { return scopeTokenPattern.MatchString(s) }

// testCert returns a certificate of cn and org whose SPKI is spki-<cn>; it
// panics if cn or org is not UTF-8.
func testCert(cn string, org ...string) *x509.Certificate {
	return mustSubjectCert(pkix.Name{CommonName: cn, Organization: org}.ToRDNSequence(), "spki-"+cn)
}

// mustSubjectCert returns a certificate whose raw and parsed subject is rdns
// and whose SPKI is spki; it panics if rdns does not marshal.
func mustSubjectCert(rdns pkix.RDNSequence, spki string) *x509.Certificate {
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		panic(err)
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&rdns)
	return &x509.Certificate{Subject: subject, RawSubject: raw, RawSubjectPublicKeyInfo: []byte(spki)}
}

// mtlsRequest builds a TLS request presenting cert without a verified chain.
func mtlsRequest(tb testing.TB, cert *x509.Certificate) *http.Request {
	tb.Helper()
	r := newReq(tb, http.MethodGet, "/", http.NoBody)
	r.TLS = &tls.ConnectionState{}
	if cert != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{cert}
	}
	return r
}

// verifiedMTLSRequest builds a TLS request presenting cert with a verified chain.
func verifiedMTLSRequest(tb testing.TB, cert *x509.Certificate) *http.Request {
	tb.Helper()
	r := mtlsRequest(tb, cert)
	r.TLS.VerifiedChains = [][]*x509.Certificate{{cert}}
	return r
}

// testUnix is the fixed verification time of the JWT tests, in seconds.
const testUnix = 1_800_000_000

// tokenLimit is the largest encoded token accepted, 16 KiB.
const tokenLimit = 16 << 10

func mustAlgorithm(tb testing.TB, name string) algorithm {
	tb.Helper()
	a, ok := lookupAlgorithm(name)
	if !ok {
		tb.Fatalf("lookupAlgorithm(%q) = false, want an algorithm", name)
	}
	return a
}

// testRSAKeyPEM and testRSAKey2PEM hold distinct 2048-bit PKCS #8 signing
// keys; the PEM label keeps secret scanners from taking them for real keys.
const (
	testRSAKeyPEM = `-----BEGIN TESTING KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQWXgZHfDdiHcd
eHLjUrgKoGHuw/acGhxsJzfS+enPnvcj3FpW3kWAWW5KCPhktHrWtafCGM+cULTB
ZHdfEDZxJ5QfmXNPkO5PBBq2lzN5laFIQwrI/QQ4Q/zZ0XkwI8uMeiUYdoCSzbrV
rNXz2ClmTpTvHTR9+UJbOrevNis2dgf6ldBFBMOmUYyiTn6vUz3KNlhxfQcl5fj5
32pdPUp+3Eh2GbEHpE8ackW+ie0ckkXIdSjb5oTzIM8Uezg0gZsLMLGDS1pNdRnK
uFCOz3HVjZkdF0/TfyZaYxWtvxOsic2G1QUDM68ZpaO3bevQznR9UtjN6CSePGt6
Dmk4Qrm7AgMBAAECggEAEOdBVCBWu1Jn/48XGxRJ9CrA50MkzdNcfPXNlKNL8dk+
yb0F40hTMS+QQBdsN5dg4+yG+LtUlKUDlTEWcjL5h8KjRNEJRupGO0jk9e1ccr/N
/vPZeybz4bC6Yd2ZzGsLB5GdUtfCZKamQtGr5gWijjdP4/plmNbRKF+iKWfmp5tU
Sn2nPKmo6i9Um2v1Flydc0nO/YUZDlSMiC++6U0Y4kdyrDFgI8WroWSvFe98HG+H
Vk+A5LVGN1QrWTwxx2BIDkJBLdRDyltTIn34Z/QhE0FlVGxC50zu/x3JB63RnIla
g9dLrpHGBiOXVTkX5hgEaw4V4cxctm6o6gvFcOdFGQKBgQDYVxFMnhSCZL2O0kP7
WD8q1NwRm3/abIVfTCMWrjRBbamx9bZ2th9b9iRezR9NADmlkm0CUfTaO87hcy7B
IVR4kntSDJ7fWIMZrBNlvVabU7wkngj8Zq8Jm0DUkfZiLmnxckgowpVW1DC+bNY+
TKbopung+IEOwNa5KZF95E6+pQKBgQD2i2YAe7UBd+BpVn1eTKUOGaSzAeUrZ04R
9ra8sOmiZhDKa/iEXLLc8Vli5JTx3nInqFdwiAKR/Mc7IMRaA7fToMzlW4udKOQP
679OlVu1EwIanR6h1IfHz+ZNv7u6SVtFauNChitvuSxpOW51LLkF751zrKh+Qibl
RMFQNmeI3wKBgQDMQ9FCrVOiFmpgiqnDjPv/fgHX4iGi46o+Y44R4SPXzypVrDG+
/pC3bL3EgRqXwqmraojgku+Eisn4VqADnGu8eFpWCzKKoXEPcUjTXCWE/Vf8nvbP
Ekkc4ekhjDu9UiOX5Ja7XZZR6IGpmuvi4M8LhmX3k8uPWYakR9pmqoWrPQKBgCoh
MgH9IbYphPibJfs6P65EJYfNWBrtoUKilSFzXck5hb8Baks8B/iHaY3jn6whJgKu
2ppJM588wdLRy5vSLNSGEt1Som3tseMiluNX1H8By4c+uCBRUA6N8T3x+KNhq64W
ENWqVbvWuccVYFG3nbps8sv0gippJXpiIGKTmWejAoGBAISNYI+Nz8um1TBMcNMC
LuakfqR/Xot3i/5tLjW+gMhoqBxSw/V4PXY1PRRplQIkiHBeWUwKZfqOEz08g6KN
9gg++In1n2A0tfYZQ114dQpq6VhbKxK/jX2DXxulzyQIIWmKTGibaOwloMBgzynE
U2VR5AfztMGGSOA5O1sVrWBC
-----END TESTING KEY-----`
	testRSAKey2PEM = `-----BEGIN TESTING KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCpBBhPYYNuuTfC
4NoFqok1xVLKidiZWJCgp2t6qNVMfM9xTEh8uV0o/K4IuIyGz9f5qsSn+gGmPr4r
ceAQb1zE6VIIxjO2kzRc/L6If47cEEOCwCnuWPBlhKA4IlViwNve8Zo/r8wx5e/k
reLlbRD28HCJBWg85LAXBtf8TGhgApUXsW4apzUjt2rRZG8Ii7rwbTfbSwpMdqmx
1W30VfTSi8ZNGV/0IAU/i9GI4ZgqMGLGNO04S4BlmYC3k67yxENx0mGLXSRg3tyt
WKhOC+kFRSJs/ySzrTWnNBH6DaxEmw+DsZxJirXrCZyiiSccm96mvkuCses3s/8e
/DGQobFtAgMBAAECggEACl6IskgQhPjCkcdzQNE9YUnloizyV7geCWk0GB6nFW37
2R7dvJ8vtr3H3Jub7YJvZO8j6Q1W0BD94FL4dPGsHp2U7ZphXlRqLEFKXDv9MwWh
arJo8ClPOF86aC89D1W3N5aZiMo7jB0oCl7bsokuNwQ510I4arH6FrOSCTXT2n38
iBAsec7dhpRut16IP30IoGAgdXL24GnBw/XO9jLCYM+Y01iaTFb2A06w+FnJ1asI
53dSA7zaDMTfj171Lvgmo1fjPoUFOv5P3SSfxJEWll2eT5MZzk/Vu03qg3W6xmEf
Yq2PNzBsCFmk+voEu5j0my/nQQcuDceHntIvBCGCcQKBgQDJuN/vmVpEcrxZJJAs
VfSwkIWxd3nFq9/JdfIRSJp5Yog9EyCjAV1Lao5kSGVmgs4JOdclVBsaYTurSszI
Vjrf/NicXfgiFlzr8fRYCxeWkvbYu4IXfs6MlYvzi4X8Q+iwuL9EUKGSBOScJN/d
/tAL3YpccwdbCl0KaTM81WSSMQKBgQDWflZzMF7bnsIIscN99Paya7Lxv4XMeXSw
mF0afFkXeLz3I9GzCQ91EUm/w+IJrApWddQxGhP7xsVfHGy1jwBhX0M9T+L+0fZS
X1OCqO47VluNQCFTue41f+Qz7Z1+z5kXq6P9KdkY5g29zheUfnNjnAtlWRTm/kxg
j2eVYcPn/QKBgE8/vWJxGeB4Pvy6e5Wfc1EGhi+RY5rAClwoZSBbKKz1g9aStCi1
+YQOacCGHKgoTW+cdKSqpTc46etCqK8wCVNED4lm9XvW00yysq8ANJUoSageCl7W
p6jde60DrHDN8RW0jxf0oXUvTOz3I6ggWnW+5IOrgUFIEgNsDwAgSbGRAoGBAK2N
pB2oMdi6aH3oeCneoA5WHoCFW5nLXKPXZN4dZ2kahKvkC7U1y5AJ4QaNVMRGtEap
KHxigXDjsKf4s+1kPAaNsjZWAXH2Kb0U7Nl4HutcQM/V6CF6/EfFp7xss1b8Wv9Q
HmymA8elvdCqhWHdvzgF9yKWJdeSQ/KNll7EsGNxAoGBAI5iUmuONbxp76M/MIMH
DXoiEHsiwHNgO7nYwgfKv8A/LS/wsd3IZhsew9zDVdm6ZJ4LqMIxPWglx6TlNI4C
4/IxE8gpctvbkZTDkQKUjEyiwtoE+lAEM3ArLIvdd7eTPBF8xoBaq5Ln/fanuB0C
Yg+zzrUjPLbGLluPEhL10JIq
-----END TESTING KEY-----`
)

func testRSAKey() *rsa.PrivateKey { return mustRSAKey(testRSAKeyPEM) }

func testRSAKey2() *rsa.PrivateKey { return mustRSAKey(testRSAKey2PEM) }

// mustRSAKey parses the RSA key of a PEM block; it panics if text holds no
// PKCS #8 RSA key.
func mustRSAKey(text string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		panic("test RSA key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		panic("test RSA key is not RSA")
	}
	return k
}

func mustECKey(tb testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey = %v, want a key", err)
	}
	return k
}

func mustEdKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey = %v, want a key", err)
	}
	return k
}

// escape writes r as a JSON unicode escape.
func escape(r rune) string {
	return fmt.Sprintf(`\u%04x`, r)
}

func mustJSON(tb testing.TB, v any) string {
	tb.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		tb.Fatalf("Marshal = %v, want JSON", err)
	}
	return string(b)
}

// testClaims returns claims that the JWKS test verifiers accept at testUnix.
func testClaims() map[string]any {
	return map[string]any{
		claimIss: testIssuerURL, claimAud: testMCPServer, claimSub: testUser,
		claimExp: testUnix + hourSeconds, claimScope: testReadW,
	}
}

// claimsWith returns testClaims with members replaced; nil removes one.
func claimsWith(members map[string]any) map[string]any {
	c := testClaims()
	for k, v := range members {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

// signToken signs claims with key under alg as a JWT, naming kid when it is
// set.
func signToken(tb testing.TB, alg string, key any, kid string, claims map[string]any) string {
	tb.Helper()
	header := map[string]any{memberAlg: alg, memberTyp: "JWT"}
	if kid != "" {
		header[memberKid] = kid
	}
	return signRaw(tb, alg, key, mustJSON(tb, header), mustJSON(tb, claims))
}

// segment base64url-encodes s as a token segment.
func segment(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// signRaw encodes header and payload and signs them with key under alg.
func signRaw(tb testing.TB, alg string, key any, header, payload string) string {
	tb.Helper()
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload))
	return input + "." + enc.EncodeToString(signInput(tb, alg, key, input))
}

// signInput signs input under alg, deriving the hash from the alg suffix.
func signInput(tb testing.TB, alg string, key any, input string) []byte {
	tb.Helper()
	h := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384,
		"512": crypto.SHA512}[alg[len(alg)-hashDigits:]]
	var sum []byte
	if h != 0 {
		d := h.New()
		_, _ = d.Write([]byte(input))
		sum = d.Sum(nil)
	}
	var sig []byte
	var err error
	switch k := key.(type) {
	case []byte:
		mac := hmac.New(h.New, k)
		_, _ = mac.Write([]byte(input))
		sig = mac.Sum(nil)
	case *rsa.PrivateKey:
		if alg[0] == 'P' {
			sig, err = rsa.SignPSS(rand.Reader, k, h, sum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, h, sum)
		}
	case *ecdsa.PrivateKey:
		sig, err = signRS(k, sum, (k.Params().BitSize+7)/8)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	}
	if err != nil {
		tb.Fatalf("sign %s = %v, want a signature", alg, err)
	}
	return sig
}

// signRS signs sum with k as R||S, each integer size bytes long.
func signRS(k *ecdsa.PrivateKey, sum []byte, size int) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, sum)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return sig, nil
}

// publicJWK renders the public part of key as a JWK with extra members.
func publicJWK(tb testing.TB, key any, extra map[string]any) map[string]any {
	tb.Helper()
	enc := base64.RawURLEncoding
	m := map[string]any{}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		m[testMemberKty], m[memberN] = "RSA", enc.EncodeToString(k.N.Bytes())
		m[memberE] = enc.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PrivateKey:
		b, err := k.PublicKey.Bytes()
		if err != nil {
			tb.Fatalf("Bytes = %v, want the point", err)
		}
		size := (len(b) - 1) / 2
		m[testMemberKty], m[memberCrv] = "EC", k.Params().Name
		m[memberX], m[memberY] = enc.EncodeToString(b[1:1+size]), enc.EncodeToString(b[1+size:])
	case ed25519.PrivateKey:
		m[testMemberKty], m[memberCrv], m[memberX] = "OKP", crvEd25519, enc.EncodeToString(k[ed25519.SeedSize:])
	}
	maps.Copy(m, extra)
	return m
}

// jwksDocument renders keys as a JWK Set.
func jwksDocument(tb testing.TB, keys ...map[string]any) []byte {
	tb.Helper()
	return []byte(mustJSON(tb, map[string]any{"keys": keys}))
}

// jwksReply is the status and body a jwksServer answers with.
type jwksReply struct {
	status int
	body   []byte
}

// jwksServer serves a swappable reply and counts its requests.
type jwksServer struct {
	*httptest.Server

	reply atomic.Pointer[jwksReply]
	hits  atomic.Int32
}

// newJWKSServer serves body with status 200 until set swaps the reply.
func newJWKSServer(tb testing.TB, body []byte) *jwksServer {
	tb.Helper()
	s := &jwksServer{}
	s.set(http.StatusOK, body)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		reply := s.reply.Load()
		w.WriteHeader(reply.status)
		writeBody(tb, w, string(reply.body))
	}))
	tb.Cleanup(s.Close)
	return s
}

func (s *jwksServer) set(status int, body []byte) {
	s.reply.Store(&jwksReply{status: status, body: body})
}

// validOAuth returns an HMAC-mode OAuth Config that New accepts.
func validOAuth() *Config {
	return &Config{Mode: ModeOAuth, OAuth: OAuthConfig{
		Issuer:     testIssuerURL,
		Audience:   testMCPServer,
		HMACSecret: secret.New(testLongSecret),
	}}
}

// metadataServer answers each path with a document built from its own URL
// and records the paths it served.
type metadataServer struct {
	*httptest.Server

	docs  map[string]func(base string) string
	mu    sync.Mutex
	paths []string
}

func newMetadataServer(tb testing.TB, docs map[string]func(base string) string) *metadataServer {
	tb.Helper()
	s := &metadataServer{docs: docs}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		doc, ok := s.docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeBody(tb, w, doc(s.URL))
	}))
	tb.Cleanup(s.Close)
	return s
}

// metadataDoc renders a document for issuerURL with endpoints under base.
func metadataDoc(issuerURL, base string) string {
	return `{"issuer":"` + issuerURL + `","jwks_uri":"` + base + `/jwks","authorization_endpoint":"` + base +
		`/authorize","token_endpoint":"` + base + `/token","scopes_supported":["openid"],"extra":{"a":[1,2]}}`
}

// Upstream identity provider and facade fixture values.
//
//nolint:gosec // G101: fixture values, not credentials.
const (
	testIDPHost      = "login.example.test"
	testIDPIssuer    = "https://login.example.test/tenant/v2.0"
	testIDPAuthorize = "https://login.example.test/tenant/oauth2/v2.0/authorize"
	testIDPToken     = "https://login.example.test/tenant/oauth2/v2.0/token"
	testFacadeClient = "5f1c7a2e-8d44-4b3a-9e61-2c0d9a7b4e10"
	testFacadeSecret = "Q~8s+t&x=y%zz/Ab"
	testScopePrefix  = "api://memory-app"
	testScopeMemory  = "memory"
	testMCPOrigin    = "https://mcp.example.com"
	testMCPResource  = "https://mcp.example.com/mcp"
	testLoopbackURI  = "http://localhost:53682/callback"
	testRefreshToken = "0.AAAA-refresh"
	testUpstreamRes  = "api://upstream"
	testTokenReply   = `{"token_type":"Bearer","scope":"api://memory-app/memory","expires_in":3599,` +
		`"access_token":"eyJ0eXAiOiJKV1QifQ.e30.c2ln","refresh_token":"` + testRefreshToken + `"}`
)

// formClientID is the client_id parameter the facade pins upstream.
const formClientID = "client_id"

// idpRequest is a token request as the fake identity provider received it.
type idpRequest struct {
	form        url.Values
	contentType string
	basicAuth   bool
}

// fakeIDP is an in-memory upstream identity provider shaped like Entra ID:
// it serves doc as discovery, answers token requests with answer, and
// records every token request.
type fakeIDP struct {
	tb          testing.TB
	doc         func() (int, string)
	answer      http.HandlerFunc
	discoveries atomic.Int32
	mu          sync.Mutex
	requests    []idpRequest
}

// newFakeIDP returns a provider publishing the testIDP* endpoints and
// answering every token request with testTokenReply.
func newFakeIDP(tb testing.TB) *fakeIDP {
	tb.Helper()
	return &fakeIDP{
		tb: tb,
		doc: func() (int, string) {
			return http.StatusOK, `{"issuer":"` + testIDPIssuer + `","authorization_endpoint":"` + testIDPAuthorize +
				`","token_endpoint":"` + testIDPToken + `","jwks_uri":"https://login.example.test/tenant/keys"}`
		},
		answer: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", testTypeJSON)
			writeBody(tb, w, testTokenReply)
		},
	}
}

// ServeHTTP answers discovery and token requests on the provider's paths.
func (p *fakeIDP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/tenant/v2.0" + testOpenIDConfiguration:
		p.discoveries.Add(1)
		status, doc := p.doc()
		w.WriteHeader(status)
		writeBody(p.tb, w, doc)
	case strings.TrimPrefix(testIDPToken, "https://"+testIDPHost):
		body, err := io.ReadAll(r.Body)
		form, parseErr := url.ParseQuery(string(body))
		if err != nil || parseErr != nil || r.Method != http.MethodPost {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _, basic := r.BasicAuth()
		p.mu.Lock()
		p.requests = append(p.requests, idpRequest{form: form, contentType: r.Header.Get("Content-Type"),
			basicAuth: basic})
		p.mu.Unlock()
		p.answer(w, r)
	default:
		http.NotFound(w, r)
	}
}

// received returns the token requests recorded so far.
func (p *fakeIDP) received() []idpRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.requests)
}

// logRecord is what a logCapture keeps of a record: level, message, the error
// attribute and whether its context carries the mark.
type logRecord struct {
	level    slog.Level
	msg      string
	err      error
	inMarked bool
}

// logCapture is a slog.Handler that keeps every record it handles; with
// onlyMarked it handles only the records of a marked context, and with hold it
// keeps each record once hold closes.
type logCapture struct {
	hold       chan struct{}
	mu         sync.Mutex
	records    []logRecord
	onlyMarked bool
}

// Enabled reports every level as enabled, under onlyMarked for a marked
// context alone.
func (c *logCapture) Enabled(ctx context.Context, _ slog.Level) bool {
	return !c.onlyMarked || isMarked(ctx)
}

// Handle keeps the level, message and error attribute of r, once hold closes.
//
//nolint:gocritic // hugeParam: slog.Handler requires the Record by value.
func (c *logCapture) Handle(ctx context.Context, r slog.Record) error {
	if c.hold != nil {
		<-c.hold
	}
	rec := logRecord{level: r.Level, msg: r.Message, inMarked: isMarked(ctx)}
	r.Attrs(func(a slog.Attr) bool {
		if err, ok := a.Value.Any().(error); ok && a.Key == "error" {
			rec.err = err
		}
		return true
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, rec)
	return nil
}

// WithAttrs returns c, whose records keep no handler attributes.
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }

// WithGroup returns c, whose records keep no groups.
func (c *logCapture) WithGroup(string) slog.Handler { return c }

// logged returns the records kept so far.
func (c *logCapture) logged() []logRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.records)
}

// warned reports whether c kept exactly one record, a warning with msg and
// an error that errorMatches want.
func (c *logCapture) warned(msg string, want error) bool {
	got := c.logged()
	return len(got) == 1 && got[0].level == slog.LevelWarn && got[0].msg == msg && errorMatches(got[0].err, want)
}

// ctxKey keys the mark that a test puts on the context it passes.
type ctxKey struct{}

const mark = "marked"

func marked(tb testing.TB) context.Context {
	tb.Helper()
	return context.WithValue(tb.Context(), ctxKey{}, mark)
}

func isMarked(ctx context.Context) bool {
	return ctx != nil && ctx.Value(ctxKey{}) == mark
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// answerWith returns a transport that answers every request with status, an
// empty header and body.
func answerWith(status int, body string) roundTripFunc {
	return func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{},
			Body: io.NopCloser(strings.NewReader(body))}, nil
	}
}

// markCounting returns a transport that counts in n the requests of a marked
// context and passes every request to next.
func markCounting(n *atomic.Int32, next http.RoundTripper) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		if isMarked(r.Context()) {
			n.Add(1)
		}
		return next.RoundTrip(r)
	}
}

// hostTransport serves each outbound request with the handler of its host.
type hostTransport map[string]http.Handler

// RoundTrip serves r with the handler of its host, or fails for another host.
func (t hostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	h, ok := t[r.URL.Host]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errNoRoute, r.URL.Host)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if r.Body != nil {
		if err := r.Body.Close(); err != nil {
			return nil, fmt.Errorf("close request body: %w", err)
		}
	}
	return w.Result(), nil
}

// stall holds r until its context ends, as an upstream that never answers.
func stall(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, fmt.Errorf("stalled: %w", r.Context().Err())
}

// facadeConfig returns an HMAC-mode OAuth Config with a confidential facade
// over idp, reached through an in-memory transport.
func facadeConfig(idp *fakeIDP) *Config {
	cfg := validOAuth()
	cfg.HTTPClient = &http.Client{Transport: hostTransport{testIDPHost: idp}}
	cfg.OAuth.Issuer = testIDPIssuer
	cfg.OAuth.RequiredScopes = []string{testScopeMemory}
	cfg.OAuth.Facade = FacadeConfig{
		ClientID: testFacadeClient, ClientSecret: secret.New(testFacadeSecret), ScopePrefix: testScopePrefix,
	}
	return cfg
}

// facadeMux returns a mux on which the Gate of cfg mounted /mcp.
func facadeMux(tb testing.TB, cfg *Config) *http.ServeMux {
	tb.Helper()
	mux := http.NewServeMux()
	mustGate(tb, cfg).Mount(mux, "/mcp")
	return mux
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// oauthErrorCode returns the error member of an OAuth JSON error body.
func oauthErrorCode(tb testing.TB, w *httptest.ResponseRecorder) string {
	tb.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		tb.Fatalf("error body = %q (%v), want an OAuth JSON error", w.Body.String(), err)
	}
	if w.Header().Get("Cache-Control") != oauthwire.CacheNoStore {
		tb.Fatalf("error Cache-Control = %q, want %q", w.Header().Get("Cache-Control"), oauthwire.CacheNoStore)
	}
	return body.Error
}

// testFacade returns the facade of the Gate built from cfg.
func testFacade(tb testing.TB, cfg *Config) *facade {
	tb.Helper()
	return mustGate(tb, cfg).authServer
}

// claudeClient is how a Claude client registers and authorizes.
type claudeClient struct {
	name         string
	registration string
	redirectURI  string
	refreshScope string
}

// claudeClients returns the claude.ai web client and Claude Code.
func claudeClients() []claudeClient {
	return []claudeClient{
		{
			name: "claude.ai",
			registration: `{"client_name":"claude.ai","grant_types":["authorization_code","refresh_token"],` +
				`"response_types":["code"],"token_endpoint_auth_method":"none",` +
				`"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`,
			redirectURI:  "https://claude.ai/api/mcp/auth_callback",
			refreshScope: testScopeMemory,
		},
		{
			name: "Claude Code",
			registration: `{"client_name":"Claude Code (memory)","redirect_uris":["` + testLoopbackURI + `"],` +
				`"grant_types":["authorization_code","refresh_token"],"response_types":["code"],` +
				`"token_endpoint_auth_method":"none"}`,
			redirectURI: testLoopbackURI,
		},
	}
}

// pkcePair returns a code verifier and its S256 challenge.
func pkcePair(seed string) (verifier, codeChallenge string) {
	verifier = segment(strings.Repeat(seed, seedRepeats))[:minVerifier]
	sum := sha256.Sum256([]byte(verifier))
	return verifier, segment(string(sum[:]))
}

// with returns a copy of v with key set to value.
func with(v url.Values, key, value string) url.Values {
	out := maps.Clone(v)
	out.Set(key, value)
	return out
}

// without returns a copy of v without key.
func without(v url.Values, key string) url.Values {
	out := maps.Clone(v)
	out.Del(key)
	return out
}

// benchWriter is a ResponseWriter that a benchmark resets and reuses, so
// only the allocations of the handler under test are measured.
type benchWriter struct {
	headers http.Header
	status  int
}

func newBenchWriter() *benchWriter { return &benchWriter{headers: make(http.Header)} }

// Header returns the reused header map.
func (w *benchWriter) Header() http.Header { return w.headers }

// Write discards b.
func (*benchWriter) Write(b []byte) (int, error) { return len(b), nil }

// WriteString discards s, as net/http writers take a string without a copy.
func (*benchWriter) WriteString(s string) (int, error) { return len(s), nil }

// WriteHeader records status.
func (w *benchWriter) WriteHeader(status int) { w.status = status }

// reset clears the header map and the status for the next iteration.
func (w *benchWriter) reset() {
	clear(w.headers)
	w.status = 0
}

// claimValues maps JSON values to what Claim returns for them.
func claimValues() map[string]any {
	return map[string]any{
		`"s"`: "s", `"\ufffd"`: "\ufffd", "\"\ufffd\"": "\ufffd", `"\ud83d\ude00"`: "\U0001F600",
		jsonNull: nil, "true": true, "false": false, "-0": int64(0), "-0.0": math.Copysign(0, -1),
		"12": int64(claimSmall), "1e3": claimKilo, "1.0": 1.0, "99999999999999999999": claimHuge, "1e400": "1e400",
		"[1]": "[1]", `{"a":1}`: `{"a":1}`,
	}
}

// sameValue reports whether got equals want, a float64 bit for bit, so the
// sign of zero counts.
func sameValue(got, want any) bool {
	if g, ok := got.(float64); ok {
		w, isFloat := want.(float64)
		return isFloat && math.Float64bits(g) == math.Float64bits(w)
	}
	return got == want
}

// bearerRequest returns a GET of / that carries token as a bearer
// credential, or no credential when token is empty.
func bearerRequest(tb testing.TB, token string) *http.Request {
	tb.Helper()
	r := newReq(tb, http.MethodGet, "/", http.NoBody)
	if token != "" {
		r.Header.Set(headerAuthorization, "Bearer "+token)
	}
	return r
}

// smuggled returns parameters that must never reach the upstream issuer.
func smuggled() url.Values {
	return url.Values{
		"audience": {"https://payments.example/api"}, paramRequestURI: {"https://attacker.example/req.jwt"},
		paramRequest: {"eyJhbGciOiJub25lIn0.e30."}, "claims": {`{"id_token":{"acr":null}}`}, "x-unknown": {"1"},
		"client_secret": {"evil"}, "client_assertion": {"jwt"}, "client_assertion_type": {"bearer"},
	}
}

// verifyRoom returns the room that parseJWS leaves for a verification.
func verifyRoom() []byte { return make([]byte, 0, verifyScratch) }

// writeBody writes s from a handler, where Fatalf is not allowed.
func writeBody(tb testing.TB, w io.Writer, s string) {
	tb.Helper()
	if _, err := io.WriteString(w, s); err != nil {
		tb.Errorf("WriteString(response body) = %v, want nil", err)
	}
}

// jsonEscape matches, leftmost alternative first, an escaped surrogate pair,
// a lone escaped surrogate and any other escape.
var jsonEscape = regexp.MustCompile(
	`\\u[dD][89abAB][[:xdigit:]]{2}\\u[dD][c-fC-F][[:xdigit:]]{2}|\\u[dD][89a-fA-F][[:xdigit:]]{2}|\\.`)

// hasLoneSurrogate reports whether raw escapes a surrogate outside a pair.
func hasLoneSurrogate(raw string) bool {
	for _, m := range jsonEscape.FindAllString(raw, -1) {
		if len(m) == len(`\ud800`) {
			return true
		}
	}
	return false
}

// maxNesting is how deep the documents the package reads nest arrays and
// objects, the top object included.
const maxNesting = 32

// errNotStrict is the refusal of strictMembers.
var errNotStrict = errors.New("test: not a strict JSON object")

// strictMembers calls fn with the name and raw value of each member of doc in order
// and returns fn's first error, or errNotStrict at the first fault of a UTF-8 object
// nested maxNesting deep, in which no object repeats a name, with no lone surrogate.
func strictMembers(doc string, fn func(name string, value json.RawMessage) error) error {
	dec := json.NewDecoder(strings.NewReader(doc))
	if open, err := dec.Token(); err != nil || open != json.Delim('{') {
		return errNotStrict
	}
	seen := make(map[string]bool)
	for dec.More() {
		name, value, ok := strictMember(dec, doc)
		if !ok || seen[name] {
			return errNotStrict
		}
		seen[name] = true
		if err := fn(name, value); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || strings.TrimLeft(doc[dec.InputOffset():], " \t\r\n") != "" {
		return errNotStrict
	}
	return nil
}

// strictMember reads from dec the next member of doc, its decoded name and raw
// value, and reports whether the member is UTF-8 without a lone surrogate and its
// value nests within maxNesting under the object and holds no object repeating a name.
func strictMember(dec *json.Decoder, doc string) (name string, value json.RawMessage, ok bool) {
	start := dec.InputOffset()
	token, err := dec.Token()
	name, isName := token.(string)
	if err != nil || !isName || dec.Decode(&value) != nil {
		return "", nil, false
	}
	member := doc[start:dec.InputOffset()]
	values := json.NewDecoder(bytes.NewReader(value))
	values.UseNumber()
	return name, value, utf8.ValidString(member) && !hasLoneSurrogate(member) && 1+nesting(value) <= maxNesting &&
		uniqueNames(values)
}

// uniqueNames reads the next value from dec and reports whether the read succeeds
// and no object in the value repeats a member name.
func uniqueNames(dec *json.Decoder) bool {
	open, err := dec.Token()
	if err != nil {
		return false
	}
	if open != json.Delim('{') && open != json.Delim('[') {
		return true
	}
	seen := make(map[string]bool)
	for dec.More() {
		if open == json.Delim('{') {
			token, nameErr := dec.Token()
			name, isName := token.(string)
			if nameErr != nil || !isName || seen[name] {
				return false
			}
			seen[name] = true
		}
		if !uniqueNames(dec) {
			return false
		}
	}
	_, err = dec.Token()
	return err == nil
}

// nesting returns how deep the JSON value raw nests arrays and objects.
func nesting(raw json.RawMessage) int {
	depth, deepest, quoted, escaped := 0, 0, false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case quoted:
			escaped, quoted = c == '\\', c != '"'
		case c == '"':
			quoted = true
		case c == '[' || c == '{':
			depth++
			deepest = max(deepest, depth)
		case c == ']' || c == '}':
			depth--
		}
	}
	return deepest
}

// stringValue decodes value when it is a JSON string.
func stringValue(value json.RawMessage) (string, bool) {
	var s string
	if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &s) != nil {
		return "", false
	}
	return s, true
}

// stringValues decodes value when it is a JSON array of strings.
func stringValues(value json.RawMessage) ([]string, bool) {
	var elems []json.RawMessage
	if len(value) == 0 || value[0] != '[' || json.Unmarshal(value, &elems) != nil {
		return nil, false
	}
	out := make([]string, 0, len(elems))
	for _, e := range elems {
		s, ok := stringValue(e)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// anyValue is a value that any setting and any list accepts.
const anyValue = "x"

const jsonNull = "null"

const jsonEmptyArray = "[]"

const emptyObject = "{}"

// Documented durations: the key cache TTL and fetch timeout defaults, how long
// stale keys and metadata serve, and the pause after a failed or forced fetch.
const (
	wantKeysTTL      = 5 * time.Minute
	wantFetchTimeout = 10 * time.Second
	staleLimit       = 24 * time.Hour
	fetchPause       = 30 * time.Second
)

// oidcScopes returns the OpenID Connect scopes the facade relays unqualified.
func oidcScopes() []string { return []string{"openid", "offline_access", "profile", "email"} }

// policySkew is the skew, in seconds, of the claim policies referenceClaims
// stands for.
const policySkew = 45

// referenceJOSE is what verification reads of a JOSE header: the alg name,
// the kid and whether typ is at+jwt.
type referenceJOSE struct {
	algName, kid string
	accessType   bool
}

// referenceHeader reads data, a decoded JOSE header, with encoding/json, hands
// each member in order to set, and requires alg.
func referenceHeader(data string) (referenceJOSE, error) {
	var h referenceJOSE
	err := strictMembers(data, h.set)
	switch {
	case errors.Is(err, errNotStrict), err == nil && h.algName == "":
		return referenceJOSE{}, errMalformedToken
	case err != nil:
		return referenceJOSE{}, err
	}
	return h, nil
}

// set records one header member, refusing crit, an alg, kid or typ that is no
// string, an alg outside the accepted list and a typ setType refuses.
func (h *referenceJOSE) set(name string, value json.RawMessage) error {
	if name == "crit" {
		return errCriticalHeader
	}
	if name != "alg" && name != "kid" && name != "typ" {
		return nil
	}
	s, ok := stringValue(value)
	switch {
	case !ok:
		return errMalformedToken
	case name == "kid":
		h.kid = s
	case name == "typ":
		return h.setType(s)
	case !slices.Contains(acceptedAlgs(), s):
		return errUnsupportedAlg
	default:
		h.algName = s
	}
	return nil
}

// acceptedAlgs returns the names of the JWS algorithms verification accepts.
func acceptedAlgs() []string {
	return []string{
		"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256", "HS384",
		"HS512",
	}
}

// setType records typ, JWT or at+jwt under Unicode case folding, each also
// under application/, or refuses it.
func (h *referenceJOSE) setType(typ string) error {
	for _, media := range []string{"", "application/"} {
		switch {
		case strings.EqualFold(typ, media+"jwt"):
			return nil
		case strings.EqualFold(typ, media+"at+jwt"):
			h.accessType = true
			return nil
		}
	}
	return errTokenType
}

// referenceToken is what verification reads of a compact token: the header,
// the claims, the signature and the signing input.
type referenceToken struct {
	jose                      referenceJOSE
	claims, sigText, signedAs string
}

// jwsSegments is how many segments a compact token holds.
const jwsSegments = 3

// referenceJWS reads raw as a compact token of at most 16 KiB in three strict
// base64url segments, whose header referenceHeader accepts.
func referenceJWS(raw string) (referenceToken, error) {
	if len(raw) > tokenLimit {
		return referenceToken{}, errTokenTooLarge
	}
	parts := strings.Split(raw, jwsSeparator)
	if len(parts) != jwsSegments {
		return referenceToken{}, errMalformedToken
	}
	decoded := make([]string, len(parts))
	for i, part := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || strings.ContainsAny(part, "\r\n") {
			return referenceToken{}, errMalformedToken
		}
		decoded[i] = string(b)
	}
	h, err := referenceHeader(decoded[0])
	if err != nil {
		return referenceToken{}, err
	}
	signedAs := parts[0] + jwsSeparator + parts[1]
	return referenceToken{jose: h, claims: decoded[1], sigText: decoded[2], signedAs: signedAs}, nil
}

// referenceClaims reads payload with encoding/json for the test issuer, audience
// and skew at testUnix: the ID token markers, the issuer and audience, the times,
// the subject and the scopes, in that order, each refused by class.
func referenceClaims(payload string) (tokenClaims, error) {
	m := make(map[string]json.RawMessage)
	if strictMembers(payload, func(name string, value json.RawMessage) error {
		m[name] = value
		return nil
	}) != nil {
		return tokenClaims{}, errMalformedClaims
	}
	for _, check := range []func(map[string]json.RawMessage) error{referenceMarkers, referenceIdentity,
		referenceTimes} {
		if err := check(m); err != nil {
			return tokenClaims{}, err
		}
	}
	subject, err := referenceSubject(m)
	if err != nil {
		return tokenClaims{}, err
	}
	scopes, err := referenceScopes(m)
	if err != nil {
		return tokenClaims{}, err
	}
	return tokenClaims{subject: subject, scopes: scopes}, nil
}

// referenceMarkers refuses an ID token: an at_hash or c_hash, or a nonce
// without scope, scp or roles.
func referenceMarkers(m map[string]json.RawMessage) error {
	has := func(name string) bool {
		_, ok := m[name]
		return ok
	}
	if has("at_hash") || has("c_hash") || has("nonce") && !has("scope") && !has("scp") && !has("roles") {
		return errIDToken
	}
	return nil
}

// referenceIdentity requires iss, a string when present, to be the test
// issuer, and aud, a string or an array of strings, to name the test audience.
func referenceIdentity(m map[string]json.RawMessage) error {
	iss := ""
	if v, present := m["iss"]; present {
		s, ok := stringValue(v)
		if !ok {
			return errMalformedClaims
		}
		iss = s
	}
	if iss != testIssuerURL {
		return errIssuer
	}
	v, present := m["aud"]
	if !present {
		return errAudience
	}
	audiences, ok := stringOrStrings(v)
	switch {
	case !ok:
		return errMalformedClaims
	case !slices.Contains(audiences, testMCPServer):
		return errAudience
	}
	return nil
}

// referenceTimes requires exp, and refuses a time claim that is no number from
// 0 to 2^53, an exp over policySkew seconds before testUnix, and an nbf or iat
// over policySkew seconds after it.
func referenceTimes(m map[string]json.RawMessage) error {
	raw, present := m["exp"]
	if !present {
		return errMissingExpiry
	}
	exp, ok := referenceDate(raw)
	switch {
	case !ok:
		return errMalformedClaims
	case exp+policySkew < testUnix:
		return ErrTokenExpired
	}
	for _, late := range []struct {
		name string
		fail error
	}{{"nbf", errNotYetValid}, {"iat", errIssuedInFuture}} {
		raw, present := m[late.name]
		if !present {
			continue
		}
		at, ok := referenceDate(raw)
		switch {
		case !ok:
			return errMalformedClaims
		case at > testUnix+policySkew:
			return late.fail
		}
	}
	return nil
}

// maxDate is the largest time claim accepted, 2^53 seconds.
const maxDate = 1 << 53

// referenceDate decodes raw when it is a JSON number from 0 to maxDate.
func referenceDate(raw json.RawMessage) (float64, bool) {
	var v float64
	if string(raw) == jsonNull || json.Unmarshal(raw, &v) != nil {
		return 0, false
	}
	return v, v >= 0 && v <= maxDate
}

// referenceSubject returns the first non-empty of sub, client_id and azp, each
// a string when present.
func referenceSubject(m map[string]json.RawMessage) (string, error) {
	for _, name := range []string{"sub", "client_id", "azp"} {
		v, present := m[name]
		if !present {
			continue
		}
		s, ok := stringValue(v)
		if !ok {
			return "", errMalformedClaims
		}
		if s != "" {
			return s, nil
		}
	}
	return "", nil
}

// referenceScopes splits on spaces the scope string or, without scope, each
// string of scp, a string or an array of strings, dropping empty tokens.
func referenceScopes(m map[string]json.RawMessage) ([]string, error) {
	if v, present := m["scope"]; present {
		s, ok := stringValue(v)
		if !ok {
			return nil, errMalformedClaims
		}
		return spaceFields(s), nil
	}
	v, present := m["scp"]
	if !present {
		return nil, nil
	}
	list, ok := stringOrStrings(v)
	if !ok {
		return nil, errMalformedClaims
	}
	var tokens []string
	for _, s := range list {
		tokens = append(tokens, spaceFields(s)...)
	}
	return tokens, nil
}

// spaceFields splits s on spaces, dropping empty fields.
func spaceFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' })
}

// referenceUpstreamScope joins first and requested, each scope once, in the test
// facade's upstream terms (testScopePrefix before a bare API scope); it reports
// false for a malformed scope or a URI outside the prefix.
func referenceUpstreamScope(first, requested []string) (string, bool) {
	scopes := slices.Clone(first)
	for _, s := range requested {
		switch {
		case !scopeToken(s):
			return "", false
		case slices.Contains(oidcScopes(), s) || strings.HasPrefix(s, testScopePrefix+"/"):
		case strings.Contains(s, "://") || strings.HasPrefix(s, "urn:"):
			return "", false
		default:
			s = testScopePrefix + "/" + s
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return strings.Join(scopes, " "), true
}

// stringOrStrings decodes value when it is a JSON string or an array of
// strings.
func stringOrStrings(value json.RawMessage) ([]string, bool) {
	if s, ok := stringValue(value); ok {
		return []string{s}, true
	}
	return stringValues(value)
}

// referenceRedirectURI reports whether uri passes the outbound URL policy and
// carries no fragment.
func referenceRedirectURI(uri string) bool {
	_, err := netguard.Check(uri, errNoRoute)
	return err == nil && !strings.Contains(uri, "#")
}

// bearerPrefix starts an Authorization header of the Bearer scheme.
const bearerPrefix = "Bearer "

// Two scopes of the claims and scope tests.
const (
	scopeA = "a"
	scopeB = "b"
)

// openIDDoc serves doc at the OpenID Connect discovery path.
func openIDDoc(doc func(base string) string) map[string]func(string) string {
	return map[string]func(string) string{testOpenIDConfiguration: doc}
}
