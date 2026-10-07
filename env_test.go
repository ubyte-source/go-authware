package authware

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
)

const (
	wantEnvConfig = "ConfigFromEnv = %v, want a config"
	envTestList   = "AUTH_TEST_LIST"
	dnA           = "CN=a"
)

// clearAuthEnv unsets every AUTH_ variable for the duration of the test.
func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "AUTH_") {
			t.Setenv(name, "")
		}
	}
}

// testPin is the SPKI pin fullEnv sets.
func testPin() []byte { return bytes.Repeat([]byte{0xFB}, sha256.Size) }

// fullEnv sets every variable ConfigFromEnv reads to a value it accepts.
func fullEnv() map[string]string {
	return map[string]string{
		"AUTH_MODE": "oauth", "AUTH_REALM": "r", "AUTH_BEARER_TOKEN": "bt", "AUTH_APIKEY": "ak",
		"AUTH_APIKEY_HEADER": "X-K", "AUTH_OAUTH_ISSUER": testIssuerURL, "AUTH_OAUTH_AUDIENCE": "aud",
		"AUTH_OAUTH_JWKS_URL": testJWKSURL, "AUTH_OAUTH_HMAC_SECRET": "hs",
		"AUTH_OAUTH_REQUIRED_SCOPES": " read , write ", "AUTH_OAUTH_REQUIRE_AT_JWT": "true",
		"AUTH_OAUTH_CLOCK_SKEW": "1m", "AUTH_OAUTH_KEYS_CACHE_TTL": "2m", "AUTH_OAUTH_FETCH_TIMEOUT": "3s",
		"AUTH_OAUTH_PUBLIC_URL": testHTTPS, "AUTH_OAUTH_TRUST_FORWARDED_PROTO": "1",
		"AUTH_OAUTH_RESOURCE": "https://res", "AUTH_OAUTH_RESOURCE_NAME": "n",
		"AUTH_OAUTH_RESOURCE_DOCUMENTATION": "https://doc", "AUTH_OAUTH_AUTHORIZATION_SERVERS": "https://a,https://b",
		"AUTH_OAUTH_FACADE_CLIENT_ID": "cid", "AUTH_OAUTH_FACADE_CLIENT_SECRET": "cs",
		"AUTH_OAUTH_FACADE_SCOPE_PREFIX": "api://p", "AUTH_OAUTH_FACADE_UPSTREAM_RESOURCE": "up",
		"AUTH_MTLS_ALLOWED_SUBJECTS": "a; CN=admin,O=corp",
		"AUTH_MTLS_SPKI_PINS":        base64.StdEncoding.EncodeToString(testPin()),
	}
}

func TestConfigFromEnv(t *testing.T) {
	clearAuthEnv(t)
	pin := testPin()
	for k, v := range fullEnv() {
		t.Setenv(k, v)
	}
	cfg, err := ConfigFromEnv("")
	if err != nil {
		t.Fatalf(wantEnvConfig, err)
	}
	o := cfg.OAuth
	got := fmt.Sprint(cfg.Mode, cfg.Realm, cfg.Bearer.Token.Reveal(), cfg.APIKey.Key.Reveal(), cfg.APIKey.Header,
		o.Issuer, o.Audience, o.JWKSURL, o.HMACSecret.Reveal(), o.RequiredScopes, o.RequireAccessTokenType,
		o.ClockSkew, o.KeysCacheTTL, o.FetchTimeout, o.PublicURL, o.TrustForwardedProto, o.Resource,
		o.Facade.ClientID, o.Facade.ClientSecret.Reveal(), o.Facade.ScopePrefix, o.Facade.UpstreamResource,
		cfg.MTLS.AllowedSubjects)
	want := fmt.Sprint(ModeOAuth, "r", "bt", "ak", "X-K", testIssuerURL, "aud", testJWKSURL, "hs",
		[]string{testRead, testWrite}, true, time.Minute, 2*time.Minute, 3*time.Second, testHTTPS, true,
		ResourceConfig{"https://res", "n", "https://doc", []string{"https://a", "https://b"}},
		"cid", "cs", "api://p", "up", []string{"a", testAdminDN})
	if got != want {
		t.Fatalf("ConfigFromEnv = %s, want %s", got, want)
	}
	if len(cfg.MTLS.AllowedSPKIPins) != 1 || !bytes.Equal(cfg.MTLS.AllowedSPKIPins[0], pin) {
		t.Fatalf("pins = %x, want [%x]", cfg.MTLS.AllowedSPKIPins, pin)
	}
}

func TestConfigFromEnvEmpty(t *testing.T) {
	clearAuthEnv(t)
	cfg, err := ConfigFromEnv("")
	if err != nil || cfg.Mode != "" || cfg.OAuth.RequiredScopes != nil || len(cfg.MTLS.AllowedSPKIPins) != 0 {
		t.Fatalf("ConfigFromEnv = %+v, %v, want an empty config", cfg, err)
	}
	if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(no AUTH_MODE) = %v, want ErrInvalidConfig", err)
	}
}

func TestConfigFromEnvPinEncodings(t *testing.T) {
	pin := bytes.Repeat([]byte{0xFB}, sha256.Size)
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
		base64.RawURLEncoding}
	for _, enc := range encodings {
		clearAuthEnv(t)
		t.Setenv("AUTH_MTLS_SPKI_PINS", enc.EncodeToString(pin))
		cfg, err := ConfigFromEnv("")
		if err != nil || len(cfg.MTLS.AllowedSPKIPins) != 1 || !bytes.Equal(cfg.MTLS.AllowedSPKIPins[0], pin) {
			t.Fatalf("pins = %x, %v, want [%x]", cfg.MTLS.AllowedSPKIPins, err, pin)
		}
	}
}

func TestConfigFromEnvRejects(t *testing.T) {
	bad := map[string]string{
		"AUTH_OAUTH_REQUIRE_AT_JWT":        "yes-please",
		"AUTH_OAUTH_TRUST_FORWARDED_PROTO": "sure",
		"AUTH_OAUTH_CLOCK_SKEW":            "30",
		"AUTH_OAUTH_KEYS_CACHE_TTL":        "5 minutes",
		"AUTH_OAUTH_FETCH_TIMEOUT":         "10x",
		"AUTH_OAUTH_REQUIRED_SCOPES":       "read,,write",
		"AUTH_MTLS_SPKI_PINS":              "not*base64",
		"AUTH_MTLS_ALLOWED_SUBJECTS":       `CN=svc\`,
	}
	clearAuthEnv(t)
	for k, v := range bad {
		t.Setenv(k, v)
	}
	cfg, err := ConfigFromEnv("")
	if cfg != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ConfigFromEnv = %v, %v, want nil and ErrInvalidConfig", cfg, err)
	}
	for k, v := range bad {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("ConfigFromEnv error = %v, want it to name %s", err, k)
		}
		if strings.Contains(err.Error(), v) {
			t.Errorf("ConfigFromEnv error = %v, want no value of %s in it", err, k)
		}
	}
}

func TestConfigFromEnvPrefix(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("AUTH_MODE", "oauth")
	t.Setenv("MCP_INBOUND_AUTH_MODE", "bearer")
	t.Setenv("MCP_INBOUND_AUTH_BEARER_TOKEN", testLongSecret)
	t.Setenv("MCP_INBOUND_AUTH_OAUTH_CLOCK_SKEW", "soon")
	cfg, err := ConfigFromEnv("MCP_INBOUND_")
	if cfg != nil || !errors.Is(err, ErrInvalidConfig) ||
		!strings.Contains(err.Error(), "MCP_INBOUND_AUTH_OAUTH_CLOCK_SKEW") {
		t.Fatalf("ConfigFromEnv = %v, %v; want an error naming the prefixed variable", cfg, err)
	}
	t.Setenv("MCP_INBOUND_AUTH_OAUTH_CLOCK_SKEW", "")
	cfg, err = ConfigFromEnv("MCP_INBOUND_")
	if err != nil {
		t.Fatalf(wantEnvConfig, err)
	}
	if cfg.Mode != ModeBearer || cfg.Bearer.Token.Reveal() != testLongSecret {
		t.Fatalf("prefixed config = %+v, want mode bearer with the prefixed token", cfg)
	}
}

func TestEnvNames(t *testing.T) {
	names := EnvNames("")
	want := slices.Sorted(maps.Keys(fullEnv()))
	if got := slices.Sorted(slices.Values(names)); !slices.Equal(got, want) {
		t.Fatalf("EnvNames(\"\") = %q, want %q", got, want)
	}
	prefixed := make([]string, 0, len(names))
	for _, name := range names {
		prefixed = append(prefixed, "MCP_"+name)
	}
	if got := EnvNames("MCP_"); !slices.Equal(got, prefixed) {
		t.Fatalf("EnvNames(MCP_) = %q, want %q", got, prefixed)
	}
}

// TestEnvNamesRead sets each variable EnvNames lists alone and requires the
// Config ConfigFromEnv reads to change.
func TestEnvNamesRead(t *testing.T) {
	clearAuthEnv(t)
	blank, err := ConfigFromEnv("")
	if err != nil {
		t.Fatalf(wantEnvConfig, err)
	}
	values := fullEnv()
	for _, name := range EnvNames("") {
		clearAuthEnv(t)
		t.Setenv(name, values[name])
		if got, err := ConfigFromEnv(""); err != nil || reflect.DeepEqual(got, blank) {
			t.Errorf("%s=%s: ConfigFromEnv = %+v, %v; want the variable read", name, values[name], got, err)
		}
	}
}

// TestEnvNamesDocumented requires the example environment to name exactly
// the variables EnvNames lists, and the readme to name each of them.
func TestEnvNamesDocumented(t *testing.T) {
	example, err := os.ReadFile(".env.example")
	if err != nil {
		t.Fatalf("ReadFile(.env.example) = %v, want the example", err)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("ReadFile(README.md) = %v, want the README", err)
	}
	lines := regexp.MustCompile(`(?m)^(?:# )?(AUTH_[A-Z_]+)=`).FindAllSubmatch(example, -1)
	listed := make([]string, 0, len(lines))
	for _, m := range lines {
		listed = append(listed, string(m[1]))
	}
	slices.Sort(listed)
	want := slices.Sorted(slices.Values(EnvNames("")))
	if !slices.Equal(listed, want) {
		t.Errorf(".env.example names %q, want %q", listed, want)
	}
	for _, name := range want {
		if !bytes.Contains(readme, []byte(name)) {
			t.Errorf("README.md names %s = false, want true", name)
		}
	}
}

// TestConfigFromEnvSubjects checks a distinguished name from the environment
// stays whole, so a certificate matching only one of its RDNs is refused, and
// that a common name keeps the separator it escapes, as its rendering does.
func TestConfigFromEnvSubjects(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("AUTH_MODE", "mtls")
	t.Setenv("AUTH_MTLS_ALLOWED_SUBJECTS", testAdminDN+`; svc\;blue`)
	cfg, err := ConfigFromEnv("")
	if err != nil {
		t.Fatalf(wantEnvConfig, err)
	}
	g := mustGate(t, cfg)
	for cert, want := range map[*x509.Certificate]error{
		testCert("admin", "corp"): nil,
		testCert("admin"):         ErrInvalidCredentials,
		testCert("other", "corp"): ErrInvalidCredentials,
		testCert("svc;blue"):      nil,
		testCert(`svc\;blue`):     ErrInvalidCredentials,
		testCert("svc"):           ErrInvalidCredentials,
	} {
		if _, err := g.Authenticate(verifiedMTLSRequest(t, cert)); !errors.Is(err, want) {
			t.Errorf("Authenticate(%s) = %v, want %v", cert.Subject, err, want)
		}
	}
}

// newEnvReader returns a reader of the process environment.
func newEnvReader() *envReader {
	return &envReader{lookup: os.Getenv, p: problems.New(ErrInvalidConfig)}
}

func TestEnvReaderList(t *testing.T) {
	e := newEnvReader()
	t.Setenv(envTestList, `a, b ,c\\`)
	if got := e.list(envTestList, ','); !slices.Equal(got, []string{"a", "b", `c\\`}) || e.p.Err() != nil {
		t.Fatalf("list(,) = %v, %v, want [a b c\\\\]", got, e.p.Err())
	}
	if got := e.list(envTestList, ';'); !slices.Equal(got, []string{`a, b ,c\\`}) || e.p.Err() != nil {
		t.Fatalf("list(;) = %v, %v, want [a, b ,c\\\\]", got, e.p.Err())
	}
}

func TestEnvReaderListRejects(t *testing.T) {
	const lone = "has an element ending in a lone backslash"
	for v, reason := range map[string]string{
		"a,": "has an empty element", " ,a": "has an empty element", "a, ,b": "has an empty element",
		`x\`: lone, `x\,y\`: lone, `y,x\\\`: lone,
	} {
		t.Setenv(envTestList, v)
		e := newEnvReader()
		got := e.list(envTestList, ',')
		if found := recorded(e.p); got != nil || len(found) != 1 || !errors.Is(found[0], ErrInvalidConfig) ||
			!strings.Contains(found[0].Error(), "AUTH_TEST_LIST "+reason) {
			t.Errorf("list(%q) = %v, %v; want nil and one problem: AUTH_TEST_LIST %s", v, got, found, reason)
		}
	}
}

func TestLoneBackslash(t *testing.T) {
	for s, want := range map[string]bool{
		"": false, "a": false, `a\`: true, `a\\`: false, `a\\\`: true, `\`: true, `\a`: false,
	} {
		if got := loneBackslash(s); got != want {
			t.Errorf("loneBackslash(%q) = %t, want %t", s, got, want)
		}
	}
}

func TestSplitList(t *testing.T) {
	bs := `\`
	tests := map[string][]string{
		"":                        {""},
		"CN=a,O=b; CN=c":          {"CN=a,O=b", "CN=c"},
		" CN=a" + bs + ";b ;CN=c": {dnA + bs + ";b", "CN=c"},
		dnA + bs + " ; CN=b":      {dnA + bs + " ", "CN=b"},
		dnA + bs + bs + ";CN=b":   {dnA + bs + bs, "CN=b"},
		dnA + bs:                  {dnA + bs},
		bs + " a ; b":             {bs + " a", "b"},
		" a" + bs + bs + " ;b":    {"a" + bs + bs, "b"},
		";":                       {"", ""},
	}
	for in, want := range tests {
		if got := splitList(in, ';'); !slices.Equal(got, want) {
			t.Errorf("splitList(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzSplitList checks splitList against a two-pass reference: mark the
// escaped bytes, then cut at the unmarked separators and trim unmarked spaces.
func FuzzSplitList(f *testing.F) {
	for _, seed := range []string{"", "CN=a,O=b; CN=c", ` CN=a\;b ;CN=c`, `CN=a\ ; CN=b`, `a\\;b`, `x\`, " ; "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := splitList(s, ';'), splitListReference(s, ';'); !slices.Equal(got, want) {
			t.Fatalf("splitList(%q) = %q, want %q", s, got, want)
		}
	})
}

// splitListReference splits s at each unescaped sep and trims the unescaped
// spaces around each element, marking escaped bytes in a first pass.
func splitListReference(s string, sep byte) []string {
	escaped := escapedBytes(s)
	var out []string
	start := 0
	for i := range len(s) + 1 {
		if i == len(s) || (!escaped[i] && s[i] == sep) {
			out = append(out, trimUnescaped(s, escaped, start, i))
			start = i + 1
		}
	}
	return out
}

// escapedBytes marks each backslash of s and the byte it escapes.
func escapedBytes(s string) []bool {
	escaped := make([]bool, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			escaped[i] = true
			if i+1 < len(s) {
				i++
				escaped[i] = true
			}
		}
	}
	return escaped
}

// trimUnescaped returns s[lo:hi] without the unescaped spaces at its ends.
func trimUnescaped(s string, escaped []bool, lo, hi int) string {
	for lo < hi && !escaped[lo] && s[lo] == ' ' {
		lo++
	}
	for hi > lo && !escaped[hi-1] && s[hi-1] == ' ' {
		hi--
	}
	return s[lo:hi]
}

// ExampleConfigFromEnv reads the EXAMPLE_AUTH_* variables; with no mode set,
// New refuses the configuration instead of admitting every request.
func ExampleConfigFromEnv() {
	cfg, err := ConfigFromEnv("EXAMPLE_")
	if err != nil {
		log.Fatal(err)
	}
	gate, err := New(cfg)
	fmt.Println(gate == nil, errors.Is(err, ErrInvalidConfig))
	// Output: true true
}
