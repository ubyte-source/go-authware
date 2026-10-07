package authware

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

func TestConfigValidate(t *testing.T) {
	if err := (*Config)(nil).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Validate() = %v, want ErrInvalidConfig", err)
	}
	short := &Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New("short")}}
	if err := short.Validate(); !errors.Is(err, ErrInvalidConfig) ||
		!strings.Contains(err.Error(), "bearer token is shorter") {
		t.Fatalf("short token Validate() = %v, want ErrInvalidConfig naming the bearer token", err)
	}
	ok := &Config{Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: secret.New(testLongSecret)}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid Validate() = %v, want nil", err)
	}
	if ok.Realm != "" || ok.APIKey.Header != "" {
		t.Fatalf("Validate left %+v, want its receiver without defaults", ok)
	}
}

func TestConfigPrepareRejects(t *testing.T) {
	long := secret.New(testLongSecret)
	short := secret.New(strings.Repeat(anyValue, secretFloor-1))
	pin := make([]byte, 32)
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"nil config", nil, "nil config"},
		{"empty mode", &Config{}, "mode is required"},
		{"unknown mode", &Config{Mode: "Bearer"}, `unknown mode "Bearer"`},
		{"short bearer", &Config{Mode: ModeBearer, Bearer: BearerConfig{Token: short}}, "bearer token is shorter"},
		{"short key", &Config{Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: short}}, "API key is shorter"},
		{"bad header", &Config{Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: long, Header: "X Key"}},
			"not a valid header"},
		{"empty mtls", &Config{Mode: ModeMTLS}, "mtls needs"},
		{"empty subject", &Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSubjects: []string{""}}}, "subject is empty"},
		{"short pin", &Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSPKIPins: [][]byte{pin[:sha256.Size-1]}}},
			"pin 0 is not"},
		{"long pin", &Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSPKIPins: [][]byte{make([]byte, 33)}}},
			"pin 0 is not"},
		{"unrendered cn", &Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSubjects: []string{"a;b"}}}, `"a;b" is not`},
		{"lone backslash cn", &Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSubjects: []string{`svc\`}}},
			"is not written"},
		{"lone backslash dn", &Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSubjects: []string{`CN=svc\`}}},
			"is not written"},
		{"bearer space", &Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New(testLongSecret + " x")}},
			"bearer token is not a header value"},
		{"bearer tab", &Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New(testLongSecret + "\tx")}},
			"bearer token is not a header value"},
		{"bearer newline", &Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New(testLongSecret + "\n")}},
			"bearer token is not a header value"},
		{"key newline", &Config{Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: secret.New(testLongSecret + "\n")}},
			"API key is not a header value"},
		{"key padded", &Config{Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: secret.New(" " + testLongSecret)}},
			"API key is not a header value"},
		{"foreign section", &Config{Mode: ModeNone, Bearer: BearerConfig{Token: long}},
			"Bearer settings require mode bearer"},
		{"no issuer", &Config{Mode: ModeOAuth, OAuth: OAuthConfig{Audience: testAudience, HMACSecret: long}},
			"issuer is required"},
		{"no audience", &Config{Mode: ModeOAuth, OAuth: OAuthConfig{Issuer: "i", HMACSecret: long}},
			"audience is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.prepare()
			if got != nil || !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("prepare = %+v, %v, want nil, ErrInvalidConfig with %q", got, err, tc.want)
			}
		})
	}
}

func TestConfigPrepareAccepts(t *testing.T) {
	long := secret.New(testLongSecret)
	tests := map[string]*Config{
		"none":   {Mode: ModeNone},
		"bearer": {Mode: ModeBearer, Bearer: BearerConfig{Token: long}},
		"apikey": {Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: long, Header: "x-custom-key"}},
		"mtls cn": {Mode: ModeMTLS, MTLS: MTLSConfig{
			AllowedSubjects: []string{testCN, `semi\;colon`, `\#hash`, `CN=a\\`},
		}},
		"key space":  {Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: secret.New("key " + testLongSecret)}},
		"mtls pin":   {Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSPKIPins: [][]byte{make([]byte, 32)}}},
		"oauth hmac": validOAuth(),
		"oauth jwks": {Mode: ModeOAuth, OAuth: OAuthConfig{
			Issuer: "urn:idp", Audience: testAudience, JWKSURL: testJWKSURL,
			Resource: ResourceConfig{AuthorizationServers: []string{testIssuerURL}},
		}},
		"oauth hmac name issuer": {Mode: ModeOAuth, OAuth: OAuthConfig{
			Issuer: testNameIssuer, Audience: testAudience, HMACSecret: long,
		}},
		"oauth jwks plain issuer": {Mode: ModeOAuth, OAuth: OAuthConfig{
			Issuer: "http://idp.internal", Audience: testAudience, JWKSURL: testJWKSURL,
		}},
		"oauth uri scope": {Mode: ModeOAuth, OAuth: OAuthConfig{
			Issuer: testIssuerURL, Audience: testAudience, HMACSecret: long,
			RequiredScopes: []string{"https://api.example.com/read"},
		}},
		"oauth disco": {Mode: ModeOAuth, OAuth: OAuthConfig{Issuer: "http://localhost:8080/", Audience: testAudience}},
		"oauth facade": {Mode: ModeOAuth, OAuth: OAuthConfig{
			Issuer: testIssuerURL, Audience: testAudience, PublicURL: "https://api.example.com:8443",
			Facade:         FacadeConfig{ClientID: testClientID, ScopePrefix: "api://app"},
			RequiredScopes: []string{"read", "api://app/write", scopeOpenID},
		}},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := cfg.prepare(); err != nil {
				t.Fatalf("prepare = %v, want nil", err)
			}
		})
	}
}

func TestConfigPrepareJoinsEveryProblem(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuth: OAuthConfig{ClockSkew: -1, RequiredScopes: []string{"a b"}}}
	got, err := cfg.prepare()
	var joined interface{ Unwrap() []error }
	if got != nil || !errors.Is(err, ErrInvalidConfig) || !errors.As(err, &joined) {
		t.Fatalf("prepare = %+v, %v, want nil, joined %v", got, err, ErrInvalidConfig)
	}
	for _, problem := range joined.Unwrap() {
		if !errors.Is(problem, ErrInvalidConfig) {
			t.Errorf("problem %q, want one wrapping %v", problem, ErrInvalidConfig)
		}
	}
	for _, want := range []string{"issuer is required", "audience is required", "clock skew", "scope"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("prepare error = %v, want it to name %q", err, want)
		}
	}
}

// The clock skew applyDefaults sets, and the shortest secret accepted.
const (
	wantClockSkew = 30 * time.Second
	secretFloor   = 32
)

// testAudience is the audience of the configuration tests.
const testAudience = "a"

func TestConfigApplyDefaults(t *testing.T) {
	c := &Config{OAuth: OAuthConfig{Issuer: testIssuerURL}, APIKey: APIKeyConfig{Header: "x-my-key"}}
	c.applyDefaults()
	o := c.OAuth
	if c.Realm != "restricted" || c.APIKey.Header != "X-My-Key" || o.ClockSkew != wantClockSkew ||
		o.KeysCacheTTL != wantKeysTTL || o.FetchTimeout != wantFetchTimeout {
		t.Fatalf("applyDefaults = %+v, want realm, canonical header, skew, TTL and timeout defaults", c)
	}
	if len(o.Resource.AuthorizationServers) != 1 || o.Resource.AuthorizationServers[0] != testIssuerURL {
		t.Fatalf("AuthorizationServers = %v, want [%s]", o.Resource.AuthorizationServers, testIssuerURL)
	}
	c = &Config{APIKey: APIKeyConfig{}}
	c.applyDefaults()
	if c.APIKey.Header != "X-Api-Key" || c.OAuth.Resource.AuthorizationServers != nil {
		t.Fatalf("applyDefaults = %+v, want header X-Api-Key and no authorization servers", c)
	}
}

func TestConfigApplyDefaultsFacade(t *testing.T) {
	c := &Config{OAuth: OAuthConfig{Issuer: testIssuerURL, Facade: FacadeConfig{ClientID: testClientID}}}
	c.applyDefaults()
	if c.OAuth.Resource.AuthorizationServers != nil {
		t.Fatalf("AuthorizationServers = %v, want nil with a facade", c.OAuth.Resource.AuthorizationServers)
	}
}

func TestConfigApplyDefaultsInsecureIssuer(t *testing.T) {
	for _, issuerURL := range []string{"", testNameIssuer, "http://idp.internal"} {
		c := &Config{OAuth: OAuthConfig{Issuer: issuerURL}}
		c.applyDefaults()
		if c.OAuth.Resource.AuthorizationServers != nil {
			t.Fatalf("AuthorizationServers(issuer %q) = %v, want nil", issuerURL, c.OAuth.Resource.AuthorizationServers)
		}
	}
}

func TestAdvertisable(t *testing.T) {
	for issuerURL, want := range map[string]bool{
		testIssuerURL: true, "http://localhost:8080/": true, "": false, testNameIssuer: false,
		"http://idp.internal": false,
	} {
		if got := advertisable(issuerURL); got != want {
			t.Errorf("advertisable(%q) = %t, want %t", issuerURL, got, want)
		}
	}
}

func TestConfigPrepareKeepsIssuerExact(t *testing.T) {
	const auth0 = "https://tenant.auth0.com/"
	cfg := validOAuth()
	cfg.OAuth.Issuer = auth0
	got, err := cfg.prepare()
	if err != nil {
		t.Fatalf("prepare = %v, want nil", err)
	}
	if got.OAuth.Issuer != auth0 {
		t.Fatalf("Issuer = %q, want %q", got.OAuth.Issuer, auth0)
	}
}

func TestConfigCloneIsIndependent(t *testing.T) {
	pin := make([]byte, 32)
	scopes := []string{testAudience}
	servers := []string{testIssuerURL}
	subjects := []string{"s"}
	c := &Config{
		OAuth: OAuthConfig{RequiredScopes: scopes, Resource: ResourceConfig{AuthorizationServers: servers}},
		MTLS:  MTLSConfig{AllowedSubjects: subjects, AllowedSPKIPins: [][]byte{pin}},
	}
	out := c.clone()
	scopes[0], servers[0], subjects[0], pin[0] = anyValue, anyValue, anyValue, 1
	if out.OAuth.RequiredScopes[0] != testAudience || out.OAuth.Resource.AuthorizationServers[0] != testIssuerURL ||
		out.MTLS.AllowedSubjects[0] != "s" || out.MTLS.AllowedSPKIPins[0][0] != 0 {
		t.Fatalf("clone = %+v, want copies unchanged by edits of the original", out)
	}
}

func TestConfigRefuseForeign(t *testing.T) {
	long := secret.New(testLongSecret)
	sections := map[Mode]*Config{
		ModeBearer: {Bearer: BearerConfig{Token: long}},
		ModeAPIKey: {APIKey: APIKeyConfig{Header: "X-Key"}},
		ModeOAuth:  {OAuth: OAuthConfig{Facade: FacadeConfig{ScopePrefix: "api://x"}}},
		ModeMTLS:   {MTLS: MTLSConfig{AllowedSubjects: []string{testCN}}},
	}
	names := map[Mode]string{ModeBearer: "Bearer", ModeAPIKey: "APIKey", ModeOAuth: "OAuth", ModeMTLS: "MTLS"}
	for owner, cfg := range sections {
		for _, mode := range []Mode{ModeNone, ModeBearer, ModeAPIKey, ModeOAuth, ModeMTLS, "", anyValue} {
			c := *cfg
			c.Mode = mode
			p := problems.New(ErrInvalidConfig)
			c.refuseForeign(p)
			want := fmt.Sprintf("%s settings require mode %s", names[owner], owner)
			got := recorded(p)
			switch {
			case mode == owner && len(got) != 0:
				t.Errorf("refuseForeign(%s section, mode %q) = %v, want none", owner, mode, got)
			case mode != owner && (len(got) != 1 || !errors.Is(got[0], ErrInvalidConfig) ||
				!strings.HasSuffix(got[0].Error(), want)):
				t.Errorf("refuseForeign(%s section, mode %q) = %v, want %q", owner, mode, got, want)
			}
		}
	}
}

// TestConfigRefuseForeignEveryField sets each field of each mode section
// alone, down to the fields of nested structs: each is a setting that a
// Config of another mode refuses.
func TestConfigRefuseForeignEveryField(t *testing.T) {
	for _, section := range []struct {
		mode  Mode
		field string
	}{
		{ModeBearer, "Bearer"}, {ModeAPIKey, "APIKey"}, {ModeOAuth, "OAuth"}, {ModeMTLS, "MTLS"},
	} {
		for _, path := range leafFields(reflect.TypeFor[Config](), section.field) {
			cfg := &Config{Mode: ModeNone}
			setField(t, reflect.ValueOf(cfg).Elem(), path)
			if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) ||
				!strings.Contains(err.Error(), section.field+" settings require mode "+string(section.mode)) {
				t.Errorf("Validate(mode none, %s set) = %v, want the %s section refused", path, err, section.field)
			}
		}
	}
}

// leafFields lists the paths, dotted from name, of the fields of the named
// field of t that are not structs holding fields of their own.
func leafFields(t reflect.Type, name string) []string {
	f, _ := t.FieldByName(name)
	if f.Type.Kind() != reflect.Struct || f.Type == reflect.TypeFor[secret.Value]() {
		return []string{name}
	}
	var out []string
	for i := range f.Type.NumField() {
		for _, leaf := range leafFields(f.Type, f.Type.Field(i).Name) {
			out = append(out, name+"."+leaf)
		}
	}
	return out
}

// setField gives the field at path of v, a struct, a non-zero value.
func setField(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	f := v.FieldByName(strings.Split(path, ".")[0])
	if _, rest, nested := strings.Cut(path, "."); nested {
		setField(t, f, rest)
		return
	}
	switch value := f.Addr().Interface().(type) {
	case *string:
		*value = anyValue
	case *bool:
		*value = true
	case *time.Duration:
		*value = time.Second
	case *[]string:
		*value = []string{anyValue}
	case *[][]byte:
		*value = [][]byte{{1}}
	case *secret.Value:
		*value = secret.New(anyValue)
	default:
		t.Fatalf("setField(%s) of type %s = no value, want a non-zero value of every settable type", path, f.Type())
	}
}

func TestLongEnough(t *testing.T) {
	p := problems.New(ErrInvalidConfig)
	if !longEnough(p, "token", secret.New(testLongSecret)) || len(recorded(p)) != 0 {
		t.Fatalf("longEnough(32 bytes) = false or %v, want true and no problem", recorded(p))
	}
	short := strings.Repeat(anyValue, secretFloor-1)
	want := ErrInvalidConfig.Error() + ": token is shorter than 32 bytes"
	ok := longEnough(p, "token", secret.New(short))
	if found := recorded(p); ok || len(found) != 1 || found[0].Error() != want {
		t.Fatalf("longEnough(31 bytes) = %t with %v, want false and %q", ok, found, want)
	}
}

func TestMinSecretLen(t *testing.T) {
	for n, short := range map[int]bool{secretFloor - 1: true, secretFloor: false} {
		v := secret.New(strings.Repeat("k", n))
		oauth := validOAuth()
		oauth.OAuth.HMACSecret = v
		for _, cfg := range []*Config{
			{Mode: ModeBearer, Bearer: BearerConfig{Token: v}},
			{Mode: ModeAPIKey, APIKey: APIKeyConfig{Key: v}},
			oauth,
		} {
			if _, err := New(cfg); short != errors.Is(err, ErrInvalidConfig) {
				t.Errorf("New(%s with %d bytes) = %v, want ErrInvalidConfig %v", cfg.Mode, n, err, short)
			}
		}
	}
}
