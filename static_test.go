package authware

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// The repeats of a digit run for a long token, and the header of the API
// key tests.
const (
	longRepeats   = 100
	testKeyHeader = "X-Test-Key"
)

// TestStaticAuthenticatorBearer reads the bearer token from Authorization
// alone, whatever other header carries it.
func TestStaticAuthenticatorBearer(t *testing.T) {
	a := newBearerAuthenticator(BearerConfig{Token: secret.New(testLongSecret)}, defaultRealm)
	tests := []struct {
		name   string
		header http.Header
		want   error
	}{
		{"valid", http.Header{headerAuthorization: {bearerPrefix + testLongSecret}}, nil},
		{"scheme case", http.Header{headerAuthorization: {"bEaReR " + testLongSecret}}, nil},
		{"absent", http.Header{}, ErrMissingCredentials},
		{"unnamed header", http.Header{"": {testLongSecret}}, ErrMissingCredentials},
		{"other scheme", http.Header{headerAuthorization: {"Basic " + testLongSecret}}, ErrMissingCredentials},
		{"wrong", http.Header{headerAuthorization: {bearerPrefix + testLongSecret[1:] + "x"}}, ErrInvalidCredentials},
		{"prefix", http.Header{headerAuthorization: {bearerPrefix + testLongSecret[:len(testLongSecret)/2]}},
			ErrInvalidCredentials},
		{"empty", http.Header{headerAuthorization: {bearerPrefix}}, ErrInvalidCredentials},
		{"two spaces", http.Header{headerAuthorization: {"Bearer  " + testLongSecret}}, ErrInvalidCredentials},
		{"repeated", http.Header{headerAuthorization: {bearerPrefix + testLongSecret, bearerPrefix + testLongSecret}},
			ErrInvalidCredentials},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReq(t, http.MethodGet, "/", http.NoBody)
			r.Header = tc.header
			id, e := a.authenticate(r)
			if tc.want == nil {
				if e != nil || id.Mode() != ModeBearer || id.Subject() != "static-bearer" {
					t.Fatalf("authenticate = %+v, %v, want the static bearer identity", id, e)
				}
				return
			}
			if id != nil || e == nil || !errors.Is(e, tc.want) {
				t.Fatalf("authenticate = %+v, %v, want nil, %v", id, e, tc.want)
			}
		})
	}
}

// TestStaticAuthenticatorAPIKey reads the API key from its header, else from
// Authorization: ApiKey.
func TestStaticAuthenticatorAPIKey(t *testing.T) {
	key := secret.New(testLongSecret)
	cfg := withDefaults(&Config{APIKey: APIKeyConfig{Key: key, Header: strings.ToLower(testKeyHeader)}})
	a := newAPIKeyAuthenticator(cfg.APIKey, defaultRealm)
	tests := []struct {
		name   string
		header http.Header
		want   error
	}{
		{"header", http.Header{testKeyHeader: {testLongSecret}}, nil},
		{"authorization", http.Header{headerAuthorization: {"ApiKey " + testLongSecret}}, nil},
		{"scheme case", http.Header{headerAuthorization: {"apikey " + testLongSecret}}, nil},
		{"absent", http.Header{}, ErrMissingCredentials},
		{"bearer scheme", http.Header{headerAuthorization: {"Bearer " + testLongSecret}}, ErrMissingCredentials},
		{"wrong header", http.Header{testKeyHeader: {"wrong"}}, ErrInvalidCredentials},
		{"repeated header", http.Header{testKeyHeader: {testLongSecret, testLongSecret}}, ErrInvalidCredentials},
		{"wrong authorization", http.Header{headerAuthorization: {"ApiKey wrong"}}, ErrInvalidCredentials},
		{
			"header wins",
			http.Header{testKeyHeader: {"wrong"}, headerAuthorization: {"ApiKey " + testLongSecret}},
			ErrInvalidCredentials,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReq(t, http.MethodGet, "/", http.NoBody)
			r.Header = tc.header
			id, e := a.authenticate(r)
			if tc.want == nil {
				if e != nil || id.Mode() != ModeAPIKey || id.Subject() != "static-apikey" {
					t.Fatalf("authenticate = %+v, %v, want the static API key identity", id, e)
				}
				return
			}
			if id != nil || e == nil || !errors.Is(e, tc.want) {
				t.Fatalf("authenticate = %+v, %v, want nil, %v", id, e, tc.want)
			}
		})
	}
}

func TestNewAPIKeyAuthenticator(t *testing.T) {
	a := newAPIKeyAuthenticator(APIKeyConfig{Key: secret.New(testLongSecret), Header: defaultKeyHeader}, defaultRealm)
	if a.keyHeader != defaultKeyHeader || a.id.Mode() != ModeAPIKey {
		t.Fatalf("authenticator = %+v, want header %s and an API key identity", a, defaultKeyHeader)
	}
}

// TestStaticAuthenticatorChallengeScheme challenges with the scheme of each
// mode and names the mode.
func TestStaticAuthenticatorChallengeScheme(t *testing.T) {
	for _, tc := range []struct {
		a      *staticAuthenticator
		scheme string
		mode   Mode
	}{
		{newBearerAuthenticator(BearerConfig{}, defaultRealm), schemeBearer, ModeBearer},
		{newAPIKeyAuthenticator(APIKeyConfig{}, defaultRealm), schemeAPIKey, ModeAPIKey},
	} {
		if scheme, mode := tc.a.challengeScheme(), tc.a.mode(); scheme != tc.scheme || mode != tc.mode {
			t.Errorf("challengeScheme, mode = %q, %q; want %q, %q", scheme, mode, tc.scheme, tc.mode)
		}
	}
}

func TestMatchesDigest(t *testing.T) {
	want := digestOf(secret.New("expected"))
	matched := []bool{matchesDigest("expected", &want), matchesDigest("expecte", &want), matchesDigest("", &want)}
	if !slices.Equal(matched, []bool{true, false, false}) {
		t.Fatalf("matchesDigest(expected, expecte, empty) = %v, want [true false false]", matched)
	}
	for i := range want {
		near := want
		near[i] ^= 1
		if matchesDigest("expected", &near) {
			t.Fatalf("matchesDigest(digest differing in byte %d) = true, want false", i)
		}
	}
	long := strings.Repeat("0123456789", longRepeats)
	want = digestOf(secret.New(long))
	matched = []bool{matchesDigest(long, &want), matchesDigest(long[:999]+"x", &want), matchesDigest(long[:512], &want)}
	if !slices.Equal(matched, []bool{true, false, false}) {
		t.Fatalf("matchesDigest(1000 bytes, last byte changed, first 512) = %v, want [true false false]", matched)
	}
	assertAllocs(t, 0, func() { matchesDigest(long, &want) })
}

func TestDigestOf(t *testing.T) {
	if got, want := digestOf(secret.New("a")), sha256.Sum256([]byte("a")); got != want {
		t.Fatalf("digestOf(a) = %x, want %x", got, want)
	}
}

func BenchmarkStaticAuthenticator(b *testing.B) {
	// 32 bytes in base64url and in hex, as long as a typical token and key.
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := hex.EncodeToString(make([]byte, 32))
	bearer := newReq(b, http.MethodGet, "/", http.NoBody)
	bearer.Header.Set(headerAuthorization, schemeBearer+" "+token)
	apiKey := newReq(b, http.MethodGet, "/", http.NoBody)
	apiKey.Header.Set(defaultKeyHeader, key)
	for _, bc := range []struct {
		name string
		a    *staticAuthenticator
		r    *http.Request
		mode Mode
	}{
		{"shared token", newBearerAuthenticator(BearerConfig{Token: secret.New(token)}, defaultRealm), bearer,
			ModeBearer},
		{"shared key", newAPIKeyAuthenticator(APIKeyConfig{Key: secret.New(key), Header: defaultKeyHeader},
			defaultRealm), apiKey, ModeAPIKey},
	} {
		b.Run(bc.name, func(b *testing.B) {
			if id, e := bc.a.authenticate(bc.r); e != nil || id.mode != bc.mode {
				b.Fatalf("authenticate = %v, %v, want a %s identity", id, e, bc.mode)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, e := bc.a.authenticate(bc.r); e != nil {
					b.Fatalf("authenticate = %v, want nil", e)
				}
			}
		})
	}
}
