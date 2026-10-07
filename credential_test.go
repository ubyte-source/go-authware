package authware

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The credential of the Authorization header cases, and the refusals of a
// missing and of a malformed ApiKey credential.
const (
	testMyKey        = "my-key"
	refusedMissing   = "no ApiKey credentials"
	refusedMalformed = "malformed ApiKey credentials"
)

func TestAuthorizationCredential(t *testing.T) {
	tests := []struct {
		header string
		cred   string
		want   error
		msg    string
	}{
		{"ApiKey my-key", testMyKey, nil, ""},
		{"APIKEY my-key", testMyKey, nil, ""},
		{"Api", "", ErrMissingCredentials, refusedMissing},
		{"ApiKeyX my-key", "", ErrMissingCredentials, refusedMissing},
		{"NotKey my-key", "", ErrMissingCredentials, refusedMissing},
		{"ApiKey", "", ErrMissingCredentials, refusedMissing},
		{"ApiKey ", "", ErrInvalidCredentials, refusedMalformed},
		{"ApiKey k\tv", "", ErrInvalidCredentials, refusedMalformed},
		{"ApiKey k v", "", ErrInvalidCredentials, refusedMalformed},
		{"Api\xe2\x84\xaaey my-key", "", ErrMissingCredentials, refusedMissing},
	}
	scheme := newCredentialScheme(schemeAPIKey)
	for _, tc := range tests {
		r := newReq(t, http.MethodGet, "/", http.NoBody)
		r.Header.Set("Authorization", tc.header)
		got, e := authorizationCredential(r, scheme)
		if tc.want == nil && (e != nil || got != tc.cred) {
			t.Errorf("authorizationCredential(%q) = %q, %v, want %q", tc.header, got, e, tc.cred)
		}
		if tc.want != nil && (got != tc.cred || e == nil || !errors.Is(e, tc.want) || e.msg != tc.msg) {
			t.Errorf("authorizationCredential(%q) = %q, %v, want %q, %v with %q", tc.header, got, e, tc.cred, tc.want,
				tc.msg)
		}
	}
}

func TestAuthorizationCredentialAbsent(t *testing.T) {
	got, e := authorizationCredential(newReq(t, http.MethodGet, "/", http.NoBody), newCredentialScheme(schemeAPIKey))
	if got != "" || e == nil || !errors.Is(e, ErrMissingCredentials) || e.msg != "no credentials" {
		t.Errorf("authorizationCredential(no Authorization) = %q, %v, want \"\", ErrMissingCredentials: no credentials",
			got, e)
	}
}

// TestNewCredentialScheme names the scheme in the refusals it builds.
func TestNewCredentialScheme(t *testing.T) {
	for _, s := range []credentialScheme{newCredentialScheme(schemeBearer), newCredentialScheme(schemeAPIKey)} {
		for _, tc := range []struct {
			e    *authError
			msg  string
			kind error
		}{
			{s.absent, "no credentials", ErrMissingCredentials},
			{s.missing, "no " + s.name + " credentials", ErrMissingCredentials},
			{s.malformed, "malformed " + s.name + " credentials", ErrInvalidCredentials},
			{s.repeated, "repeated Authorization header", ErrInvalidCredentials},
		} {
			if tc.e.msg != tc.msg || !errors.Is(tc.e, tc.kind) {
				t.Errorf("newCredentialScheme(%s) refusal = %q %v, want %q %v", s.name, tc.e.msg, tc.e.class, tc.msg,
					tc.kind)
			}
		}
	}
}

// TestCredentialSchemeRender renders once, in a realm, the challenge of every
// refusal of a scheme and of the others it is given.
func TestCredentialSchemeRender(t *testing.T) {
	const challenged = `Bearer realm="api", error="invalid_token", error_description=`
	s := newCredentialScheme(schemeBearer)
	other := failure(ErrInvalidCredentials, "invalid bearer token", nil)
	s.render("api", other)
	for e, want := range map[*authError]string{
		s.absent: `Bearer realm="api"`, s.missing: `Bearer realm="api"`,
		s.malformed: challenged + `"malformed Bearer credentials"`,
		s.repeated:  challenged + `"repeated Authorization header"`, other: challenged + `"invalid bearer token"`,
	} {
		if e.rendered != want {
			t.Errorf("render: challenge of %q = %s, want %s", e.msg, e.rendered, want)
		}
	}
}

// tokenPattern matches an HTTP token, the form of an authentication scheme.
var tokenPattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// FuzzAuthorizationCredential checks one or two Authorization values against
// a reference: two are invalid, and one holds a credential after a token that
// is the scheme in any ASCII case, a space, then no space or tab.
func FuzzAuthorizationCredential(f *testing.F) {
	for _, seed := range []string{
		"Bearer abc", "bEaReR abc", "Basic abc", schemeBearer, bearerPrefix, "Bearer a b", "Bearer a\tb", "Bearer  abc",
		" Bearer abc", "B\u212aarer abc", "Bearer\tabc",
	} {
		f.Add(seed, "", false)
	}
	f.Add("Bearer abc", "Bearer abc", true)
	f.Fuzz(func(t *testing.T, first, second string, repeated bool) {
		values := []string{first}
		if repeated {
			values = append(values, second)
		}
		want, wantErr := referenceCredential(values)
		got, e := authorizationCredential(&http.Request{Header: http.Header{headerAuthorization: values}},
			newCredentialScheme(schemeBearer))
		if got != want || (wantErr == nil) != (e == nil) || wantErr != nil && !errors.Is(e, wantErr) {
			t.Fatalf("authorizationCredential(%q) = %q, %v, want %q, %v", values, got, e, want, wantErr)
		}
	})
}

// referenceCredential returns the bearer credential of the Authorization
// values, or the sentinel of their refusal.
func referenceCredential(values []string) (string, error) {
	if len(values) > 1 {
		return "", ErrInvalidCredentials
	}
	scheme, credential, found := strings.Cut(values[0], " ")
	switch {
	case !found || !tokenPattern.MatchString(scheme) || !strings.EqualFold(scheme, schemeBearer):
		return "", ErrMissingCredentials
	case credential == "" || strings.ContainsAny(credential, " \t"):
		return "", ErrInvalidCredentials
	}
	return credential, nil
}

// TestAuthorizationCredentialAllocs refuses a foreign or malformed credential
// without allocating: the scheme holds its refusals.
func TestAuthorizationCredentialAllocs(t *testing.T) {
	scheme := newCredentialScheme(schemeBearer)
	for _, tc := range []struct {
		header string
		want   error
	}{{"Basic abc", ErrMissingCredentials}, {"Bearer a b", ErrInvalidCredentials}} {
		r := &http.Request{Header: http.Header{headerAuthorization: {tc.header}}}
		assertAllocs(t, 0, func() {
			if got, e := authorizationCredential(r, scheme); got != "" || !errors.Is(e, tc.want) {
				t.Fatalf("authorizationCredential(%q) = %q, %v, want \"\", %v", tc.header, got, e, tc.want)
			}
		})
	}
}
