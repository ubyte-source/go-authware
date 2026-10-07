package authware

import (
	"net/http"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

const headerAuthorization = "Authorization"

// credentialScheme is an Authorization scheme with the refusals of a request
// without Authorization, with credentials of another scheme, with malformed
// credentials and with Authorization repeated, each built once.
type credentialScheme struct {
	name      string
	absent    *authError
	missing   *authError
	malformed *authError
	repeated  *authError
}

// newCredentialScheme returns the Authorization scheme name, an ASCII token,
// with its refusals.
func newCredentialScheme(name string) credentialScheme {
	return credentialScheme{
		name:      name,
		absent:    failure(ErrMissingCredentials, "no credentials", nil),
		missing:   failure(ErrMissingCredentials, "no "+name+" credentials", nil),
		malformed: failure(ErrInvalidCredentials, "malformed "+name+" credentials", nil),
		repeated:  failure(ErrInvalidCredentials, "repeated Authorization header", nil),
	}
}

// render gives the refusals of s, and others, their challenge in realm, rendered
// once for a gate whose challenges no request changes.
func (s credentialScheme) render(realm string, others ...*authError) {
	for _, e := range append([]*authError{s.absent, s.missing, s.malformed, s.repeated}, others...) {
		e.rendered = challengeHeader(s.name, realm, e, "")
	}
}

// authorizationCredential returns the credential of the single Authorization
// header whose scheme, an ASCII token compared case-insensitively, is s.
func authorizationCredential(r *http.Request, s credentialScheme) (string, *authError) {
	values := r.Header[headerAuthorization]
	if len(values) > 1 {
		return "", s.repeated
	}
	if len(values) == 0 {
		return "", s.absent
	}
	name, credential, found := strings.Cut(values[0], " ")
	if !found || !syntax.IsToken(name) || !strings.EqualFold(name, s.name) {
		return "", s.missing
	}
	if credential == "" || strings.ContainsAny(credential, " \t") {
		return "", s.malformed
	}
	return credential, nil
}
