package authware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// staticAuthenticator admits the one shared secret of ModeBearer or ModeAPIKey:
// the value of keyHeader when it is set and sent, else the credential of the
// Authorization scheme. It refuses another secret with invalid.
type staticAuthenticator struct {
	id        *Identity
	scheme    credentialScheme
	invalid   *authError
	repeated  *authError
	keyHeader string
	secretSum [sha256.Size]byte
}

// newBearerAuthenticator returns the authenticator of c, whose refusals
// challenge in realm.
func newBearerAuthenticator(c BearerConfig, realm string) *staticAuthenticator {
	a := &staticAuthenticator{
		id:        &Identity{mode: ModeBearer, subject: "static-bearer"},
		scheme:    newCredentialScheme(schemeBearer),
		invalid:   failure(ErrInvalidCredentials, "invalid bearer token", nil),
		secretSum: digestOf(c.Token),
	}
	a.scheme.render(realm, a.invalid)
	return a
}

// newAPIKeyAuthenticator returns the authenticator of c, which refuses a
// repeated key header with repeated and challenges in realm.
func newAPIKeyAuthenticator(c APIKeyConfig, realm string) *staticAuthenticator {
	a := &staticAuthenticator{
		id:        &Identity{mode: ModeAPIKey, subject: "static-apikey"},
		scheme:    newCredentialScheme(schemeAPIKey),
		invalid:   failure(ErrInvalidCredentials, "invalid API key", nil),
		repeated:  failure(ErrInvalidCredentials, "repeated API key header", nil),
		keyHeader: c.Header,
		secretSum: digestOf(c.Key),
	}
	a.scheme.render(realm, a.invalid, a.repeated)
	return a
}

func (a *staticAuthenticator) authenticate(r *http.Request) (*Identity, *authError) {
	credential, e := a.credential(r)
	if e != nil {
		return nil, e
	}
	if !matchesDigest(credential, &a.secretSum) {
		return nil, a.invalid
	}
	return a.id, nil
}

func (a *staticAuthenticator) challengeScheme() string { return a.scheme.name }

func (a *staticAuthenticator) mode() Mode { return a.id.mode }

// credential returns the value of keyHeader when it is set and sent once, else
// the credential of the Authorization header.
func (a *staticAuthenticator) credential(r *http.Request) (string, *authError) {
	values := r.Header[a.keyHeader]
	switch {
	case a.keyHeader == "" || len(values) == 0:
		return authorizationCredential(r, a.scheme)
	case len(values) > 1:
		return "", a.repeated
	}
	return values[0], nil
}

// digestOf hashes a configured secret for matchesDigest.
func digestOf(v secret.Value) [sha256.Size]byte {
	return sha256.Sum256([]byte(v.Reveal()))
}

// matchesDigest compares the digest of got with want in constant time,
// hiding the secret length; got reaches the hash through a stack chunk.
func matchesDigest(got string, want *[sha256.Size]byte) bool {
	h := sha256.New()
	var chunk [256]byte
	for got != "" {
		n := copy(chunk[:], got)
		_, _ = h.Write(chunk[:n])
		got = got[n:]
	}
	var sum [sha256.Size]byte
	return subtle.ConstantTimeCompare(h.Sum(sum[:0]), want[:]) == 1
}
