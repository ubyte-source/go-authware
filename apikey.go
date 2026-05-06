package authware

import (
	"crypto/subtle"
	"net/http"
)

var _ Authenticator = (*apiKeyAuthenticator)(nil)

var apiKeyIdentity = &Identity{Method: ModeAPIKey, Subject: "static-apikey"}

var errInvalidAPIKey = &authError{status: http.StatusUnauthorized, message: "invalid API key"}

type apiKeyAuthenticator struct {
	realm  string
	header string
	value  string
}

func (a *apiKeyAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	if v := r.Header[a.header]; len(v) > 0 && secureEqual(v[0], a.value) {
		return apiKeyIdentity, nil
	}
	if v := r.Header["Authorization"]; len(v) > 0 {
		if token, ok := parseAuthScheme(v[0], "apikey"); ok && secureEqual(token, a.value) {
			return apiKeyIdentity, nil
		}
	}
	return nil, errInvalidAPIKey
}

func (a *apiKeyAuthenticator) Challenge(err error, resourceMetadataURL string) (status int, header, message string) {
	return challengeFromError(a.realm, err, resourceMetadataURL)
}

func (*apiKeyAuthenticator) Metadata(_ string) *ProtectedResourceMetadata { return nil }

// secureEqual performs a constant-time string comparison.
func secureEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
