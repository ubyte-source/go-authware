package authware

import "net/http"

var _ Authenticator = (*bearerAuthenticator)(nil)

var bearerIdentity = Identity{Method: ModeBearer, Subject: "static-bearer"}
var errInvalidBearerToken = unauthorizedError("invalid bearer token")

type bearerAuthenticator struct {
	realm string
	token string // bare token without "Bearer " prefix
}

func (a *bearerAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	v := r.Header["Authorization"]
	if len(v) == 0 {
		return Identity{}, errInvalidBearerToken
	}
	token, ok := bearerToken(v[0])
	if !ok || !secureEqual(token, a.token) {
		return Identity{}, errInvalidBearerToken
	}
	return bearerIdentity, nil
}

func (a *bearerAuthenticator) Challenge(err error, resourceMetadataURL string) (status int, header, message string) {
	return challengeFromError(a.realm, err, resourceMetadataURL)
}

func (a *bearerAuthenticator) Metadata(_ string) *ProtectedResourceMetadata {
	return nil
}
