package authware

import "net/http"

var _ Authenticator = (*bearerAuthenticator)(nil)

var bearerIdentity = &Identity{Method: ModeBearer, Subject: "static-bearer"}

var errInvalidBearerToken = unauthorisedError("invalid bearer token")

type bearerAuthenticator struct {
	realm string
	token string
}

func (a *bearerAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	v := r.Header["Authorization"]
	if len(v) == 0 {
		return nil, errInvalidBearerToken
	}
	token, ok := parseAuthScheme(v[0], "bearer")
	if !ok || !secureEqual(token, a.token) {
		return nil, errInvalidBearerToken
	}
	return bearerIdentity, nil
}

func (a *bearerAuthenticator) Challenge(err error, resourceMetadataURL string) (status int, header, message string) {
	return challengeFromError(a.realm, err, resourceMetadataURL)
}

func (*bearerAuthenticator) Metadata(_ string) *ProtectedResourceMetadata { return nil }
