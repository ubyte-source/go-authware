package authware

import "net/http"

var _ Authenticator = allowAllAuthenticator{}

var noneIdentity = Identity{Method: ModeNone}

// allowAllAuthenticator permits all requests without credentials.
type allowAllAuthenticator struct{}

func (allowAllAuthenticator) Authenticate(_ *http.Request) (Identity, error) {
	return noneIdentity, nil
}

func (allowAllAuthenticator) Challenge(err error, resourceMetadataURL string) (status int, header, message string) {
	return challengeFromError(defaultRealm, err, resourceMetadataURL)
}

func (allowAllAuthenticator) Metadata(_ string) *ProtectedResourceMetadata {
	return nil
}
