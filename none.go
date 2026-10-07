package authware

import "net/http"

// noneAuthenticator admits every request.
type noneAuthenticator struct {
	id *Identity
}

func newNoneAuthenticator() *noneAuthenticator {
	return &noneAuthenticator{id: &Identity{mode: ModeNone}}
}

func (a *noneAuthenticator) authenticate(*http.Request) (*Identity, *authError) {
	return a.id, nil
}

func (*noneAuthenticator) challengeScheme() string { return "" }

func (*noneAuthenticator) mode() Mode { return ModeNone }
