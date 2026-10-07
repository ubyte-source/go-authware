package authware

import (
	"net/http"
	"testing"
)

func TestNewNoneAuthenticator(t *testing.T) {
	a := newNoneAuthenticator()
	id, e := a.authenticate(newReq(t, http.MethodGet, "/", http.NoBody))
	if e != nil || id.Mode() != ModeNone || id.Subject() != "" {
		t.Fatalf("authenticate = %+v, %v, want an anonymous ModeNone identity", id, e)
	}
}
