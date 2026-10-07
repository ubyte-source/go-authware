package cred

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// basicUser is the user of the Basic tests.
const (
	basicUser = "svc"
)

func TestBasic(t *testing.T) {
	tok, err := Basic(basicUser, secret.New("p:w"))
	if err != nil {
		t.Fatalf("Basic = %v, want a token", err)
	}
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	tok.Apply(r)
	user, password, ok := r.BasicAuth()
	if !ok || user != basicUser || password != "p:w" {
		t.Fatalf("BasicAuth() = %q, %q, %v, want svc, p:w", user, password, ok)
	}
	if tok, err = Basic(basicUser, secret.Value{}); err != nil || tok.Value.Reveal() != "c3ZjOg==" {
		t.Fatalf("Basic(svc, empty) = %v, %v, want c3ZjOg==", tok, err)
	}
	if tok, err = Basic(basicUser, secret.New(">>>")); err != nil || tok.Value.Reveal() != "c3ZjOj4+Pg==" {
		t.Fatalf("Basic(svc, >>>) = %v, %v, want the standard alphabet c3ZjOj4+Pg==", tok, err)
	}
}

func TestBasicRejects(t *testing.T) {
	for _, user := range []string{"", "a:b", "svc\n", " svc", "s\x00vc"} {
		if _, err := Basic(user, secret.New("p")); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Basic(%q) err = %v, want ErrInvalidConfig", user, err)
		}
	}
}
