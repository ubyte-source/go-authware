package authware

import (
	"errors"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// skewSeconds is the default clock skew in seconds.
const skewSeconds = 30

func TestDefaultRealm(t *testing.T) {
	g := mustGate(t, &Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New(testLongSecret)}})
	if g.realm != "restricted" {
		t.Fatalf("realm = %q, want %q", g.realm, "restricted")
	}
}

// TestDefaultClockSkew checks a default OAuth config admits a token expired 30s
// ago and refuses one expired 31s ago as ErrTokenExpired.
func TestDefaultClockSkew(t *testing.T) {
	a := newTestOAuth(t, &validOAuth().OAuth, nil)
	for age, want := range map[int]error{skewSeconds: nil, skewSeconds + 1: ErrTokenExpired} {
		token := signToken(t, algHS256, []byte(testLongSecret), "",
			claimsWith(map[string]any{claimExp: testUnix - age}))
		id, err := a.validateToken(t.Context(), token, time.Unix(testUnix, 0))
		if !errors.Is(err, want) || (err == nil) == (id == nil) {
			t.Errorf("validateToken(expired %ds ago) = %+v, %v, want %v and an identity only without error", age, id,
				err, want)
		}
	}
}
