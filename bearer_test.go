package authware

import (
	"errors"
	"testing"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

func TestBearerConfigInUse(t *testing.T) {
	for token, want := range map[string]bool{"": false, anyValue: true} {
		if got := (&BearerConfig{Token: secret.New(token)}).inUse(); got != want {
			t.Errorf("inUse(token %q) = %t, want %t", token, got, want)
		}
	}
}

// TestBearerConfigValidate accepts a token of 32 bytes that a header carries
// after the scheme, and refuses a shorter one or one with a space, a tab or a
// control byte.
func TestBearerConfigValidate(t *testing.T) {
	for token, want := range map[string]int{
		testLongSecret: 0, testLongSecret[1:]: 1, testLongSecret[1:] + " ": 1, testLongSecret[1:] + "\t": 1,
		testLongSecret[1:] + "\x00": 1, testLongSecret[2:]: 1,
	} {
		p := problems.New(ErrInvalidConfig)
		(&BearerConfig{Token: secret.New(token)}).validate(p)
		if got := recorded(p); len(got) != want || want > 0 && !errors.Is(p.Err(), ErrInvalidConfig) {
			t.Errorf("validate(token %q) = %v, want %d problems wrapping ErrInvalidConfig", token, got, want)
		}
	}
}
