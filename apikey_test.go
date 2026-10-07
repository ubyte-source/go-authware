package authware

import (
	"errors"
	"testing"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

func TestAPIKeyConfigInUse(t *testing.T) {
	for _, tc := range []struct {
		cfg  APIKeyConfig
		want bool
	}{
		{APIKeyConfig{}, false},
		{APIKeyConfig{Key: secret.New(anyValue)}, true},
		{APIKeyConfig{Header: anyValue}, true},
	} {
		if got := tc.cfg.inUse(); got != tc.want {
			t.Errorf("inUse(%+v) = %t, want %t", tc.cfg, got, tc.want)
		}
	}
}

// TestAPIKeyConfigValidate accepts a key of 32 bytes that a header carries,
// and a header name that is a token; it refuses anything else.
func TestAPIKeyConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		key, header string
		want        int
	}{
		{testLongSecret, defaultKeyHeader, 0},
		{testLongSecret + " x", defaultKeyHeader, 0},
		{testLongSecret[1:], defaultKeyHeader, 1},
		{testLongSecret + "\n", defaultKeyHeader, 1},
		{testLongSecret, "X Key", 1},
		{testLongSecret, "", 1},
		{"", "", 2},
	} {
		p := problems.New(ErrInvalidConfig)
		(&APIKeyConfig{Key: secret.New(tc.key), Header: tc.header}).validate(p)
		if got := recorded(p); len(got) != tc.want || tc.want > 0 && !errors.Is(p.Err(), ErrInvalidConfig) {
			t.Errorf("validate(%q, %q) = %v, want %d problems wrapping ErrInvalidConfig", tc.key, tc.header, got,
				tc.want)
		}
	}
}
