package authware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestFailure(t *testing.T) {
	tests := []struct {
		kind   error
		code   string
		status int
	}{
		{ErrMissingCredentials, "", http.StatusUnauthorized},
		{ErrInvalidCredentials, codeInvalidToken, http.StatusUnauthorized},
		{ErrTokenExpired, codeInvalidToken, http.StatusUnauthorized},
		{ErrInsufficientScope, "", http.StatusForbidden},
		{ErrKeysUnavailable, "", http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		e := failure(tc.kind, "m", nil)
		if e.status != tc.status || e.code != tc.code || !errors.Is(e, tc.kind) {
			t.Errorf("failure(%v) = status %d code %q, want %d %q matching the kind", tc.kind, e.status, e.code,
				tc.status, tc.code)
		}
	}
}

func TestInsufficientScope(t *testing.T) {
	e := insufficientScope([]string{testRead, testWrite})
	if e.status != http.StatusForbidden || e.code != codeInsufficientScope ||
		e.scope != testReadW || !errors.Is(e, ErrInsufficientScope) {
		t.Fatalf("insufficientScope = %+v, want a 403 insufficient_scope naming %q", e, testReadW)
	}
}

func TestAuthErrorError(t *testing.T) {
	tests := []struct {
		err  *authError
		want string
	}{
		{failure(ErrInvalidCredentials, "bad", nil), "authware: invalid credentials: bad"},
		{failure(ErrTokenExpired, "", nil), "authware: token expired"},
		{failure(ErrTokenExpired, "exp passed", nil), "authware: token expired: exp passed"},
		{failure(ErrKeysUnavailable, "verification keys unavailable", errUpstream),
			"authware: verification keys unavailable: test: upstream failed"},
		{failure(ErrInvalidCredentials, string(errSignature), errSignature),
			"authware: invalid credentials: invalid JWT signature"},
	}
	for _, tc := range tests {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

func TestAuthErrorIsUnwrap(t *testing.T) {
	e := failure(ErrKeysUnavailable, "keys unavailable", context.DeadlineExceeded)
	if !errors.Is(e, ErrKeysUnavailable) || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(%v) = false, want the kind and the cause to match", e)
	}
	if errors.Is(e, ErrInvalidCredentials) {
		t.Fatalf("errors.Is(%v, ErrInvalidCredentials) = true, want false", e)
	}
}

func TestTokenErrorError(t *testing.T) {
	if got := errMalformedToken.Error(); got != "malformed token" {
		t.Fatalf("Error() = %q, want %q", got, "malformed token")
	}
}

func TestErrInsecureURL(t *testing.T) {
	cfg := &Config{Mode: ModeOAuth, OAuth: OAuthConfig{Issuer: "http://idp.example", Audience: "a"}}
	_, err := New(cfg)
	if !errors.Is(err, ErrInsecureURL) || !errors.Is(err, ErrInvalidConfig) ||
		strings.Count(err.Error(), "authware:") != 1 {
		t.Fatalf("New = %v, want ErrInvalidConfig wrapping ErrInsecureURL under one package prefix", err)
	}
}
