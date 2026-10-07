package authware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A realm, the values of a byte and the DEL control byte.
const (
	testRealm  = "r"
	byteValues = 256
	del        = 0x7F
)

func TestChallengeHeader(t *testing.T) {
	invalid := failure(ErrInvalidCredentials, "invalid bearer token", nil)
	missing := failure(ErrMissingCredentials, "no credentials", nil)
	tests := []struct {
		name   string
		scheme string
		e      *authError
		meta   string
		want   string
	}{
		{"bearer invalid", schemeBearer, invalid, "",
			`Bearer realm="r", error="invalid_token", error_description="invalid bearer token"`},
		{"bearer expired", schemeBearer, failure(ErrTokenExpired, "", nil), "",
			`Bearer realm="r", error="invalid_token", error_description="token expired"`},
		{"bearer missing", schemeBearer, missing, "https://x/.well-known/oauth-protected-resource",
			`Bearer realm="r", resource_metadata="https://x/.well-known/oauth-protected-resource"`},
		{"bearer scope", schemeBearer, insufficientScope([]string{"a", "b"}), "https://m",
			`Bearer realm="r", error="insufficient_scope", error_description="missing required scope", ` +
				`scope="a b", resource_metadata="https://m"`},
		{"bearer forbidden", schemeBearer, forbidden(), "https://m", ""},
		{"bearer unavailable", schemeBearer, failure(ErrKeysUnavailable, "down", nil), "https://m", ""},
		{"apikey invalid", schemeAPIKey, invalid, "", `ApiKey realm="r"`},
		{"apikey scope", schemeAPIKey, insufficientScope([]string{"a"}), "", ""},
		{"no scheme", "", invalid, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := challengeHeader(tc.scheme, testRealm, tc.e, tc.meta); got != tc.want {
				t.Fatalf("challengeHeader = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestWriteChallenge(t *testing.T) {
	tests := []struct {
		e     *authError
		body  string
		retry string
	}{
		{failure(ErrInvalidCredentials, "secret detail", nil), "unauthorized\n", ""},
		{insufficientScope([]string{"a"}), "forbidden\n", ""},
		{failure(ErrKeysUnavailable, "idp down", nil), "service unavailable\n", "30"},
	}
	for _, tc := range tests {
		w := httptest.NewRecorder()
		writeChallenge(w, schemeBearer, testRealm, tc.e, "")
		if w.Code != tc.e.status || w.Body.String() != tc.body || w.Header().Get("Retry-After") != tc.retry {
			t.Errorf("writeChallenge(%v) = %d %q retry %q, want %d %q retry %q", tc.e, w.Code, w.Body.String(),
				w.Header().Get("Retry-After"), tc.e.status, tc.body, tc.retry)
		}
	}
	w := httptest.NewRecorder()
	writeChallenge(w, schemeBearer, testRealm, failure(ErrInvalidCredentials, "bad", nil), "")
	if w.Header().Get("WWW-Authenticate") == "" || w.Code != http.StatusUnauthorized {
		t.Fatalf("writeChallenge(Bearer) = %d %v, want 401 with the challenge", w.Code, w.Header())
	}
}

// TestWriteChallengeWithoutScheme answers the refusals of a mode without an
// authentication scheme 403, never a 401 without a challenge.
func TestWriteChallengeWithoutScheme(t *testing.T) {
	for _, e := range []*authError{
		failure(ErrInvalidCredentials, "bad", nil), failure(ErrMissingCredentials, "none", nil), forbidden(),
	} {
		w := httptest.NewRecorder()
		writeChallenge(w, "", testRealm, e, "")
		if w.Header().Values("WWW-Authenticate") != nil || w.Code != http.StatusForbidden ||
			w.Body.String() != "forbidden\n" {
			t.Errorf("writeChallenge(no scheme, %v) = %d %v %q, want 403 forbidden without a challenge", e, w.Code,
				w.Header(), w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	writeChallenge(w, "", testRealm, failure(ErrKeysUnavailable, "down", nil), "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("writeChallenge(no scheme, keys unavailable) = %d %v, want 503 with Retry-After 30", w.Code,
			w.Header())
	}
}

func TestChallenge(t *testing.T) {
	got := challenge("S", [2]string{"realm", "a\"b\\c\r\nd\x7f"}, [2]string{"x", "y"})
	if want := `S realm="a\"b\\c  d ", x="y"`; got != want {
		t.Fatalf("challenge = %s, want %s", got, want)
	}
	if got := challenge("S"); got != "S" {
		t.Fatalf("challenge(no params) = %q, want S", got)
	}
}

// TestChallengeHeaderAllocs renders the longest Bearer challenge, naming two
// scopes, into one allocation: the auth-params stay on the stack, the scope text
// is joined when the refusal is built, and the text is sized first.
func TestChallengeHeaderAllocs(t *testing.T) {
	e := insufficientScope([]string{"a", "b"})
	assertAllocs(t, 1, func() { challengeHeader(schemeBearer, testRealm, e, "https://m") })
}

func TestWriteQuoted(t *testing.T) {
	for i := range byteValues {
		c := byte(i)
		want := string([]byte{c})
		switch {
		case c < ' ' || c == del:
			want = " "
		case c == '"' || c == '\\':
			want = `\` + want
		}
		var b strings.Builder
		writeQuoted(&b, "a"+string([]byte{c})+"z")
		if got := b.String(); got != "a"+want+"z" {
			t.Errorf("writeQuoted(byte %#x) = %q, want %q", c, got, "a"+want+"z")
		}
	}
}
