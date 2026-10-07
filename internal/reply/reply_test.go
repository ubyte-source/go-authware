package reply

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status              int
		name, header, value string
	}{
		{http.StatusUnauthorized, Challenge, "WWW-Authenticate", `Bearer realm="r"`},
		{http.StatusForbidden, Challenge, "WWW-Authenticate", ""},
		{http.StatusServiceUnavailable, RetryAfter, "Retry-After", "30"},
	} {
		got, want := stale(), stale()
		Error(got, tc.status, tc.name, tc.value)
		if tc.value != "" {
			want.Header().Set(tc.header, tc.value)
		}
		http.Error(want, strings.ToLower(http.StatusText(tc.status)), tc.status)
		if got.Code != want.Code || got.Body.String() != want.Body.String() ||
			!maps.EqualFunc(got.Header(), want.Header(), slices.Equal[[]string]) {
			t.Errorf("Error(%d, %s, %q) = %d %v %q, want %d %v %q", tc.status, tc.name, tc.value,
				got.Code, got.Header(), got.Body, want.Code, want.Header(), want.Body)
		}
	}
}

// stale returns a recorder whose header holds values an answer must replace.
func stale() *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Length", "99")
	rec.Header().Set("Content-Type", "application/json")
	return rec
}

// discard is a ResponseWriter that keeps only its header.
type discard struct{ h http.Header }

func (d *discard) Header() http.Header { return d.h }

func (*discard) Write(b []byte) (int, error) { return len(b), nil }

func (*discard) WriteString(s string) (int, error) { return len(s), nil }

func (*discard) WriteHeader(int) {}

// TestErrorAllocs pins the one allocation of an error reply: the array of its
// header values.
func TestErrorAllocs(t *testing.T) {
	w := &discard{h: make(http.Header, 4)}
	assertAllocs(t, 1, func() {
		clear(w.h)
		Error(w, http.StatusUnauthorized, Challenge, "Bearer")
	})
}
