package authware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newReq builds a request scoped to the test's context. Centralized here
// to keep call-sites short and to avoid the noctx linter on every site.
func newReq(tb testing.TB, method, target string, body io.Reader) *http.Request {
	tb.Helper()
	return httptest.NewRequestWithContext(tb.Context(), method, target, body)
}
