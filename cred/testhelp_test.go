package cred

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(tb testing.TB, method, target string, body io.Reader) *http.Request {
	tb.Helper()
	return httptest.NewRequestWithContext(tb.Context(), method, target, body)
}

// newHTTPReq builds a standard *http.Request scoped to the test context.
// Errors are fatal — invalid fixtures are bugs in the test, not the code
// under test.
func newHTTPReq(tb testing.TB, method, urlStr string, body io.Reader) *http.Request {
	tb.Helper()
	r, err := http.NewRequestWithContext(tb.Context(), method, urlStr, body)
	if err != nil {
		tb.Fatalf("http.NewRequestWithContext: %v", err)
	}
	return r
}
