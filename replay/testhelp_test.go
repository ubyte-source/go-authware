package replay

import (
	"io"
	"net/http"
	"testing"
)

// newHTTPReq builds a standard *http.Request scoped to the test context.
// Replay tests prefer http.NewRequestWithContext over httptest.NewRequest
// because the helpers exercise URL parsing on absolute URLs.
func newHTTPReq(tb testing.TB, method, urlStr string, body io.Reader) *http.Request {
	tb.Helper()
	r, err := http.NewRequestWithContext(tb.Context(), method, urlStr, body)
	if err != nil {
		tb.Fatalf("http.NewRequestWithContext: %v", err)
	}
	return r
}
