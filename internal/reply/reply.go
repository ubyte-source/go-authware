package reply

import (
	"io"
	"net/http"
)

// Header names in the canonical form http.Header stores, so they go straight
// into the map.
const (
	// Challenge names WWW-Authenticate, the scheme a client must authenticate with.
	Challenge = "Www-Authenticate"
	// RetryAfter names the header that tells a client when to try again.
	RetryAfter = "Retry-After"
)

// Error answers status, 401, 403 or 503, as http.Error does with the status text
// lowercased, and sets the header name, which must be in canonical form, to value
// unless value is empty.
func Error(w http.ResponseWriter, status int, name, value string) {
	vals := [...]string{"text/plain; charset=utf-8", "nosniff", value}
	h := w.Header()
	delete(h, "Content-Length")
	h["Content-Type"], h["X-Content-Type-Options"] = vals[:1:1], vals[1:2:2]
	if value != "" {
		h[name] = vals[2:]
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body(status)) //nolint:errcheck // a failed write means the client is gone
}

// body returns the body http.Error writes for status, 401, 403 or 503.
func body(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized\n"
	case http.StatusForbidden:
		return "forbidden\n"
	}
	return "service unavailable\n"
}
