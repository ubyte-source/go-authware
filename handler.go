package authware

import (
	"net/http"
	"strings"
)

// AuthCheckHandler returns an HTTP handler compatible with nginx
// auth_request. Success returns 200 with X-Auth-Subject, X-Auth-Method
// and (when non-empty) X-Auth-Scopes. Header values are sanitized
// against control bytes. Both success and failure responses set
// Cache-Control: no-store so a caching reverse proxy never serves
// another caller's identity headers from cache.
func AuthCheckHandler(auth Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		id, err := auth.Authenticate(r)
		if err != nil {
			status, header, message := auth.Challenge(err, "")
			if header != "" {
				w.Header().Set("WWW-Authenticate", header)
			}
			http.Error(w, message, status)
			return
		}
		w.Header().Set("X-Auth-Subject", sanitiseHeaderValue(id.Subject))
		w.Header().Set("X-Auth-Method", sanitiseHeaderValue(string(id.Method)))
		if len(id.Scopes) > 0 {
			w.Header().Set("X-Auth-Scopes", sanitiseHeaderValue(strings.Join(id.Scopes, " ")))
		}
		w.WriteHeader(http.StatusOK)
	})
}

// sanitiseHeaderValue replaces control bytes (< 0x20) and 0x7F with
// spaces to prevent header-injection.
func sanitiseHeaderValue(v string) string {
	for i := range len(v) {
		c := v[i]
		if c < 0x20 || c == 0x7F {
			return sanitiseHeaderValueSlow(v, i)
		}
	}
	return v
}

func sanitiseHeaderValueSlow(v string, start int) string {
	b := make([]byte, len(v))
	copy(b[:start], v[:start])
	for i := start; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c == 0x7F {
			b[i] = ' '
			continue
		}
		b[i] = c
	}
	return string(b)
}
