package authware

import (
	"net/http"
)

// AuthCheckHandler returns an HTTP handler for use with nginx auth_request
// or similar reverse-proxy authentication subrequests.
//
// On success it returns 200 with the following response headers:
//
//   - X-Auth-Subject: the authenticated subject
//   - X-Auth-Method: the authentication method used
//   - X-Auth-Scopes: space-separated scopes (if any)
//
// On failure it returns the appropriate HTTP status (401/403) with a
// WWW-Authenticate header for Bearer-based schemes.
//
// Note: the WWW-Authenticate challenge does not include a resource_metadata
// parameter (RFC 9728). If your nginx configuration requires it, proxy through
// a handler that calls auth.Challenge with the full resource metadata URL.
//
// Nginx configuration example:
//
//	location /api {
//	    auth_request /check;
//	    auth_request_set $auth_user $upstream_http_x_auth_subject;
//	}
//	location = /check {
//	    internal;
//	    proxy_pass http://authcheck:9090/check;
//	    proxy_pass_request_headers on;
//	}
func AuthCheckHandler(auth Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.Authenticate(r)
		if err != nil {
			status, header, message := auth.Challenge(err, "")
			if header != "" {
				w.Header().Set("WWW-Authenticate", header)
			}
			http.Error(w, message, status)
			return
		}
		w.Header().Set("X-Auth-Subject", id.Subject)
		w.Header().Set("X-Auth-Method", id.Method)
		if id.Scopes != "" {
			w.Header().Set("X-Auth-Scopes", id.Scopes)
		}
		w.WriteHeader(http.StatusOK)
	})
}
