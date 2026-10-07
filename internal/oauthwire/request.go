package oauthwire

import (
	"context"
	"net/http"
	"net/url"
)

// NewGetRequest builds a GET of a copy of u, which passed the outbound URL
// policy.
func NewGetRequest(ctx context.Context, u *url.URL) *http.Request {
	return newRequest(ctx, http.MethodGet, u)
}

// newRequest builds a bodiless request to a copy of u by hand, as
// http.NewRequestWithContext would parse u again.
func newRequest(ctx context.Context, method string, u *url.URL) *http.Request {
	target := *u
	return (&http.Request{Method: method, URL: &target, Header: http.Header{}}).WithContext(ctx)
}
