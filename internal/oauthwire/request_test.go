package oauthwire

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestNewGetRequest(t *testing.T) {
	t.Parallel()
	u := &url.URL{Scheme: "https", Host: "idp.example.com", Path: "/jwks"}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := NewGetRequest(ctx, u)
	if req.Method != http.MethodGet || req.URL.String() != u.String() || req.Context() != ctx ||
		req.Header == nil || len(req.Header) != 0 || req.Body != nil {
		t.Fatalf("NewGetRequest = %s %v %+v, want a bare GET of %v", req.Method, req.URL, req.Header, u)
	}
	req.URL.Path = "/elsewhere"
	if u.Path != "/jwks" {
		t.Fatalf("u path after request rewrite = %q, want /jwks", u.Path)
	}
}
