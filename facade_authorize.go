package authware

import (
	"crypto/sha256"
	"maps"
	"net/http"
	"net/url"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

// serveAuthorize redirects a PKCE S256 code request to the upstream
// authorization endpoint in the upstream client's terms. Any other request
// gets a 400, never a redirect to its unvalidated redirect_uri.
func (f *facade) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	vals, err := parseParams(r.URL.RawQuery)
	if err != nil {
		badRequest(codeInvalidRequest, descMalformedParams).write(w)
		return
	}
	if e := checkAuthorize(vals); e != nil {
		e.write(w)
		return
	}
	params, up, e := f.relayTarget(r.Context(), vals, f.params.authorize)
	if e != nil {
		e.write(w)
		return
	}
	maps.Copy(params, up.authorizeQuery)
	h := w.Header()
	h.Set("Cache-Control", oauthwire.CacheNoStore)
	h.Set("Location", up.authorizeURL+"?"+params.Encode())
	w.WriteHeader(http.StatusFound)
}

// checkAuthorize accepts a code request with a valid redirect_uri and an
// S256 code_challenge, carrying no request object.
func checkAuthorize(vals url.Values) *endpointError {
	switch {
	case vals.Has(paramRequest) || vals.Has(paramRequestURI):
		return badRequest(codeInvalidRequest, "request objects are not supported")
	case !validRedirectURI(vals.Get(paramRedirectURI)):
		return badRequest(codeInvalidRequest, descBadRedirectURI)
	case vals.Get(paramResponseType) != responseTypeCode:
		return badRequest(codeUnsupportedResponse, "response_type must be code")
	case vals.Get(paramCodeChallengeMethod) != pkceMethodS256:
		return badRequest(codeInvalidRequest, "code_challenge_method must be S256")
	case !validChallenge(vals.Get(paramCodeChallenge)):
		return badRequest(codeInvalidRequest, "code_challenge must be a base64url SHA-256 digest")
	}
	return nil
}

// validChallenge accepts the unpadded base64url encoding of a SHA-256 digest.
func validChallenge(c string) bool {
	var buf [sha256.Size]byte
	d, ok := syntax.AppendSegment(buf[:0], c)
	return ok && len(d) == sha256.Size
}
