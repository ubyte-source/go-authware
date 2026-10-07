package authware

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

var (
	errUpstreamStatus = errors.New("upstream answered neither 2xx nor 4xx")
	errBodyNotAllowed = errors.New("upstream answered 204 with a body")
)

// serveToken relays a code or refresh grant to the upstream token endpoint with the
// client parameters rewritten and the upstream client credentials added, and returns
// uncached a 2xx or 4xx upstream answer of at most 1 MiB other than a 204 with a body.
func (f *facade) serveToken(w http.ResponseWriter, r *http.Request) {
	vals, e := readTokenRequest(r)
	if e != nil {
		e.write(w)
		return
	}
	params, up, e := f.relayTarget(r.Context(), vals, f.params.token)
	if e != nil {
		e.write(w)
		return
	}
	ans, err := f.post(r.Context(), up.tokenURL, params)
	if err != nil {
		level := slog.LevelWarn
		if ctx := r.Context(); errors.Is(ctx.Err(), context.Canceled) &&
			(errors.Is(err, context.Canceled) || errors.Is(err, context.Cause(ctx))) {
			level = slog.LevelDebug
		}
		f.idp.log.LogAttrs(r.Context(), level, errPrefix+"token relay failed", slog.Any("error", err))
		unavailable().write(w)
		return
	}
	writeUpstreamAnswer(w, ans)
}

// readTokenRequest decodes a form of unique parameters that checkGrant
// accepts.
func readTokenRequest(r *http.Request) (url.Values, *endpointError) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != oauthwire.FormContentType {
		return nil, badRequest(codeInvalidRequest, "content type must be "+oauthwire.FormContentType)
	}
	body, err := netguard.ReadRequest(r, maxFacadeBodyBytes, errBodyTooLarge)
	if err != nil {
		return nil, badRequest(codeInvalidRequest, descUnreadableBody)
	}
	vals, err := parseParams(string(body))
	if err != nil {
		return nil, badRequest(codeInvalidRequest, descMalformedParams)
	}
	if e := checkGrant(vals); e != nil {
		return nil, e
	}
	return vals, nil
}

// checkGrant accepts a refresh grant, or a code grant with a well-formed
// code_verifier, whose redirect_uri, when sent, is valid.
func checkGrant(vals url.Values) *endpointError {
	switch vals.Get(oauthwire.ParamGrantType) {
	case grantAuthorizationCode:
		if !validVerifier(vals.Get(paramCodeVerifier)) {
			return badRequest(codeInvalidRequest, "code_verifier is missing or malformed")
		}
	case oauthwire.GrantRefreshToken:
	default:
		return badRequest(codeUnsupportedGrantType, "grant_type must be authorization_code or refresh_token")
	}
	if vals.Has(paramRedirectURI) && !validRedirectURI(vals.Get(paramRedirectURI)) {
		return badRequest(codeInvalidRequest, descBadRedirectURI)
	}
	return nil
}

// Length bounds of a PKCE code_verifier.
const (
	minVerifierLen = 43
	maxVerifierLen = 128
)

// validVerifier accepts 43 to 128 unreserved URI characters.
func validVerifier(v string) bool {
	if len(v) < minVerifierLen || len(v) > maxVerifierLen {
		return false
	}
	for i := range len(v) {
		if !syntax.IsUnreserved(v[i]) {
			return false
		}
	}
	return true
}

// post sends vals, authenticated as the upstream client in the form body, to endpoint
// through the client that refuses redirects. A failed send, read or close, an oversized
// body, a status neither 2xx nor 4xx and a 204 with a body are upstream failures.
func (f *facade) post(ctx context.Context, endpoint *url.URL, vals url.Values) (oauthwire.Answer, error) {
	oauthwire.SetClientParams(vals, f.params.clientID, f.secret.Reveal())
	req := oauthwire.NewTokenRequest(ctx, endpoint, vals)
	ans, err := oauthwire.Send(f.idp.client, req, errBodyTooLarge)
	switch {
	case err != nil:
		return oauthwire.Answer{}, err
	case ans.Status < http.StatusOK,
		ans.Status >= http.StatusMultipleChoices && ans.Status < http.StatusBadRequest,
		ans.Status >= http.StatusInternalServerError:
		return oauthwire.Answer{}, fmt.Errorf("%w: status %d", errUpstreamStatus, ans.Status)
	case ans.Status == http.StatusNoContent && len(ans.Body) > 0:
		return oauthwire.Answer{}, errBodyNotAllowed
	}
	return ans, nil
}

// writeUpstreamAnswer copies a 2xx or 4xx upstream answer other than a 204 with a
// body: its status, body, Content-Type and WWW-Authenticate, marked uncacheable.
func writeUpstreamAnswer(w http.ResponseWriter, ans oauthwire.Answer) {
	h := w.Header()
	h["Content-Type"] = nil // no sniffed type when the answer has none
	for _, k := range []string{"Content-Type", "WWW-Authenticate"} {
		for _, v := range ans.Header.Values(k) {
			h.Add(k, v)
		}
	}
	h.Set("Cache-Control", oauthwire.CacheNoStore)
	h.Set("Pragma", oauthwire.PragmaNoCache)
	// net/http's HTTP/2 server refuses even an empty write after a 204.
	if len(ans.Body) == 0 {
		w.WriteHeader(ans.Status)
		return
	}
	oauthwire.WriteBody(w, ans.Status, ans.Body)
}
