package cred

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Invalidator drops a token that the server rejected. Implementations must be
// safe for concurrent use.
type Invalidator interface {
	// Invalidate receives stale, the token the server rejected.
	Invalidate(stale *Token)
}

type invalidatingSource interface {
	TokenSource
	Invalidator
}

// signedTransport signs every request with signer and sends none that follows a
// redirect.
type signedTransport struct {
	base   http.RoundTripper
	signer Signer
}

// renewingTransport signs with the tokens of renewer, drops a token answered
// with 401 and then retries a replayable request once; it sends no request that
// follows a redirect.
type renewingTransport struct {
	base    http.RoundTripper
	renewer invalidatingSource
}

// NewTransport signs a clone of each request through base or http.DefaultTransport with
// s, not nil, or with a copy of s when it is a *Token, and refuses with ErrRedirect a
// request that follows a redirect. AsSigner over an Invalidator adds the 401 renewal.
func NewTransport(base http.RoundTripper, s Signer) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	switch signer := s.(type) {
	case *tokenSigner:
		if renewer, ok := signer.src.(invalidatingSource); ok {
			return &renewingTransport{base: base, renewer: renewer}
		}
	case *Token:
		s = signer.shared()
	}
	return &signedTransport{base: base, signer: s}
}

// RoundTrip sends a clone of r signed by the signer, or refuses r with ErrRedirect
// when it follows a redirect.
func (t *signedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Response != nil {
		return nil, unsent(ErrRedirect, r.Body)
	}
	return sendSigned(t.base, r, r.Body, t.signer)
}

// RoundTrip sends a clone of r with a token of the source, or refuses r with
// ErrRedirect when it follows a redirect. A 401 invalidates the token; a
// replayable request is then sent once more when the source yields another.
func (t *renewingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Response != nil {
		return nil, unsent(ErrRedirect, r.Body)
	}
	resp, tok, err := t.send(r)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	t.renewer.Invalidate(tok)
	if !replayable(r) {
		return resp, nil
	}
	fresh := t.renewal(r.Context(), tok)
	if fresh == nil {
		return resp, nil
	}
	body, ok := replayBody(r)
	if !ok {
		return resp, nil
	}
	drain(resp.Body)
	return sendSigned(t.base, r, body, fresh)
}

// send sends a clone of r signed with a token of the source and returns that
// token.
func (t *renewingTransport) send(r *http.Request) (*http.Response, *Token, error) {
	tok, err := fetchToken(r.Context(), t.renewer)
	if err != nil {
		return nil, nil, unsent(credentialError(err), r.Body)
	}
	resp, err := sendSigned(t.base, r, r.Body, tok)
	if err != nil {
		return nil, nil, err
	}
	return resp, tok, nil
}

// renewal returns the token the source yields in place of stale, or nil when
// it fails or yields stale again.
func (t *renewingTransport) renewal(ctx context.Context, stale *Token) *Token {
	fresh, err := fetchToken(ctx, t.renewer)
	if err != nil || fresh == stale {
		return nil
	}
	return fresh
}

// sendSigned sends through base a clone of r carrying body and signed by s.
func sendSigned(base http.RoundTripper, r *http.Request, body io.ReadCloser, s Signer) (*http.Response, error) {
	ctx := r.Context()
	clone := r.Clone(ctx)
	clone.Body = body
	if err := s.Sign(ctx, clone); err != nil {
		return nil, unsent(credentialError(err), clone.Body)
	}
	return base.RoundTrip(clone)
}

// unsent closes the body of a request that is not sent and returns err joined
// with a failed close.
func unsent(err error, body io.ReadCloser) error {
	if body == nil || body == http.NoBody {
		return err
	}
	if cerr := body.Close(); cerr != nil {
		return errors.Join(err, fmt.Errorf(errPrefix+"close request body: %w", cerr))
	}
	return err
}

// replayable reports whether r can be sent again: it has GetBody or no body.
func replayable(r *http.Request) bool {
	return r.GetBody != nil || r.Body == nil || r.Body == http.NoBody
}

// replayBody returns the body of a second send of r, which is replayable: a
// fresh GetBody copy, or r.Body without GetBody. It reports false when GetBody
// fails.
func replayBody(r *http.Request) (io.ReadCloser, bool) {
	if r.GetBody == nil {
		return r.Body, true
	}
	body, err := r.GetBody()
	if err != nil {
		return nil, false
	}
	return body, true
}

const maxDrain = 4 << 10

// drain reads at most maxDrain bytes of a dropped answer, so that its
// connection can be reused, and closes it.
func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxDrain)) //nolint:errcheck // a dropped read has no receiver
	_ = body.Close()                                           //nolint:errcheck // a dropped close has no receiver
}
