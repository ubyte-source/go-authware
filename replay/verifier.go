package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/reply"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// Verifier checks the anti-replay envelope of inbound requests; a proxy in
// front of it that rewrites the host or re-escapes the path breaks the check.
// It is safe for concurrent use.
type Verifier struct {
	verifierConfig

	mac   *macScratch
	store NonceStore
}

var errNilStore = fmt.Errorf("%w: nil nonce store", ErrInvalidConfig)

// NewVerifier returns a Verifier keyed with key, which must hold at least 32 bytes,
// recording nonces in store, which must not be nil; a short key, a nil store or an
// option out of range fails with an error wrapping [ErrInvalidConfig].
func NewVerifier(key secret.Value, store NonceStore, opts ...VerifierOption) (*Verifier, error) {
	if store == nil {
		return nil, errNilStore
	}
	c, err := newVerifierConfig(opts)
	if err != nil {
		return nil, err
	}
	mac, err := newMACScratch(key)
	if err != nil {
		return nil, err
	}
	return &Verifier{mac: mac, store: store, verifierConfig: c}, nil
}

// Verify checks the headers, the timestamp window and the signature of r, records
// the nonce and checks the window again; it restores a body it reads in full.
// Errors that blame the request wrap [ErrRejected]; a store failure wraps its error.
func (v *Verifier) Verify(ctx context.Context, r *http.Request) error {
	env, err := readEnvelope(r.Header)
	if err != nil {
		return err
	}
	if !v.admits(env.unix) {
		return ErrTimestampSkew
	}
	var body *[sha256.Size]byte
	if hasBody(r) {
		var sum [sha256.Size]byte
		if sum, err = bodyDigest(r); err != nil {
			return err
		}
		body = &sum
	}
	st := v.mac.get()
	defer v.mac.put(st)
	b := strconv.AppendInt(st.input(r, body), env.unix, decimalBase)
	st.buf = append(append(b, '\n'), env.nonce...)
	var want [hexSigLen]byte
	hex.Encode(want[:], v.mac.keyedSum(st, st.buf))
	if subtle.ConstantTimeCompare(want[:], []byte(env.signature)) != 1 {
		return ErrInvalidSignature
	}
	return v.record(ctx, env.nonce, env.unix)
}

// retryAfter is the Retry-After, in seconds, of the answer to a store failure.
const retryAfter = "1"

// Middleware passes next each request v verifies, a copy with the body restored
// when it has one, and changes no field of the caller's; it answers a rejected
// request 401 naming HeaderSignature, and 503 with Retry-After when the store fails.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified := r
		if hasBody(r) {
			c := *r
			verified = &c
		}
		err := v.Verify(r.Context(), verified)
		switch {
		case err == nil:
			next.ServeHTTP(w, verified)
		case errors.Is(err, ErrRejected):
			reply.Error(w, http.StatusUnauthorized, reply.Challenge, HeaderSignature)
		default:
			reply.Error(w, http.StatusServiceUnavailable, reply.RetryAfter, retryAfter)
		}
	})
}

// admits reports whether the window admits the timestamp unix now, from
// unix-window until unix+window+1s.
func (v *Verifier) admits(unix int64) bool {
	return withinWindow(time.Now().Unix(), unix, int64(v.window/time.Second))
}

// record records nonce until the window stops admitting the timestamp unix, and
// refuses a nonce Seen finds fresh after that: the store may have dropped the
// record of an earlier use by then.
func (v *Verifier) record(ctx context.Context, nonce string, unix int64) error {
	fresh, err := v.store.Seen(ctx, nonce, time.Unix(unix, 0).Add(v.window+time.Second))
	switch {
	case err != nil:
		return fmt.Errorf(errPrefix+"nonce store: %w", err)
	case !fresh:
		return ErrNonceReplayed
	case !v.admits(unix):
		return ErrTimestampSkew
	}
	return nil
}

// envelope is the parsed, canonical form of the three headers.
type envelope struct {
	nonce     string
	signature string
	unix      int64
}

// readEnvelope requires each header exactly once, in canonical form.
func readEnvelope(h http.Header) (envelope, error) {
	ts, nonce, sig := h[HeaderTimestamp], h[HeaderNonce], h[HeaderSignature]
	if len(ts) == 0 || len(nonce) == 0 || len(sig) == 0 {
		return envelope{}, ErrMissingHeaders
	}
	if len(ts) != 1 || len(nonce) != 1 || len(sig) != 1 {
		return envelope{}, ErrMalformedHeaders
	}
	unix, ok := parseTimestamp(ts[0])
	if !ok || !isLowerHex(nonce[0], hexNonceLen) || !isLowerHex(sig[0], hexSigLen) {
		return envelope{}, ErrMalformedHeaders
	}
	return envelope{nonce: nonce[0], signature: sig[0], unix: unix}, nil
}

const timestampBits = 64

// parseTimestamp accepts only the canonical decimal form of a non-negative
// int64: no sign, no leading zeros.
func parseTimestamp(s string) (int64, bool) {
	if s == "" || s[0] == '+' || s[0] == '-' || (s[0] == '0' && s != "0") {
		return 0, false
	}
	v, err := strconv.ParseInt(s, decimalBase, timestampBits)
	if err != nil {
		return 0, false
	}
	return v, true
}

// isLowerHex reports whether s is n lowercase hex digits.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// withinWindow reports whether |now-ts| <= window for window >= 0. A
// difference past MaxInt64 wraps negative and fails the check.
func withinWindow(now, ts, window int64) bool {
	d := max(now, ts) - min(now, ts)
	return d >= 0 && d <= window
}

// bodyDigest returns the SHA-256 of the body r has, refusing one over
// maxBodyBytes, and restores r.Body once it is read in full.
func bodyDigest(r *http.Request) ([sha256.Size]byte, error) {
	data, err := netguard.ReadRequest(r, maxBodyBytes, errBodyOverLimit)
	if err != nil {
		return [sha256.Size]byte{}, invalidBody(err)
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	return sha256.Sum256(data), nil
}
