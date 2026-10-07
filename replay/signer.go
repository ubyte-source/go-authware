package replay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// Signer attaches the anti-replay headers to outbound requests, signing a valid
// ASCII host with its letters lowercased and without an IPv6 zone. It implements
// cred.Signer and is safe for concurrent use.
type Signer struct {
	mac    *macScratch
	bodies *netguard.Digester
}

// NewSigner returns a Signer keyed with key; a key shorter than 32 bytes fails
// with [ErrShortKey].
func NewSigner(key secret.Value) (*Signer, error) {
	mac, err := newMACScratch(key)
	if err != nil {
		return nil, err
	}
	return &Signer{mac: mac, bodies: new(netguard.Digester)}, nil
}

// Sign sets the timestamp, a nonce from crypto/rand and the signature headers on
// r, after it hashes the body as the package comment states; a body that fails to
// read or close, or exceeds 1 MiB, fails with [ErrInvalidBody].
func (s *Signer) Sign(_ context.Context, r *http.Request) error {
	var body *[sha256.Size]byte
	if hasBody(r) {
		sum, err := s.bodies.Digest(r, maxBodyBytes, errBodyOverLimit)
		if err != nil {
			return invalidBody(err)
		}
		body = &sum
	}
	st := s.mac.get()
	defer s.mac.put(st)
	rand.Read(st.random[:]) //nolint:revive // crypto/rand.Read never returns an error
	b := st.input(r, body)
	ts := len(b)
	b = strconv.AppendInt(b, time.Now().Unix(), decimalBase)
	nonce := len(b) + 1
	b = hex.AppendEncode(append(b, '\n'), st.random[:])
	sig := len(b)
	st.buf = hex.AppendEncode(b, s.mac.keyedSum(st, b))
	// The three values share one string, and their header slices one array.
	values := string(st.buf[ts:])
	nonce, sig = nonce-ts, sig-ts
	vals := []string{values[:nonce-1], values[nonce:sig], values[sig:]}
	if r.Header == nil {
		r.Header = http.Header{}
	}
	h := r.Header
	h[HeaderTimestamp], h[HeaderNonce], h[HeaderSignature] = vals[:1:1], vals[1:2:2], vals[2:]
	return nil
}
