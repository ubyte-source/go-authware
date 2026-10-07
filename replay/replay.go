package replay

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/ubyte-source/go-authware/v2/internal/keyedmac"
	"github.com/ubyte-source/go-authware/v2/secret"
)

const (
	// HeaderTimestamp carries the signing time in Unix seconds, canonical
	// decimal without sign or leading zeros.
	HeaderTimestamp = "X-Auth-Timestamp"
	// HeaderNonce carries 16 random bytes as 32 lowercase hex digits.
	HeaderNonce = "X-Auth-Nonce"
	// HeaderSignature carries 64 lowercase hex digits of the HMAC-SHA256 of
	// six lines joined by "\n": method, host with ASCII letters lowercased and
	// no IPv6 zone, request URI, hex SHA-256 of the body, timestamp and nonce.
	HeaderSignature = "X-Auth-Signature"
)

// Sizes and limits of the replay key, envelope and body, and the base of its timestamp.
const (
	minKeyLen    = 32
	nonceBytes   = 16
	hexNonceLen  = 2 * nonceBytes
	hexSigLen    = 2 * sha256.Size
	maxBodyBytes = 1 << 20
	decimalBase  = 10
)

// errPrefix starts the text of every error the package returns.
const errPrefix = "replay: "

var (
	// ErrRejected is wrapped by every error that blames the request rather
	// than the server.
	ErrRejected = errors.New(errPrefix + "request rejected")
	// ErrMissingHeaders reports a request without one of the three headers.
	ErrMissingHeaders = fmt.Errorf("%w: missing headers", ErrRejected)
	// ErrMalformedHeaders reports a repeated or non-canonical header.
	ErrMalformedHeaders = fmt.Errorf("%w: malformed headers", ErrRejected)
	// ErrTimestampSkew reports a timestamp outside the window.
	ErrTimestampSkew = fmt.Errorf("%w: timestamp out of window", ErrRejected)
	// ErrInvalidBody reports a body, signed or verified, that fails to read or
	// close, or exceeds 1 MiB.
	ErrInvalidBody = fmt.Errorf("%w: invalid body", ErrRejected)
	// ErrInvalidSignature reports a signature that does not match the request.
	ErrInvalidSignature = fmt.Errorf("%w: invalid signature", ErrRejected)
	// ErrNonceReplayed reports a nonce the store has already recorded.
	ErrNonceReplayed = fmt.Errorf("%w: nonce already seen", ErrRejected)

	// ErrInvalidConfig reports a constructor argument that cannot work.
	ErrInvalidConfig = errors.New(errPrefix + "invalid config")
	// ErrShortKey reports a key shorter than 32 bytes.
	ErrShortKey = fmt.Errorf("%w: key shorter than 32 bytes", ErrInvalidConfig)
	// ErrInvalidOption reports an option outside its allowed range.
	ErrInvalidOption = fmt.Errorf("%w: option out of range", ErrInvalidConfig)
	// ErrInvalidCapacity reports a memory store capacity below 1.
	ErrInvalidCapacity = fmt.Errorf("%w: memory store capacity below 1", ErrInvalidConfig)
	// ErrStoreFull reports a memory store full of live nonces.
	ErrStoreFull = errors.New(errPrefix + "memory store full")

	// errBodyTooLarge reports, under ErrInvalidBody, a body over 1 MiB.
	errBodyTooLarge = errors.New("body too large")
	// errBodyOverLimit is the refusal of a body over 1 MiB, built once.
	errBodyOverLimit = invalidBody(errBodyTooLarge)
)

// invalidBody wraps cause, why a body was refused, under ErrInvalidBody unless
// cause already wraps it.
func invalidBody(cause error) error {
	if errors.Is(cause, ErrInvalidBody) {
		return cause
	}
	return fmt.Errorf("%w: %w", ErrInvalidBody, cause)
}

// macScratch is the HMAC-SHA256 of the key and a pool of the per-call
// scratch that signs with it.
type macScratch struct {
	pool  sync.Pool
	keyed *keyedmac.MAC
}

// macState is the per-call scratch: the canonical input, its MAC and the
// random bytes of a nonce.
type macState struct {
	buf    []byte
	sum    [sha256.Size]byte
	random [nonceBytes]byte
}

// maxPooledInput bounds the canonical input buffer a pooled state keeps, so
// a request with a long URI leaves no large buffer behind.
const maxPooledInput = 4 << 10

func newMACScratch(key secret.Value) (*macScratch, error) {
	if key.Len() < minKeyLen {
		return nil, ErrShortKey
	}
	return &macScratch{keyed: keyedmac.New(sha256.New, []byte(key.Reveal()))}, nil
}

func (m *macScratch) get() *macState {
	if st, ok := m.pool.Get().(*macState); ok {
		return st
	}
	return &macState{}
}

// put pools st, dropping a canonical input buffer over maxPooledInput.
func (m *macScratch) put(st *macState) {
	if cap(st.buf) > maxPooledInput {
		st.buf = nil
	}
	m.pool.Put(st)
}

// keyedSum returns the HMAC-SHA256 of input; the result aliases st.
func (m *macScratch) keyedSum(st *macState, input []byte) []byte {
	return m.keyed.Sum(st.sum[:0], input)
}

// emptyBodyHex is the hex SHA-256 of an empty body.
const emptyBodyHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// hasBody reports whether r carries a body, which it lacks when its Body is nil or
// http.NoBody, or when it is a server request, RequestURI set, whose ContentLength
// is 0: net/http then gives it a Body that yields no byte.
func hasBody(r *http.Request) bool {
	if r.RequestURI != "" && r.ContentLength == 0 {
		return false
	}
	return r.Body != nil && r.Body != http.NoBody
}

// input returns the buffer of st holding the lines of the canonical input that
// precede the timestamp, each followed by "\n": method, host, request URI and the
// hex of body, the SHA-256 of the body, or emptyBodyHex when body is nil.
func (st *macState) input(r *http.Request, body *[sha256.Size]byte) []byte {
	b := st.buf[:0]
	b = append(b, cmp.Or(r.Method, http.MethodGet)...)
	b = append(b, '\n')
	b = appendHost(b, cmp.Or(r.Host, r.URL.Host))
	b = append(b, '\n')
	b = appendRequestURI(b, r.URL)
	b = append(b, '\n')
	if body == nil {
		b = append(b, emptyBodyHex...)
	} else {
		b = hex.AppendEncode(b, body[:])
	}
	return append(b, '\n')
}

// appendHost appends host without the zone of an IPv6 literal, as net/http
// sends it, and with ASCII letters lowercased.
func appendHost(b []byte, host string) []byte {
	head, tail := splitZone(host)
	return appendLower(appendLower(b, head), tail)
}

// splitZone returns host around the zone of an IPv6 literal, which net/http drops:
// "[fe80::1%en0]:80" around "%en0". A host without a zone is head, tail empty.
func splitZone(host string) (head, tail string) {
	if !strings.HasPrefix(host, "[") {
		return host, ""
	}
	end := strings.LastIndexByte(host, ']')
	if end == -1 {
		return host, ""
	}
	zone := strings.LastIndexByte(host[:end], '%')
	if zone == -1 {
		return host, ""
	}
	return host[:zone], host[end:]
}

// appendRequestURI appends u.RequestURI() to b, joining the query itself
// instead of through the string RequestURI allocates for it.
func appendRequestURI(b []byte, u *url.URL) []byte {
	path := *u
	path.RawQuery, path.ForceQuery = "", false
	b = append(b, path.RequestURI()...)
	if u.ForceQuery || u.RawQuery != "" {
		b = append(append(b, '?'), u.RawQuery...)
	}
	return b
}

// appendLower appends s with ASCII letters lowercased.
func appendLower(b []byte, s string) []byte {
	for i := range len(s) {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return b
}
