package replay

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// Header names carrying the anti-replay envelope.
const (
	HeaderTimestamp = "X-Auth-Timestamp"
	HeaderNonce     = "X-Auth-Nonce"
	HeaderSignature = "X-Auth-Signature"
)

const (
	defaultWindow      = 5 * time.Minute
	defaultMemorySize  = 65536
	nonceBytes         = 16
	hexNonceLen        = nonceBytes * 2
	hexSignatureLen    = sha256.Size * 2
	minKeyLen          = 32
	timestampMaxDigits = 20
)

// newlineSep is shared so the per-call `[]byte{'\n'}` literal does not
// escape to the heap.
var newlineSep = []byte{'\n'}

// Sentinel errors returned by the package.
var (
	ErrMissingHeaders   = errors.New("replay: missing headers")
	ErrTimestampSkew    = errors.New("replay: timestamp out of window")
	ErrSignatureInvalid = errors.New("replay: invalid signature")
	ErrNonceReplayed    = errors.New("replay: nonce already seen")
	ErrShortKey         = errors.New("replay: key must be at least 32 bytes")
	ErrMemoryCapacity   = errors.New("replay: Memory capacity must be > 0")
	ErrStoreFull        = errors.New("replay: nonce store full")
)

// NonceStore records nonces that have been seen so [Verifier.Verify]
// can reject replays. Implementations must be safe for concurrent use.
type NonceStore interface {
	Seen(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
}

// Signer attaches the three replay headers to an outbound request.
//
// Sign implements [github.com/ubyte-source/go-authware/cred.Signer], so
// a Signer composes with cred.RoundTripper.
type Signer struct {
	hmacPool     sync.Pool
	Rand         io.Reader
	Now          func() time.Time
	prng         *mathrand.ChaCha8
	Key          []byte
	prngOnce     sync.Once
	hmacPoolOnce sync.Once
	prngMu       sync.Mutex
}

// signScratch is a per-call scratch buffer reused for nonce hex,
// timestamp digits and signature hex output.
type signScratch struct {
	nonce     [nonceBytes]byte
	nonceHex  [hexNonceLen]byte
	tsDigits  [timestampMaxDigits]byte
	sigOut    [hexSignatureLen]byte
	digestOut [sha256.Size]byte
}

var signScratchPool = sync.Pool{New: func() any { return new(signScratch) }}

func borrowScratch() *signScratch {
	if s, ok := signScratchPool.Get().(*signScratch); ok {
		return s
	}
	return new(signScratch)
}

// macHasher is the structural type satisfied by hmac.New's return.
type macHasher interface {
	Reset()
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

// initHMACPool seeds the per-signer HMAC pool. The closure captures
// the Key slice; rotating a shared secret should always go through a
// fresh Signer.
func (s *Signer) initHMACPool() {
	s.hmacPoolOnce.Do(func() {
		key := s.Key
		s.hmacPool.New = func() any { return hmac.New(sha256.New, key) }
	})
}

// Sign attaches X-Auth-Timestamp, X-Auth-Nonce and X-Auth-Signature to
// r. The hot path allocates only the three http.Header values that
// http.Header.Set inevitably produces.
func (s *Signer) Sign(_ context.Context, r *http.Request) error {
	if len(s.Key) < minKeyLen {
		return ErrShortKey
	}
	scratch := borrowScratch()
	defer signScratchPool.Put(scratch)

	if err := s.fillNonce(scratch.nonce[:]); err != nil {
		return err
	}
	hex.Encode(scratch.nonceHex[:], scratch.nonce[:])

	now := s.now().Unix()
	tsBuf := strconv.AppendInt(scratch.tsDigits[:0], now, 10)

	s.initHMACPool()
	mac, ok := s.hmacPool.Get().(macHasher)
	if !ok {
		mac = hmac.New(sha256.New, s.Key)
	}
	mac.Reset()
	writeMAC(mac, r.Method, r.URL.Path, tsBuf, scratch.nonceHex[:])
	digest := mac.Sum(scratch.digestOut[:0])
	s.hmacPool.Put(mac)
	hex.Encode(scratch.sigOut[:], digest)

	r.Header.Set(HeaderTimestamp, string(tsBuf))
	r.Header.Set(HeaderNonce, string(scratch.nonceHex[:]))
	r.Header.Set(HeaderSignature, string(scratch.sigOut[:]))
	runtime.KeepAlive(scratch)
	return nil
}

// writeMAC writes the canonical signing input to mac. String inputs
// are aliased via unsafe.Slice; HMAC does not retain the buffer past
// the call. hash.Hash.Write never returns an error per the stdlib
// contract; mustWrite enforces that.
func writeMAC(mac io.Writer, method, path string, ts, nonce []byte) {
	mustWrite(mac, stringBytes(method))
	mustWrite(mac, newlineSep)
	mustWrite(mac, stringBytes(path))
	mustWrite(mac, newlineSep)
	mustWrite(mac, ts)
	mustWrite(mac, newlineSep)
	mustWrite(mac, nonce)
}

func mustWrite(w io.Writer, p []byte) {
	if _, err := w.Write(p); err != nil {
		panic(err)
	}
}

//nolint:gosec // immutable string alias; consumed synchronously by HMAC.
func stringBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// fillNonce fills dst with cryptographically random bytes. The default
// path uses a per-Signer ChaCha8 PRNG seeded once from crypto/rand;
// subsequent calls are syscall-free. A custom Rand may inject a
// different source for testing.
func (s *Signer) fillNonce(dst []byte) error {
	if s.Rand != nil {
		_, err := io.ReadFull(s.Rand, dst)
		return err
	}
	prng, err := s.entropyPRNG()
	if err != nil {
		return err
	}
	s.prngMu.Lock()
	for i := 0; i+8 <= len(dst); i += 8 {
		binary.LittleEndian.PutUint64(dst[i:], prng.Uint64())
	}
	if rem := len(dst) % 8; rem != 0 {
		var tail [8]byte
		binary.LittleEndian.PutUint64(tail[:], prng.Uint64())
		copy(dst[len(dst)-rem:], tail[:rem])
	}
	s.prngMu.Unlock()
	return nil
}

func (s *Signer) entropyPRNG() (*mathrand.ChaCha8, error) {
	var seedErr error
	s.prngOnce.Do(func() {
		var seed [32]byte
		if _, err := io.ReadFull(cryptorand.Reader, seed[:]); err != nil {
			seedErr = err
			return
		}
		s.prng = mathrand.NewChaCha8(seed)
	})
	if seedErr != nil {
		return nil, seedErr
	}
	return s.prng, nil
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Verifier validates an inbound request's anti-replay envelope.
type Verifier struct {
	hmacPool     sync.Pool
	NonceStore   NonceStore
	Now          func() time.Time
	Key          []byte
	Window       time.Duration
	storeOnce    sync.Once
	hmacPoolOnce sync.Once
}

func (v *Verifier) initHMACPool() {
	v.hmacPoolOnce.Do(func() {
		key := v.Key
		v.hmacPool.New = func() any { return hmac.New(sha256.New, key) }
	})
}

// Verify validates the three replay headers on r.
func (v *Verifier) Verify(ctx context.Context, r *http.Request) error {
	if len(v.Key) < minKeyLen {
		return ErrShortKey
	}
	timestamp, nonce, sig, err := readReplayHeaders(r)
	if err != nil {
		return err
	}
	ts, skewErr := v.checkSkew(timestamp)
	if skewErr != nil {
		return skewErr
	}

	scratch := borrowScratch()
	defer signScratchPool.Put(scratch)

	tsBuf := strconv.AppendInt(scratch.tsDigits[:0], ts, 10)

	v.initHMACPool()
	mac, ok := v.hmacPool.Get().(macHasher)
	if !ok {
		mac = hmac.New(sha256.New, v.Key)
	}
	mac.Reset()
	writeMAC(mac, r.Method, r.URL.Path, tsBuf, stringBytes(nonce))
	digest := mac.Sum(scratch.digestOut[:0])
	v.hmacPool.Put(mac)
	hex.Encode(scratch.sigOut[:], digest)

	if subtle.ConstantTimeCompare(stringBytes(sig), scratch.sigOut[:]) != 1 {
		return ErrSignatureInvalid
	}
	// Retain the nonce for as long as its timestamp can still pass
	// checkSkew: ts may lead now by window, plus a second of truncation.
	seen, err := v.store().Seen(ctx, nonce, 2*v.window()+time.Second)
	if err != nil {
		return err
	}
	if seen {
		return ErrNonceReplayed
	}
	runtime.KeepAlive(scratch)
	return nil
}

func readReplayHeaders(r *http.Request) (timestamp, nonce, signature string, err error) {
	timestamp = r.Header.Get(HeaderTimestamp)
	nonce = r.Header.Get(HeaderNonce)
	signature = r.Header.Get(HeaderSignature)
	if timestamp == "" || nonce == "" || signature == "" {
		return "", "", "", ErrMissingHeaders
	}
	if len(timestamp) > timestampMaxDigits || len(nonce) != hexNonceLen ||
		len(signature) != hexSignatureLen {
		return "", "", "", ErrMissingHeaders
	}
	if _, perr := strconv.ParseInt(timestamp, 10, 64); perr != nil {
		return "", "", "", ErrMissingHeaders
	}
	return timestamp, nonce, signature, nil
}

func (v *Verifier) checkSkew(timestamp string) (int64, error) {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return 0, ErrMissingHeaders
	}
	now := v.now().Unix()
	if abs(now-ts) > int64(v.window()/time.Second) {
		return 0, ErrTimestampSkew
	}
	return ts, nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) window() time.Duration {
	if v.Window > 0 {
		return v.Window
	}
	return defaultWindow
}

func (v *Verifier) store() NonceStore {
	v.storeOnce.Do(func() {
		if v.NonceStore == nil {
			// defaultMemorySize is a positive constant, so Memory
			// cannot fail.
			store, err := Memory(defaultMemorySize)
			if err != nil {
				panic(err)
			}
			v.NonceStore = store
		}
	})
	return v.NonceStore
}

// Middleware wraps next with replay verification.
func Middleware(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := v.Verify(r.Context(), r); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

var _ NonceStore = (*memoryStore)(nil)

// Memory returns an in-memory TTL [NonceStore]; capacity must be > 0.
// Full of live nonces it fails closed with [ErrStoreFull]: evicting a
// live nonce would re-open its replay window.
func Memory(capacity int) (NonceStore, error) {
	if capacity <= 0 {
		return nil, ErrMemoryCapacity
	}
	return &memoryStore{
		capacity: capacity,
		index:    make(map[string]*memoryEntry, capacity),
	}, nil
}

// memoryStore is a doubly-linked list with per-entry TTL. Uniform TTLs
// keep insertion order equal to expiry order, so eviction is O(1).
type memoryStore struct {
	index    map[string]*memoryEntry
	head     *memoryEntry
	tail     *memoryEntry
	capacity int
	mu       sync.Mutex
}

type memoryEntry struct {
	prev, next *memoryEntry
	expire     time.Time
	nonce      string
}

func (m *memoryStore) Seen(_ context.Context, nonce string, ttl time.Duration) (bool, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	m.evictExpiredLocked(now)

	if entry, ok := m.index[nonce]; ok {
		if entry.expire.After(now) {
			return true, nil
		}
		m.removeLocked(entry)
		delete(m.index, nonce)
	}

	if len(m.index) >= m.capacity {
		return false, ErrStoreFull
	}

	entry := &memoryEntry{nonce: nonce, expire: now.Add(ttl)}
	m.pushFrontLocked(entry)
	m.index[nonce] = entry
	return false, nil
}

func (m *memoryStore) pushFrontLocked(e *memoryEntry) {
	e.prev = nil
	e.next = m.head
	if m.head != nil {
		m.head.prev = e
	}
	m.head = e
	if m.tail == nil {
		m.tail = e
	}
}

func (m *memoryStore) removeLocked(e *memoryEntry) {
	switch {
	case e.prev != nil:
		e.prev.next = e.next
	default:
		m.head = e.next
	}
	switch {
	case e.next != nil:
		e.next.prev = e.prev
	default:
		m.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

// evictExpiredLocked drops entries whose expire time is before now,
// walking from the oldest tail. Caller holds m.mu.
func (m *memoryStore) evictExpiredLocked(now time.Time) {
	for m.tail != nil && !m.tail.expire.After(now) {
		dead := m.tail
		m.removeLocked(dead)
		delete(m.index, dead.nonce)
	}
}
