package cred

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultTokenType   = "Bearer"
	defaultTokenHeader = "Authorization"
	defaultCacheSkew   = 30 * time.Second
)

// ErrNilSource is returned by [Cache] when src is nil.
var ErrNilSource = errors.New("cred: nil TokenSource")

// Token is an outbound HTTP credential.
type Token struct {
	Expires      time.Time
	cachedHeader atomic.Pointer[string]
	cachedValue  atomic.Pointer[string]
	Header       string
	Type         string
	Value        string
}

// Apply attaches the token to r. The formatted header value is
// memoised on first call so the hot path skips the concatenation.
// Apply is safe for concurrent use.
func (t *Token) Apply(r *http.Request) {
	name := t.cachedHeader.Load()
	val := t.cachedValue.Load()
	if name == nil || val == nil {
		name, val = t.resolveCached()
	}
	r.Header.Set(*name, *val)
}

func (t *Token) resolveCached() (header, value *string) {
	hdr := t.Header
	if hdr == "" {
		hdr = defaultTokenHeader
	}
	typ := t.Type
	if typ == "" {
		typ = defaultTokenType
	}
	val := typ + " " + t.Value
	t.cachedHeader.Store(&hdr)
	t.cachedValue.Store(&val)
	return &hdr, &val
}

// TokenSource produces credentials. Implementations must be safe for
// concurrent use by multiple goroutines.
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

// TokenSourceFunc is an adapter that lets ordinary functions satisfy
// [TokenSource].
type TokenSourceFunc func(ctx context.Context) (*Token, error)

// Token calls f.
func (f TokenSourceFunc) Token(ctx context.Context) (*Token, error) {
	return f(ctx)
}

// Signer modifies a request in-place to attach a credential. It
// generalises [TokenSource] for schemes whose output depends on the
// request itself (e.g. AWS SigV4).
type Signer interface {
	Sign(ctx context.Context, r *http.Request) error
}

// SignerFunc is an adapter that lets ordinary functions satisfy [Signer].
type SignerFunc func(ctx context.Context, r *http.Request) error

// Sign calls f.
func (f SignerFunc) Sign(ctx context.Context, r *http.Request) error {
	return f(ctx, r)
}

var (
	_ Signer            = (*tokenSigner)(nil)
	_ http.RoundTripper = (*signedTransport)(nil)
	_ TokenSource       = (*cachedSource)(nil)
)

// AsSigner adapts a [TokenSource] to a [Signer] by calling Token and Apply
// on each invocation.
func AsSigner(src TokenSource) Signer {
	return &tokenSigner{src: src}
}

type tokenSigner struct {
	src TokenSource
}

func (s *tokenSigner) Sign(ctx context.Context, r *http.Request) error {
	tok, err := s.src.Token(ctx)
	if err != nil {
		return err
	}
	tok.Apply(r)
	return nil
}

// RoundTripper returns an [net/http.RoundTripper] that clones every
// request, signs the clone with s, and delegates to base (or
// [net/http.DefaultTransport] when base is nil).
func RoundTripper(base http.RoundTripper, s Signer) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &signedTransport{base: base, signer: s}
}

type signedTransport struct {
	base   http.RoundTripper
	signer Signer
}

func (t *signedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	cloned := r.Clone(r.Context())
	if err := t.signer.Sign(r.Context(), cloned); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(cloned)
}

// CacheOption customizes [Cache] construction.
type CacheOption func(*cacheConfig)

type cacheConfig struct {
	now  func() time.Time
	skew time.Duration
}

// WithSkew sets the early-refresh window: a cached token is considered
// stale when its remaining lifetime is below d. Default 30s.
func WithSkew(d time.Duration) CacheOption {
	return func(c *cacheConfig) { c.skew = d }
}

// WithClock injects a clock function for deterministic tests. The default
// is [time.Now].
func WithClock(now func() time.Time) CacheOption {
	return func(c *cacheConfig) { c.now = now }
}

// Cache wraps src to memoise tokens until near expiry. Refreshes are
// single-flighted; the hit path is zero-allocation.
func Cache(src TokenSource, opts ...CacheOption) TokenSource {
	if src == nil {
		panic(ErrNilSource)
	}
	cfg := cacheConfig{skew: defaultCacheSkew, now: time.Now}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &cachedSource{src: src, now: cfg.now, skew: cfg.skew}
}

// inflightCall lets concurrent callers share a single in-progress
// upstream refresh.
type inflightCall struct {
	done chan struct{}
	tok  *Token
	err  error
}

type cachedSource struct {
	src      TokenSource
	now      func() time.Time
	inflight *inflightCall
	cur      atomic.Pointer[Token]
	skew     time.Duration
	mu       sync.Mutex
}

func (c *cachedSource) Token(ctx context.Context) (*Token, error) {
	if tok := c.cur.Load(); tok != nil && c.fresh(tok) {
		return tok, nil
	}
	return c.refresh(ctx)
}

func (c *cachedSource) fresh(t *Token) bool {
	if t.Expires.IsZero() {
		return true
	}
	return c.now().Before(t.Expires.Add(-c.skew))
}

func (c *cachedSource) refresh(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	if tok := c.cur.Load(); tok != nil && c.fresh(tok) {
		c.mu.Unlock()
		return tok, nil
	}
	if c.inflight != nil {
		ic := c.inflight
		c.mu.Unlock()
		select {
		case <-ic.done:
			return ic.tok, ic.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ic := &inflightCall{done: make(chan struct{})}
	c.inflight = ic
	c.mu.Unlock()

	tok, err := c.src.Token(ctx)

	c.mu.Lock()
	ic.tok, ic.err = tok, err
	c.inflight = nil
	if err == nil {
		c.cur.Store(tok)
	}
	close(ic.done)
	c.mu.Unlock()

	return tok, err
}
