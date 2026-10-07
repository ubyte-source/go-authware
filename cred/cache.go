package cred

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/flight"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/internal/retry"
)

// skewDivisor caps the skew at this fraction of the lifetime a token has left
// when it is fetched.
const skewDivisor = 2

// errNilSource refuses a cached source without a token source.
var errNilSource = fmt.Errorf("%w: nil token source", ErrInvalidConfig)

// errRefreshBackoff marks a refresh refused while a failed one backs off; the
// error that carries it also wraps that failure.
var errRefreshBackoff = errors.New(errPrefix + "token refresh backing off after a failure")

// cacheConfig holds the settings of NewCachedSource.
type cacheConfig struct {
	log     *slog.Logger
	skew    time.Duration
	timeout time.Duration
}

// CacheOption configures NewCachedSource.
type CacheOption interface {
	applyCache(c *cacheConfig)
}

type cacheOption func(c *cacheConfig)

func (o cacheOption) applyCache(c *cacheConfig) { o(c) }

// WithSkew sets how long before expiry a token is refreshed; default 30s.
// It is capped at half the lifetime the token had when it was fetched.
func WithSkew(d time.Duration) CacheOption {
	return cacheOption(func(c *cacheConfig) { c.skew = d })
}

// WithTimeout bounds each refresh, which runs detached from the caller's
// cancellation; zero means 10s.
func WithTimeout(d time.Duration) CacheOption {
	return cacheOption(func(c *cacheConfig) { c.timeout = d })
}

// WithErrorLog sets the logger that receives, at warn level, the cause of
// every failed refresh; nil, the default, logs nothing.
func WithErrorLog(log *slog.Logger) CacheOption {
	return cacheOption(func(c *cacheConfig) { c.log = log })
}

// entry pairs a token with the instant it becomes due for refresh, a zero
// refreshAt never coming due, and with the instant from which Invalidate may
// drop a token again; an entry without a token marks a drop.
type entry struct {
	tok       *Token
	refreshAt time.Time
	nextDrop  time.Time
}

// fresh reports whether e holds a token not yet due for refresh, reading the
// clock only when e has a refresh instant.
func (e *entry) fresh() bool {
	return e.tok != nil && (e.refreshAt.IsZero() || time.Now().Before(e.refreshAt))
}

// CachedSource memoizes the tokens of a TokenSource until they are due for
// refresh, sharing its own copy of each with every caller. It must not be
// copied.
type CachedSource struct {
	src      TokenSource
	settings cacheConfig
	group    flight.Group[*Token]
	backoff  retry.Backoff
	// failure is the error of the last failed refresh, stored before backoff
	// starts the pause that refuses the next refreshes, so each finds it.
	failure atomic.Pointer[error]
	cur     atomic.Pointer[entry]
}

// NewCachedSource wraps src, or reports a nil src and each negative option joined,
// each wrapping ErrInvalidConfig. Concurrent refreshes share one upstream call,
// and a token already expired when it arrives counts as a failed refresh.
func NewCachedSource(src TokenSource, opts ...CacheOption) (*CachedSource, error) {
	cfg := cacheConfig{skew: defaultCacheSkew}
	for _, opt := range opts {
		if opt != nil {
			opt.applyCache(&cfg)
		}
	}
	p := problems.New(ErrInvalidConfig)
	if src == nil {
		p.Add(errNilSource)
	}
	p.NonNegative("skew", cfg.skew)
	p.NonNegative("timeout", cfg.timeout)
	if err := p.Err(); err != nil {
		return nil, err
	}
	cfg.timeout = cmp.Or(cfg.timeout, defaultTimeout)
	cfg.log = cmp.Or(cfg.log, slog.New(slog.DiscardHandler))
	return &CachedSource{src: src, settings: cfg}, nil
}

// Token returns the cached token or refreshes it. After a failed refresh no
// other starts for 30s: the cached token is served until it expires, and
// without one Token fails at once with an error wrapping that failure.
func (c *CachedSource) Token(ctx context.Context) (*Token, error) {
	if e := c.cur.Load(); e != nil && e.fresh() {
		return e.tok, nil
	}
	tok, err := c.refresh(ctx)
	if err == nil {
		return tok, nil
	}
	if e := c.cur.Load(); e != nil && e.tok != nil && time.Now().Before(e.tok.Expires) {
		return e.tok, nil
	}
	return nil, err
}

// Invalidate drops stale while it is the cached token, at most once every
// 30s, so the next Token call refreshes; any other token is left alone.
func (c *CachedSource) Invalidate(stale *Token) {
	c.drop(c.cur.Load(), stale, time.Now())
}

// drop swaps seen, the entry cached at now, for an entry without a token when
// seen holds stale and allows a drop, so the drop and the pause it starts are
// published at once; a cache that moved on since seen keeps its entry.
func (c *CachedSource) drop(seen *entry, stale *Token, now time.Time) {
	if seen != nil && seen.tok != nil && seen.tok == stale && !now.Before(seen.nextDrop) {
		c.cur.CompareAndSwap(seen, &entry{nextDrop: now.Add(retry.After)})
	}
}

// refresh joins the refresh in flight or starts one; while a failed one backs
// off, it starts none and fails with an error wrapping that failure.
func (c *CachedSource) refresh(ctx context.Context) (*Token, error) {
	tok, started, err := c.group.Join(ctx, c.settings.timeout, c.fetch, time.Now(), &c.backoff)
	switch {
	case !started:
		return nil, fmt.Errorf("%w: %w", errRefreshBackoff, *c.failure.Load())
	case errors.Is(err, flight.ErrAbandoned):
		return nil, fmt.Errorf(errPrefix+"token refresh: %w", err)
	}
	return tok, err
}

// fetch runs inside the flight, so a refresh that finished while the caller
// queued is reused instead of repeated; a failure is logged and backs off. A
// drop that lands during the fetch keeps its pause on the new token.
func (c *CachedSource) fetch(ctx context.Context) (*Token, error) {
	seen := c.cur.Load()
	if seen != nil && seen.fresh() {
		return seen.tok, nil
	}
	tok, now, err := unexpiredToken(ctx, c.src)
	if err != nil {
		c.failure.Store(&err)
		c.backoff.Fail(now)
		c.settings.log.LogAttrs(ctx, slog.LevelWarn, errPrefix+"token refresh failed", slog.Any("error", err))
		return nil, err
	}
	c.backoff.Reset()
	tok = tok.shared()
	e := &entry{tok: tok}
	if !tok.Expires.IsZero() {
		e.refreshAt = tok.Expires.Add(-min(c.settings.skew, tok.Expires.Sub(now)/skewDivisor))
	}
	for !c.replace(seen, e) {
		seen = c.cur.Load()
	}
	return tok, nil
}

// replace caches e in place of seen, keeping the instant from which seen
// allows a drop, and reports false, caching nothing, when a drop replaced
// seen first.
func (c *CachedSource) replace(seen, e *entry) bool {
	if seen != nil {
		e.nextDrop = seen.nextDrop
	}
	return c.cur.CompareAndSwap(seen, e)
}

// errRefreshedExpired refuses a refreshed token expired when its answer arrives.
var errRefreshedExpired = fmt.Errorf(errPrefix+"token refresh: %w: token already expired", ErrInvalidTokenResponse)

// unexpiredToken fetches the token of src and returns the instant its answer
// arrived, refusing a token expired at that instant.
func unexpiredToken(ctx context.Context, src TokenSource) (*Token, time.Time, error) {
	tok, err := fetchToken(ctx, src)
	now := time.Now()
	if err == nil && !tok.Expires.IsZero() && !now.Before(tok.Expires) {
		return nil, now, errRefreshedExpired
	}
	return tok, now, err
}
