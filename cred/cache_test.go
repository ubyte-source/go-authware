package cred

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// seq2 is the second token of a sequence.
const seq2 = "t2"

// The defaults of NewCachedSource, an instant, the concurrent callers of the
// race tests and the source calls after a retry, another and a recovery.
const (
	wantSkew     = 30 * time.Second
	racers       = 64
	retried      = 3
	retriedAgain = 4
	recovered    = 5
)

// newCache returns a CachedSource of a sequence whose tokens live ttl.
func newCache(t *testing.T, ttl time.Duration, opts ...CacheOption) (*CachedSource, *sequence) {
	t.Helper()
	src := &sequence{ttl: ttl}
	c, err := NewCachedSource(src, opts...)
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	return c, src
}

// TestNewCachedSource reports every problem at once, as README states of the
// New* constructors: the nil source and each negative option.
func TestNewCachedSource(t *testing.T) {
	_, err := NewCachedSource(nil)
	if !errors.Is(err, ErrInvalidConfig) || err.Error() != "cred: invalid config: nil token source" {
		t.Fatalf("NewCachedSource(nil) err = %v, want ErrInvalidConfig naming the nil source", err)
	}
	_, err = NewCachedSource(&sequence{}, WithSkew(-time.Second), WithTimeout(-time.Second))
	if !errors.Is(err, ErrInvalidConfig) || err.Error() != "cred: invalid config: skew is negative\n"+
		"cred: invalid config: timeout is negative" {
		t.Fatalf("err = %v, want two joined ErrInvalidConfig", err)
	}
	_, err = NewCachedSource(nil, WithSkew(-time.Second), WithTimeout(-time.Second))
	if !errors.Is(err, ErrInvalidConfig) || err.Error() != "cred: invalid config: nil token source\n"+
		"cred: invalid config: skew is negative\ncred: invalid config: timeout is negative" {
		t.Fatalf("NewCachedSource(nil, negative skew and timeout) err = %v; README: \"report every problem at "+
			"once\": want the nil source and both options joined", err)
	}
}

// TestNewCachedSourceNilOption skips a nil option and applies the others.
func TestNewCachedSourceNilOption(t *testing.T) {
	c, err := NewCachedSource(&sequence{}, nil, WithSkew(time.Minute), nil)
	if err != nil || c.settings.skew != time.Minute {
		t.Fatalf("NewCachedSource(nil, WithSkew(1m), nil) = %+v, %v; want a 1m skew", c, err)
	}
}

func TestNewCachedSourceDefaults(t *testing.T) {
	c, err := NewCachedSource(&sequence{}, WithTimeout(0), WithErrorLog(nil))
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	if got := c.settings; got.skew != wantSkew || got.timeout != wantTimeout ||
		got.log.Enabled(t.Context(), slog.LevelError) {
		t.Fatalf("defaults = %+v, want skew 30s, timeout 10s and a log that discards", got)
	}
	c, err = NewCachedSource(&sequence{}, WithTimeout(time.Second))
	if err != nil || c.settings.timeout != time.Second {
		t.Fatalf("WithTimeout(1s) = %+v, %v, want a 1s refresh bound", c, err)
	}
}

// TestCachedSourceTokenBackoff fails the refresh of a token due for it: the
// token is served until it expires, and no refresh starts for 30s after a
// failed one.
func TestCachedSourceTokenBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, time.Hour, WithSkew(10*time.Minute))
		start := time.Now()
		moveTo := func(d time.Duration) { time.Sleep(time.Until(start.Add(d))) }
		mustToken(t, c)
		src.fail(errSource)
		const due = 50 * time.Minute
		for i, st := range []struct {
			at    time.Duration
			calls int64
		}{
			{due, 2}, {due + time.Second, 2}, {due + pause - time.Nanosecond, 2}, {due + pause, retried},
			{time.Hour - time.Nanosecond, retriedAgain},
		} {
			moveTo(st.at)
			if got := mustToken(t, c); got != seq1 || src.calls.Load() != st.calls {
				t.Fatalf("step %d: Token = %s after %d calls, want %s after %d", i, got, src.calls.Load(), seq1,
					st.calls)
			}
		}
		moveTo(time.Hour)
		if tok, err := c.Token(t.Context()); !errors.Is(err, errRefreshBackoff) || !errors.Is(err, errSource) ||
			tok != nil || src.calls.Load() != retriedAgain {
			t.Fatalf("Token(expired, backing off) = %v, %v after %d calls, want errRefreshBackoff wrapping errSource "+
				"after 4", tok, err, src.calls.Load())
		}
		src.fail(nil)
		moveTo(time.Hour + pause)
		if got := mustToken(t, c); got != "t5" || src.calls.Load() != recovered {
			t.Fatalf("Token(after the backoff) = %s after %d calls, want t5 after 5", got, src.calls.Load())
		}
	})
}

func TestWithErrorLog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		c, src := newCache(t, time.Hour, WithErrorLog(slog.New(slog.NewTextHandler(&logs, nil))))
		mustToken(t, c)
		src.fail(errSource)
		time.Sleep(time.Hour)
		for i, want := range []error{errSource, errRefreshBackoff, errRefreshBackoff} {
			if _, err := c.Token(t.Context()); !errors.Is(err, want) || !errors.Is(err, errSource) {
				t.Fatalf("Token %d of an expired token with a failing source = %v, want %v and errSource", i, err,
					want)
			}
		}
		const want = `level=WARN msg="cred: token refresh failed" error="test: source failed"`
		if got := logs.String(); strings.Count(got, want) != 1 || strings.Count(got, "\n") != 1 {
			t.Fatalf("log = %q, want the one failed refresh warned once", got)
		}
	})
}

// TestWithErrorLogPassesTheContext logs a failed refresh under the context of
// the call that started it.
func TestWithErrorLogPassesTheContext(t *testing.T) {
	var logged atomic.Int32
	src := &sequence{}
	c, err := NewCachedSource(src, WithErrorLog(slog.New(markHandler{marked: &logged})))
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	src.fail(errSource)
	if _, err := c.Token(marked(t)); !errors.Is(err, errSource) || logged.Load() != 1 {
		t.Fatalf("Token = %v with %d records under the caller's context, want errSource and 1", err, logged.Load())
	}
}

func TestWithSkewZero(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, time.Hour, WithSkew(0))
		mustToken(t, c)
		time.Sleep(time.Hour - time.Nanosecond)
		if got := mustToken(t, c); got != seq1 {
			t.Fatalf("before expiry = %s, want %s", got, seq1)
		}
		time.Sleep(time.Nanosecond)
		if got := mustToken(t, c); got != seq2 || src.calls.Load() != 2 {
			t.Fatalf("at expiry = %s after %d calls, want %s after 2", got, src.calls.Load(), seq2)
		}
	})
}

func TestCachedSourceToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, time.Hour)
		if got := mustToken(t, c); got != seq1 {
			t.Fatalf("first Token = %s, want %s", got, seq1)
		}
		time.Sleep(time.Hour - 30*time.Second - time.Nanosecond)
		if got := mustToken(t, c); got != seq1 {
			t.Fatalf("Token before the skew = %s, want %s", got, seq1)
		}
		time.Sleep(time.Nanosecond)
		if got := mustToken(t, c); got != seq2 || src.calls.Load() != 2 {
			t.Fatalf("Token after the skew = %s after %d calls, want %s after 2", got, src.calls.Load(), seq2)
		}
	})
}

// TestCachedSourceTokenAllocs serves a fresh cached token without
// allocating.
func TestCachedSourceTokenAllocs(t *testing.T) {
	c, _ := newCache(t, time.Hour)
	first := nextToken(t, c)
	assertAllocs(t, 0, func() {
		if tok, err := c.Token(t.Context()); err != nil || tok != first {
			t.Fatalf("Token = %v, %v, want the cached %v", tok, err, first)
		}
	})
}

func TestCachedSourceTokenNoExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, 0)
		mustToken(t, c)
		time.Sleep(1000 * time.Hour)
		if got := mustToken(t, c); got != seq1 || src.calls.Load() != 1 {
			t.Fatalf("Token = %s after %d calls, want %s after 1: no expiry, no refresh", got, src.calls.Load(), seq1)
		}
	})
}

func TestCachedSourceTokenShortLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, 20*time.Second)
		mustToken(t, c)
		time.Sleep(9 * time.Second)
		if got := mustToken(t, c); got != seq1 {
			t.Fatalf("Token within half the lifetime = %s, want %s", got, seq1)
		}
		time.Sleep(2 * time.Second)
		if got := mustToken(t, c); got != seq2 || src.calls.Load() != 2 {
			t.Fatalf("Token past half the lifetime = %s after %d calls, want %s after 2", got, src.calls.Load(), seq2)
		}
	})
}

func TestCachedSourceTokenServesUnexpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, time.Minute)
		mustToken(t, c)
		src.fail(errSource)
		time.Sleep(45 * time.Second)
		if got := mustToken(t, c); got != seq1 {
			t.Fatalf("Token inside the skew window = %s, want %s", got, seq1)
		}
		time.Sleep(16 * time.Second)
		if _, err := c.Token(t.Context()); !errors.Is(err, errRefreshBackoff) {
			t.Fatalf("after expiry, backing off, err = %v, want errRefreshBackoff", err)
		}
		time.Sleep(pause)
		if _, err := c.Token(t.Context()); !errors.Is(err, errSource) {
			t.Fatalf("after expiry and the backoff err = %v, want errSource", err)
		}
	})
}

// TestCachedSourceTokenSlowFailedRefresh fails, 10s after it starts, the
// refresh of a token with 5s left: the token expired meanwhile, so Token fails.
func TestCachedSourceTokenSlowFailedRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		src := TokenSourceFunc(func(context.Context) (*Token, error) {
			if calls.Add(1) == 1 {
				return &Token{Value: secret.New(seq1), Expires: time.Now().Add(time.Minute)}, nil
			}
			time.Sleep(10 * time.Second)
			return nil, errSource
		})
		c, err := NewCachedSource(src)
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		mustToken(t, c)
		time.Sleep(55 * time.Second)
		if tok, err := c.Token(t.Context()); tok != nil || !errors.Is(err, errSource) {
			t.Fatalf("Token after a refresh that failed past expiry = %v, %v; want no token and errSource", tok, err)
		}
	})
}

// TestCachedSourceTokenArrivedExpired refuses a token that expires 5s after
// the refresh starts and arrives 10s after it.
func TestCachedSourceTokenArrivedExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := TokenSourceFunc(func(context.Context) (*Token, error) {
			tok := &Token{Value: secret.New(seq1), Expires: time.Now().Add(5 * time.Second)}
			time.Sleep(10 * time.Second)
			return tok, nil
		})
		c, err := NewCachedSource(src)
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		if tok, err := c.Token(t.Context()); tok != nil || !errors.Is(err, ErrInvalidTokenResponse) {
			t.Fatalf("Token(expired on arrival) = %v, %v; want no token and ErrInvalidTokenResponse", tok, err)
		}
	})
}

// TestCachedSourceTokenSlowAnswer times from the arrival of a 20s answer: a
// token living 60s from the request has 40s left, so it is due 20s before
// expiry, and a failure that arrives at 20s pauses refreshes until 50s.
func TestCachedSourceTokenSlowAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const delay = 20 * time.Second
		var calls atomic.Int64
		var failing atomic.Bool
		src := TokenSourceFunc(func(context.Context) (*Token, error) {
			value := "t" + strconv.FormatInt(calls.Add(1), decimalBase)
			tok := &Token{Value: secret.New(value), Expires: time.Now().Add(time.Minute)}
			time.Sleep(delay)
			if failing.Load() {
				return nil, errSource
			}
			return tok, nil
		})
		c, err := NewCachedSource(src)
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		start := time.Now()
		moveTo := func(d time.Duration) { time.Sleep(time.Until(start.Add(d))) }
		mustToken(t, c)
		moveTo(2*delay - time.Nanosecond)
		if got := mustToken(t, c); got != seq1 || calls.Load() != 1 {
			t.Fatalf("Token 20s before expiry = %s after %d calls, want %s after 1", got, calls.Load(), seq1)
		}
		moveTo(2 * delay)
		if got := mustToken(t, c); got != seq2 || calls.Load() != 2 {
			t.Fatalf("Token at 40s = %s after %d calls, want %s after 2", got, calls.Load(), seq2)
		}
		c.Invalidate(c.cur.Load().tok)
		failing.Store(true)
		failedAt := time.Now().Add(delay)
		if _, err := c.Token(t.Context()); !errors.Is(err, errSource) {
			t.Fatalf("Token(failing) = %v, want errSource", err)
		}
		time.Sleep(time.Until(failedAt.Add(pause - time.Nanosecond)))
		if _, err := c.Token(t.Context()); !errors.Is(err, errRefreshBackoff) || calls.Load() != retried {
			t.Fatalf("Token 30s after the failure arrived = %v after %d calls, want errRefreshBackoff after 3", err,
				calls.Load())
		}
	})
}

// TestCachedSourceTokenBackoffWrapsTheFailure fails, while a refresh backs off,
// with the class of the failure that started the pause: the last one.
func TestCachedSourceTokenBackoffWrapsTheFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &sequence{}
		c, err := NewCachedSource(src)
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		for _, cause := range []error{&OAuth2Error{Status: http.StatusServiceUnavailable}, ErrInvalidTokenResponse} {
			src.fail(cause)
			if _, err := c.Token(t.Context()); !errors.Is(err, cause) || errors.Is(err, errRefreshBackoff) {
				t.Fatalf("Token(failing) = %v, want %v alone", err, cause)
			}
			_, err := c.Token(t.Context())
			if !errors.Is(err, errRefreshBackoff) || !errors.Is(err, cause) ||
				err.Error() != errRefreshBackoff.Error()+": "+cause.Error() {
				t.Fatalf("Token(backing off) = %v, want errRefreshBackoff wrapping %v", err, cause)
			}
			time.Sleep(pause)
		}
		if n := src.calls.Load(); n != 2 {
			t.Fatalf("source calls = %d, want 2: none while backing off", n)
		}
	})
}

func TestCachedSourceTokenNilToken(t *testing.T) {
	c, err := NewCachedSource(nilSource{})
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	if _, err := c.Token(t.Context()); !errors.Is(err, ErrNoToken) {
		t.Fatalf("Token = %v, want ErrNoToken", err)
	}
}

func TestCachedSourceTokenFailedWithToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, fail := range []error{errSource, fmt.Errorf("%w: %w", ErrRotationNotSaved, errStore)} {
			var calls atomic.Int32
			c, err := NewCachedSource(tokenWithError(&calls, fail))
			if err != nil {
				t.Fatalf(wantCache, err)
			}
			for range 2 {
				if tok, terr := c.Token(t.Context()); tok != nil || !errors.Is(terr, fail) {
					t.Fatalf("source failing with a token = %v, %v, want no token and %v", tok, terr, fail)
				}
				time.Sleep(pause)
			}
			if calls.Load() != 2 {
				t.Fatalf("token of a failed call cached: %d calls, want 2", calls.Load())
			}
		}
	})
}

// TestCachedSourceTokenUnsavedRotation fails two refreshes while the store
// fails: the second saves the rotation again and exchanges nothing.
func TestCachedSourceTokenUnsavedRotation(t *testing.T) {
	idp, api := rotatingServer(t), acceptOnly(t, "Bearer at-2")
	synctest.Test(t, func(t *testing.T) {
		st := &fakeStore{initial: firstRT, saved: make(chan string, 8), saveErr: errStore}
		closing := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		c, err := NewCachedSource(newRefresh(t, closing, idp.srv.URL, st))
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		client := &http.Client{Transport: NewTransport(closing.Transport, AsSigner(c))}
		for range 2 {
			err := getStatus(t, client, api.URL, http.StatusNoContent)
			if !errors.Is(err, ErrCredential) || !errors.Is(err, ErrRotationNotSaved) || !errors.Is(err, errStore) {
				t.Fatalf("unsaved rotation err = %v, want ErrCredential wrapping ErrRotationNotSaved", err)
			}
			time.Sleep(pause)
		}
		st.saveErr = nil
		for range retried {
			if err := getStatus(t, client, api.URL, http.StatusNoContent); err != nil {
				t.Fatalf("GET = %v, want 204", err)
			}
		}
		want := []string{rotatedRT, rotatedRT, rotatedRT, "rt-2"}
		if saved := drained(st.saved); len(idp.requests()) != 2 || !slices.Equal(saved, want) {
			t.Fatalf("%d exchanges saving %v, want 2 saving rt-1 until it is saved, then rt-2", len(idp.requests()),
				saved)
		}
	})
}

// acceptOnly answers 204 to requests authorized by auth and 401 otherwise.
func acceptOnly(t *testing.T, auth string) *httptest.Server {
	t.Helper()
	return serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(authorization) != auth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestCachedSourceTokenLeaderCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		c, err := NewCachedSource(TokenSourceFunc(func(ctx context.Context) (*Token, error) {
			calls.Add(1)
			select {
			case <-release:
				return &Token{Value: secret.New("fresh")}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}))
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		leaderCtx, cancel := context.WithCancel(t.Context())
		leaderErr := make(chan error, 1)
		go func() {
			_, err := c.Token(leaderCtx)
			leaderErr <- err
		}()
		synctest.Wait()
		follower := make(chan *Token, 1)
		go func() {
			tok, err := c.Token(t.Context())
			if err != nil {
				t.Errorf("follower Token = %v, want the refreshed token", err)
			}
			follower <- tok
		}()
		synctest.Wait()
		cancel()
		leader := <-leaderErr
		close(release)
		const want = "cred: token refresh: shared call abandoned: context canceled"
		if !errors.Is(leader, context.Canceled) || leader.Error() != want {
			t.Errorf("leader err = %v, want %q", leader, want)
		}
		if tok := <-follower; tok == nil || tok.Value.Reveal() != "fresh" || calls.Load() != 1 {
			t.Errorf("follower got %v after %d calls, want fresh after 1", tok, calls.Load())
		}
	})
}

func TestCachedSourceTokenStampede(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c, err := NewCachedSource(TokenSourceFunc(func(context.Context) (*Token, error) {
			calls.Add(1)
			time.Sleep(time.Second)
			return &Token{Value: secret.New("shared")}, nil
		}))
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				if tok, err := c.Token(t.Context()); err != nil || tok.Value.Reveal() != "shared" {
					t.Errorf("Token = %v, %v, want shared", tok, err)
				}
			})
		}
		wg.Wait()
		if calls.Load() != 1 {
			t.Fatalf("upstream calls = %d, want 1", calls.Load())
		}
	})
}

func TestCachedSourceTokenTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, err := NewCachedSource(TokenSourceFunc(func(ctx context.Context) (*Token, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}), WithTimeout(5*time.Second))
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		start := time.Now()
		if _, err := c.Token(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Token = %v, want context.DeadlineExceeded", err)
		}
		if waited := time.Since(start); waited != 5*time.Second {
			t.Fatalf("Token waited %v, want 5s", waited)
		}
	})
}

func TestCachedSourceInvalidate(t *testing.T) {
	c, src := newCache(t, 0)
	first := nextToken(t, c)
	c.Invalidate(nil)
	c.Invalidate(&Token{Value: secret.New(seq1)})
	if got := mustToken(t, c); got != seq1 {
		t.Fatalf("Token after a foreign Invalidate = %s, want %s kept", got, seq1)
	}
	c.Invalidate(first)
	if got := mustToken(t, c); got != seq2 {
		t.Fatalf("Token after Invalidate = %s, want %s", got, seq2)
	}
	c.Invalidate(first)
	if got := mustToken(t, c); got != seq2 || src.calls.Load() != 2 {
		t.Fatalf("Token after a stale Invalidate = %s after %d calls, want %s after 2", got, src.calls.Load(), seq2)
	}
}

// TestCachedSourceInvalidatePaced drops the cached token at most once per
// pause: a second Invalidate within 30s keeps the token, one after it drops it.
func TestCachedSourceInvalidatePaced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, 0)
		c.Invalidate(nextToken(t, c))
		second := nextToken(t, c)
		time.Sleep(pause - time.Nanosecond)
		c.Invalidate(second)
		if got := mustToken(t, c); got != seq2 || src.calls.Load() != 2 {
			t.Fatalf("Token after an Invalidate within the pause = %s after %d calls, want %s after 2",
				got, src.calls.Load(), seq2)
		}
		time.Sleep(time.Nanosecond)
		c.Invalidate(second)
		if got := mustToken(t, c); got != seq3 || src.calls.Load() != retried {
			t.Fatalf("Token after an Invalidate past the pause = %s after %d calls, want %s after 3",
				got, src.calls.Load(), seq3)
		}
	})
}

// TestCachedSourceInvalidateConcurrent drops the first token from many
// callers at once: exactly one refresh follows, whatever the order.
func TestCachedSourceInvalidateConcurrent(t *testing.T) {
	c, src := newCache(t, 0)
	first := nextToken(t, c)
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	for range racers {
		ready.Add(1)
		done.Go(func() {
			ready.Done()
			<-start
			c.Invalidate(first)
			if tok, err := c.Token(t.Context()); err != nil || tok.Value.Reveal() != seq2 {
				t.Errorf("Token after the invalidation = %v, %v, want %s", tok, err, seq2)
			}
		})
	}
	ready.Wait()
	close(start)
	done.Wait()
	if n := src.calls.Load(); n != 2 {
		t.Fatalf("source calls = %d, want 2: the first token and one refresh", n)
	}
}

// TestCachedSourceDrop forces the interleavings of Invalidate: of two calls on
// one entry the second finds the first's drop and pause, one that saw the entry
// before a refresh keeps the new one, and a drop is never dropped again.
func TestCachedSourceDrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, 0)
		first := nextToken(t, c)
		seen, now := c.cur.Load(), time.Now()
		c.drop(seen, first, now)
		dropped := c.cur.Load()
		c.drop(seen, first, now)
		if got := c.cur.Load(); got != dropped || got.tok != nil || !got.nextDrop.Equal(now.Add(pause)) {
			t.Fatalf("second drop of the entry both saw = %+v, want the first drop %+v, its pause ending in 30s",
				got, dropped)
		}
		time.Sleep(pause)
		c.drop(dropped, nil, time.Now())
		if got := c.cur.Load(); got != dropped {
			t.Fatalf("drop(nil) of an entry without a token = %+v, want %+v kept", got, dropped)
		}
		if got := mustToken(t, c); got != seq2 || src.calls.Load() != 2 {
			t.Fatalf("Token after the drops = %s after %d calls, want %s after 2", got, src.calls.Load(), seq2)
		}
		refreshed := c.cur.Load()
		c.drop(seen, first, time.Now())
		if got := c.cur.Load(); got != refreshed || got.tok.Value.Reveal() != seq2 {
			t.Fatalf("drop of the entry seen before the refresh = %+v, want %+v kept", got, refreshed)
		}
	})
}

// TestCachedSourceReplace forces a drop between the entry a refresh saw and
// its store: the store caches nothing, and once it sees the drop it caches
// its token with the pause of that drop.
func TestCachedSourceReplace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _ := newCache(t, 0)
		first := nextToken(t, c)
		seen := c.cur.Load()
		c.Invalidate(first)
		dropped := c.cur.Load()
		e := &entry{tok: &Token{Value: secret.New(seq2)}}
		if c.replace(seen, e) || c.cur.Load() != dropped {
			t.Fatalf("replace over the entry seen before a drop cached %+v, want the drop %+v kept", c.cur.Load(),
				dropped)
		}
		if !c.replace(dropped, e) || c.cur.Load() != e || !e.nextDrop.Equal(time.Now().Add(pause)) {
			t.Fatalf("replace over the drop cached %+v, want %+v with the pause of the drop", c.cur.Load(), e)
		}
	})
}

// TestCachedSourceFetchKeepsAConcurrentDrop drops the token due for refresh
// while its refresh runs: the new token is cached with the pause of that drop,
// so an Invalidate of it within 30s keeps it.
func TestCachedSourceFetchKeepsAConcurrentDrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c *CachedSource
		var calls atomic.Int64
		src := TokenSourceFunc(func(context.Context) (*Token, error) {
			n := calls.Add(1)
			if n == 2 {
				c.Invalidate(c.cur.Load().tok)
			}
			value := secret.New("t" + strconv.FormatInt(n, decimalBase))
			return &Token{Value: value, Expires: time.Now().Add(time.Hour)}, nil
		})
		var err error
		if c, err = NewCachedSource(src); err != nil {
			t.Fatalf(wantCache, err)
		}
		mustToken(t, c)
		time.Sleep(time.Hour - pause)
		dropped := time.Now()
		if got := mustToken(t, c); got != seq2 || !c.cur.Load().nextDrop.Equal(dropped.Add(pause)) {
			t.Fatalf("Token after a drop during its refresh = %s, cached %+v; want %s with the pause of the drop", got,
				c.cur.Load(), seq2)
		}
		c.Invalidate(c.cur.Load().tok)
		if got := mustToken(t, c); got != seq2 || calls.Load() != 2 {
			t.Fatalf("Token after an Invalidate within the pause = %s after %d calls, want %s after 2", got,
				calls.Load(), seq2)
		}
	})
}

// TestEntryFresh judges each entry by the clock: fresh until its refresh
// instant, or for ever without one; an entry without a token is never fresh.
func TestEntryFresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		tok := &Token{Value: secret.New(seq1)}
		for e, want := range map[*entry]bool{
			{tok: tok}: true, {tok: tok, refreshAt: now.Add(time.Nanosecond)}: true, {tok: tok, refreshAt: now}: false,
			{tok: tok, refreshAt: now.Add(-time.Second)}: false, {}: false, {refreshAt: now.Add(time.Second)}: false,
		} {
			if got := e.fresh(); got != want {
				t.Errorf("fresh(refresh at %v) = %t, want %t", e.refreshAt, got, want)
			}
		}
	})
}

func TestCachedSourceFetch(t *testing.T) {
	c, src := newCache(t, time.Hour)
	mustToken(t, c)
	tok, err := c.fetch(t.Context())
	if err != nil || tok.Value.Reveal() != seq1 || src.calls.Load() != 1 {
		t.Fatalf("fetch = %v, %v after %d calls, want the cached %s after 1", tok, err, src.calls.Load(), seq1)
	}
}

// TestCachedSourceFetchShares caches a copy of the token of the source with
// its header value rendered, and leaves the token of the source as it was.
func TestCachedSourceFetchShares(t *testing.T) {
	own := &Token{Value: secret.New("abc"), Type: dpop}
	c, err := NewCachedSource(TokenSourceFunc(func(context.Context) (*Token, error) { return own, nil }))
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	tok, err := c.fetch(t.Context())
	if err != nil || tok == own || tok.rendered.Reveal() != dpopABC || !own.rendered.IsZero() ||
		c.cur.Load().tok != tok {
		t.Fatalf("fetch = %p rendering %q, %v, source token %p rendering %t; want a cached copy rendering DPoP abc",
			tok, tok.rendered.Reveal(), err, own, !own.rendered.IsZero())
	}
}

// TestCachedSourceFetchResetsBackoff ends the pause of a failed refresh with a
// refresh that succeeds.
func TestCachedSourceFetchResetsBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, src := newCache(t, time.Hour)
		c.backoff.Fail(time.Now())
		tok, err := c.fetch(t.Context())
		if waiting := c.backoff.Waiting(time.Now()); err != nil || tok.Value.Reveal() != seq1 || waiting {
			t.Fatalf("fetch = %v, %v after %d calls, backing off %t; want %s, not backing off", tok, err,
				src.calls.Load(), waiting, seq1)
		}
	})
}

// TestCachedSourceFetchExpired takes a token expiring as it arrives for a
// failed refresh: nothing is cached and no other refresh starts for 30s.
func TestCachedSourceFetchExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		src := TokenSourceFunc(func(context.Context) (*Token, error) {
			calls.Add(1)
			return &Token{Value: secret.New("old"), Expires: time.Now()}, nil
		})
		c, err := NewCachedSource(src)
		if err != nil {
			t.Fatalf(wantCache, err)
		}
		if tok, err := c.Token(t.Context()); !errors.Is(err, ErrInvalidTokenResponse) || tok != nil ||
			c.cur.Load() != nil {
			t.Fatalf("Token(expired) = %v, %v, want ErrInvalidTokenResponse and nothing cached", tok, err)
		}
		time.Sleep(pause - time.Nanosecond)
		if tok, err := c.Token(t.Context()); !errors.Is(err, errRefreshBackoff) || tok != nil || calls.Load() != 1 {
			t.Fatalf("Token(backing off) = %v, %v after %d calls, want errRefreshBackoff after 1", tok, err,
				calls.Load())
		}
	})
}

// TestUnexpiredToken passes a token that expires after its answer arrives, or
// never, and returns the instant of arrival; the answer takes 10s.
func TestUnexpiredToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const delay = 10 * time.Second
		for _, tc := range []struct {
			lifetime time.Duration
			ok       bool
		}{{delay + time.Nanosecond, true}, {0, true}, {delay, false}, {time.Second, false}, {-time.Hour, false}} {
			start := time.Now()
			src := TokenSourceFunc(func(context.Context) (*Token, error) {
				tok := &Token{Value: secret.New(seq1)}
				if tc.lifetime != 0 {
					tok.Expires = start.Add(tc.lifetime)
				}
				time.Sleep(delay)
				return tok, nil
			})
			tok, arrived, err := unexpiredToken(t.Context(), src)
			ok := err == nil && tok != nil
			if ok != tc.ok || !ok && !errors.Is(err, errRefreshedExpired) || !arrived.Equal(start.Add(delay)) {
				t.Errorf("unexpiredToken(living %v, answered in %v) = %v, %v, arrived %v; want accepted %t, else "+
					"errRefreshedExpired, arrived %v", tc.lifetime, delay, tok, err, arrived.Sub(start), tc.ok, delay)
			}
		}
		if tok, _, err := unexpiredToken(t.Context(), nilSource{}); tok != nil || !errors.Is(err, ErrNoToken) {
			t.Fatalf("unexpiredToken(nil token) = %v, %v, want ErrNoToken", tok, err)
		}
	})
}

func ExampleNewCachedSource() {
	src := TokenSourceFunc(func(context.Context) (*Token, error) {
		return &Token{Value: secret.New("abc"), Expires: time.Now().Add(time.Hour)}, nil
	})
	cached, err := NewCachedSource(src)
	if err != nil {
		fmt.Println(err)
		return
	}
	tok, err := cached.Token(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tok.Value.Reveal())
	// Output: abc
}

func BenchmarkCachedSourceToken(b *testing.B) {
	src := &sequence{ttl: time.Hour}
	c, err := NewCachedSource(src)
	if err != nil {
		b.Fatalf(wantCache, err)
	}
	ctx := b.Context()
	if tok, err := c.Token(ctx); err != nil || tok.Value.Reveal() != seq1 {
		b.Fatalf("Token = %v, %v, want the cached %s", tok, err, seq1)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.Token(ctx); err != nil {
				b.Errorf("Token = %v, want the cached token", err)
				return
			}
		}
	})
	if n := src.calls.Load(); n != 1 {
		b.Fatalf("source calls = %d, want 1: every other Token is a cache hit", n)
	}
}
