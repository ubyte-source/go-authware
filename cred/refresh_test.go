package cred

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// The rotations a refresh token goes through, and the calls that share one.
const (
	rotations       = 3
	concurrentCalls = 8
)

// TestNewRefreshTokenNil reports a nil config and a nil store at once.
func TestNewRefreshTokenNil(t *testing.T) {
	if _, err := NewRefreshToken(nil, NewMemoryRefreshStore(secret.New("rt"))); !errors.Is(err, ErrInvalidConfig) ||
		err.Error() != "cred: invalid config: nil config" {
		t.Fatalf("NewRefreshToken(nil) = %v, want ErrInvalidConfig: nil config", err)
	}
	_, err := NewRefreshToken(nil, nil)
	const nilBoth = "cred: invalid config: nil config\ncred: invalid config: nil refresh token store"
	if !errors.Is(err, errNilConfig) || !errors.Is(err, errNilStore) || err.Error() != nilBoth {
		t.Fatalf("NewRefreshToken(nil, nil) = %v, want every problem at once: %q", err, nilBoth)
	}
}

func TestNewRefreshToken(t *testing.T) {
	_, err := NewRefreshToken(&ClientConfig{TokenURL: idpEndpoint, Timeout: -1}, nil)
	const want = "cred: invalid config: missing client ID\ncred: invalid config: timeout is negative\n" +
		"cred: invalid config: nil refresh token store"
	if !errors.Is(err, ErrInvalidConfig) || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if _, err := NewRefreshToken(&ClientConfig{TokenURL: idpEndpoint, ClientID: "c"}, nil); !errors.Is(err,
		ErrInvalidConfig) {
		t.Fatalf("NewRefreshToken(nil store) = %v, want ErrInvalidConfig", err)
	}
	for timeout, want := range map[time.Duration]time.Duration{0: wantTimeout, customTimeout: customTimeout} {
		cfg := &ClientConfig{TokenURL: idpEndpoint, ClientID: "c", Timeout: timeout}
		src, err := NewRefreshToken(cfg, NewMemoryRefreshStore(secret.Value{}))
		if err != nil {
			t.Fatalf("NewRefreshToken = %v, want a source", err)
		}
		rt, ok := src.(*refreshToken)
		if !ok {
			t.Fatalf("source = %T, want *refreshToken", src)
		}
		if rt.timeout != want || rt.endpoint.client.Timeout != want {
			t.Errorf("Timeout %v: flight %v, client %v, want %v", timeout, rt.timeout, rt.endpoint.client.Timeout, want)
		}
	}
}

func TestNewRefreshTokenScopes(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK, okToken))
	cfg := &ClientConfig{
		TokenURL: rec.srv.URL, ClientID: testClientID, Scopes: []string{"a", "b"},
	}
	src, err := NewRefreshToken(cfg, NewMemoryRefreshStore(secret.New(firstRT)))
	if err != nil {
		t.Fatalf("NewRefreshToken = %v, want a source", err)
	}
	mustToken(t, src)
	if got := rec.requests()[0].form.Get("scope"); got != "a b" {
		t.Fatalf("scope = %q, want %q", got, "a b")
	}
}

func TestNewMemoryRefreshStore(t *testing.T) {
	st := NewMemoryRefreshStore(secret.New("a"))
	if v, err := st.Load(t.Context()); err != nil || v.Reveal() != "a" {
		t.Fatalf("initial Load = %q, %v, want a", v.Reveal(), err)
	}
	if err := st.Save(t.Context(), secret.New("b")); err != nil {
		t.Fatalf("Save = %v, want nil", err)
	}
	if v, err := st.Load(t.Context()); err != nil || v.Reveal() != "b" {
		t.Fatalf("Load = %q, %v, want b", v.Reveal(), err)
	}
}

// TestRefreshTokenTokenEmptyStore starts from a store that holds no refresh
// token: the source loads it again until one is saved.
func TestRefreshTokenTokenEmptyStore(t *testing.T) {
	st := NewMemoryRefreshStore(secret.Value{})
	src := newRefresh(t, nil, rotatingServer(t).srv.URL, st)
	for range 2 {
		if tok, err := src.Token(t.Context()); tok != nil || !errors.Is(err, ErrNoRefreshToken) {
			t.Fatalf("Token(empty store) = %v, %v, want ErrNoRefreshToken", tok, err)
		}
	}
	if err := st.Save(t.Context(), secret.New(firstRT)); err != nil {
		t.Fatalf("Save = %v, want nil", err)
	}
	if got := mustToken(t, src); got != "at-1" {
		t.Fatalf("Token after a refresh token is saved = %s, want at-1", got)
	}
}

func TestRefreshTokenToken(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 8)}
	src := newRefresh(t, nil, rotatingServer(t).srv.URL, st)
	for i := 1; i <= rotations; i++ {
		if got := mustToken(t, src); got != "at-"+strconv.Itoa(i) {
			t.Fatalf("exchange %d = %s, want at-%d", i, got, i)
		}
		if saved := <-st.saved; saved != "rt-"+strconv.Itoa(i) {
			t.Fatalf("saved = %q, want rt-%d", saved, i)
		}
	}
	if st.loads.Load() != 1 {
		t.Fatalf("store loads = %d, want 1", st.loads.Load())
	}
}

// markStore holds a refresh token and counts the saves made under a marked
// context.
type markStore struct {
	marked atomic.Int32
}

func (*markStore) Load(context.Context) (secret.Value, error) { return secret.New(firstRT), nil }

func (s *markStore) Save(ctx context.Context, _ secret.Value) error {
	if isMarked(ctx) {
		s.marked.Add(1)
	}
	return nil
}

// TestRefreshTokenTokenPassesTheContext exchanges and saves the rotated token
// under the context Token gets.
func TestRefreshTokenTokenPassesTheContext(t *testing.T) {
	var exchanges atomic.Int32
	idp := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if isMarked(r.Context()) {
			exchanges.Add(1)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
			Body: io.NopCloser(strings.NewReader(`{"access_token":"at-1","refresh_token":"rt-1"}`))}, nil
	})
	st := &markStore{}
	src := newRefresh(t, &http.Client{Transport: idp}, idpEndpoint, st)
	if _, err := src.Token(marked(t)); err != nil || exchanges.Load() != 1 || st.marked.Load() != 1 {
		t.Fatalf("Token = %v after %d marked exchanges and %d marked saves, want nil after 1 and 1", err,
			exchanges.Load(), st.marked.Load())
	}
}

// failOnceStore fails its first save and counts, as markStore, the saves
// made under a marked context.
type failOnceStore struct {
	markStore

	saves atomic.Int32
}

func (s *failOnceStore) Save(ctx context.Context, v secret.Value) error {
	if s.saves.Add(1) == 1 {
		return errStore
	}
	return s.markStore.Save(ctx, v)
}

// TestRefreshTokenTokenSavesPendingUnderTheContext saves a rotation the store
// missed under the context of the Token call whose exchange presents it.
func TestRefreshTokenTokenSavesPendingUnderTheContext(t *testing.T) {
	idp := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
			Body: io.NopCloser(strings.NewReader(`{"access_token":"at-1","refresh_token":"rt-1"}`))}, nil
	})
	st := &failOnceStore{}
	src := newRefresh(t, &http.Client{Transport: idp}, idpEndpoint, st)
	if _, err := src.Token(marked(t)); !errors.Is(err, ErrRotationNotSaved) {
		t.Fatalf("first Token = %v, want ErrRotationNotSaved", err)
	}
	if _, err := src.Token(marked(t)); err != nil || st.saves.Load() != 2 || st.marked.Load() != 1 {
		t.Fatalf("second Token = %v after %d saves, %d marked; want nil after 2, the second marked", err,
			st.saves.Load(), st.marked.Load())
	}
}

func TestRefreshTokenTokenConcurrent(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 64)}
	rec := rotatingServer(t)
	src := newRefresh(t, nil, rec.srv.URL, st)
	var wg sync.WaitGroup
	for range concurrentCalls {
		wg.Go(func() {
			if _, err := src.Token(t.Context()); err != nil {
				t.Errorf("Token = %v, want a token", err)
			}
		})
	}
	wg.Wait()
	close(st.saved)
	var saved []string
	for s := range st.saved {
		saved = append(saved, s)
	}
	if len(saved) != len(rec.requests()) || saved[len(saved)-1] != "rt-"+strconv.Itoa(len(saved)) {
		t.Fatalf("saved = %v for %d exchanges, want one save per exchange, the last its rotation", saved,
			len(rec.requests()))
	}
}

// blockingStore holds Load until its context ends and refuses Save.
type blockingStore struct{}

func (blockingStore) Load(ctx context.Context) (secret.Value, error) {
	<-ctx.Done()
	return secret.Value{}, fmt.Errorf("blocking store: %w", ctx.Err())
}

func (blockingStore) Save(context.Context, secret.Value) error {
	return errStore
}

func TestRefreshTokenTokenTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := &ClientConfig{
			TokenURL: idpEndpoint, ClientID: testClientID, Timeout: 3 * time.Second,
		}
		src, err := NewRefreshToken(cfg, blockingStore{})
		if err != nil {
			t.Fatalf("NewRefreshToken = %v, want a source", err)
		}
		start := time.Now()
		if _, err := src.Token(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context.DeadlineExceeded", err)
		}
		if waited := time.Since(start); waited != 3*time.Second {
			t.Fatalf("waited %v, want 3s", waited)
		}
	})
}

func TestRefreshTokenTokenCallerCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var exchanges atomic.Int32
		idp := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			n := exchanges.Add(1)
			if err := r.ParseForm(); err != nil || r.PostForm.Get("refresh_token") != "rt-"+strconv.Itoa(int(n-1)) {
				t.Errorf("exchange %d presented %q, %v, want rt-%d", n, r.PostForm.Get("refresh_token"), err, n-1)
			}
			if n == 1 {
				<-release
			}
			i := strconv.Itoa(int(n))
			body := `{"access_token":"at-` + i + `","refresh_token":"rt-` + i + `"}`
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})
		st := &fakeStore{initial: firstRT, saved: make(chan string, 2)}
		cfg := &ClientConfig{
			HTTPClient: &http.Client{Transport: idp}, TokenURL: idpEndpoint, ClientID: testClientID,
		}
		src, err := NewRefreshToken(cfg, st)
		if err != nil {
			t.Fatalf("NewRefreshToken = %v, want a source", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		abandoned := make(chan error, 1)
		go func() {
			_, err := src.Token(ctx)
			abandoned <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-abandoned; !errors.Is(err, context.Canceled) ||
			err.Error() != "cred: refresh token: shared call abandoned: context canceled" {
			t.Fatalf("abandoned call err = %v, want context.Canceled named by cred", err)
		}
		close(release)
		synctest.Wait()
		if got := mustToken(t, src); got != "at-2" {
			t.Fatalf("next exchange = %s, want at-2", got)
		}
		if saved := drained(st.saved); strings.Join(saved, " ") != "rt-1 rt-2" {
			t.Fatalf("saved %v, want the abandoned rotation rt-1, then rt-2", saved)
		}
	})
}

func TestRefreshTokenTokenInvalidAccess(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 1)}
	rec := newRecording(t, answer(http.StatusOK, `{"access_token":"a\u0001b","refresh_token":"rt-1"}`))
	tok, err := newRefresh(t, nil, rec.srv.URL, st).Token(t.Context())
	if tok != nil || !errors.Is(err, ErrInvalidTokenResponse) || !strings.HasPrefix(err.Error(),
		"cred: refresh token: ") {
		t.Fatalf("Token() = %v, %v, want ErrInvalidTokenResponse named after the grant", tok, err)
	}
	if saved := drained(st.saved); !slices.Equal(saved, []string{rotatedRT}) {
		t.Fatalf("saved %v, want the rotation kept despite the bad access token", saved)
	}
}

// TestRefreshTokenTokenSaveFails fails every save: the rotation stays in
// memory, and the next exchange saves it again before presenting it.
func TestRefreshTokenTokenSaveFails(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 2), saveErr: errStore}
	idp := rotatingServer(t)
	src := newRefresh(t, nil, idp.srv.URL, st)
	for range 2 {
		tok, err := src.Token(t.Context())
		if tok != nil || !errors.Is(err, ErrRotationNotSaved) || !errors.Is(err, errStore) {
			t.Fatalf("Token() = %v, %v, want no token and ErrRotationNotSaved wrapping errStore", tok, err)
		}
	}
	if saved := drained(st.saved); !slices.Equal(saved, []string{rotatedRT, rotatedRT}) || len(idp.requests()) != 1 {
		t.Fatalf("saves = %v after %d exchanges, want rt-1 twice after 1: no exchange presents an unsaved rotation",
			saved, len(idp.requests()))
	}
}

// TestRefreshTokenTokenPendingRotation fails the exchange that follows a
// rotation the store missed: that rotation is saved first.
func TestRefreshTokenTokenPendingRotation(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 4), saveErr: errStore}
	var calls atomic.Int32
	rec := newRecording(t, func(captured) (int, string) {
		if calls.Add(1) == 1 {
			return http.StatusOK, `{"access_token":"at","refresh_token":"` + rotatedRT + `"}`
		}
		return http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`
	})
	src := newRefresh(t, nil, rec.srv.URL, st)
	if _, err := src.Token(t.Context()); !errors.Is(err, ErrRotationNotSaved) {
		t.Fatalf("first exchange = %v, want ErrRotationNotSaved", err)
	}
	st.saveErr = nil
	_, err := src.Token(t.Context())
	var oe *OAuth2Error
	if !errors.As(err, &oe) || oe.Status != http.StatusServiceUnavailable {
		t.Fatalf("second exchange = %v, want the 503 as an *OAuth2Error", err)
	}
	if saved := drained(st.saved); !slices.Equal(saved, []string{rotatedRT, rotatedRT}) {
		t.Fatalf("ErrRotationNotSaved godoc: \"the next exchange saves it again\"; saved %v, want rt-1 twice", saved)
	}
	if reqs := rec.requests(); len(reqs) != 2 || reqs[1].form.Get(oauthwire.ParamRefreshToken) != rotatedRT {
		t.Fatalf("exchanges = %+v, want the second presenting rt-1", reqs)
	}
}

func TestRefreshTokenTokenSaveRetried(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 4), saveErr: errStore}
	var calls atomic.Int32
	rec := newRecording(t, func(captured) (int, string) {
		if calls.Add(1) == 1 {
			return http.StatusOK, `{"access_token":"at","refresh_token":"rt-1"}`
		}
		return http.StatusOK, okToken
	})
	src := newRefresh(t, nil, rec.srv.URL, st)
	if _, err := src.Token(t.Context()); !errors.Is(err, ErrRotationNotSaved) {
		t.Fatalf("first exchange = %v, want ErrRotationNotSaved", err)
	}
	st.saveErr = nil
	mustToken(t, src)
	mustToken(t, src)
	if n := len(st.saved); n != 2 {
		t.Fatalf("%d saves, want the failed one and its retry", n)
	}
	if got := fmt.Sprint(<-st.saved, <-st.saved); got != rotatedRT+rotatedRT {
		t.Fatalf("saves = %s, want rt-1 twice", got)
	}
	if reqs := rec.requests(); reqs[1].form.Get("refresh_token") != rotatedRT ||
		reqs[2].form.Get("refresh_token") != rotatedRT {
		t.Fatalf("exchanges = %+v, want the second and third presenting rt-1", reqs)
	}
}

func TestRefreshTokenTokenNotRotated(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 1)}
	echo := `{"access_token":"at","refresh_token":"` + firstRT + `"}`
	var calls atomic.Int32
	rec := newRecording(t, func(captured) (int, string) {
		if calls.Add(1) == 1 {
			return http.StatusOK, okToken
		}
		return http.StatusOK, echo
	})
	src := newRefresh(t, nil, rec.srv.URL, st)
	mustToken(t, src)
	mustToken(t, src)
	for _, c := range rec.requests() {
		if c.form.Get(oauthwire.ParamRefreshToken) != firstRT || c.form.Get("grant_type") != "refresh_token" {
			t.Fatalf("form = %v, want a refresh_token grant of %s", c.form, firstRT)
		}
	}
	if len(st.saved) != 0 {
		t.Fatalf("saves = %d, want 0: the token did not rotate", len(st.saved))
	}
}

func TestRefreshTokenTokenRejected(t *testing.T) {
	st := &fakeStore{initial: firstRT, saved: make(chan string, 1)}
	rec := newRecording(t, answer(http.StatusBadRequest, `{"error":"invalid_grant"}`))
	_, err := newRefresh(t, nil, rec.srv.URL, st).Token(t.Context())
	var oe *OAuth2Error
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" || oe.Transient() || len(st.saved) != 0 {
		t.Fatalf("Token = %v, want a permanent invalid_grant and no save", err)
	}
}

func TestRefreshTokenTokenStoreErrors(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK, okToken))
	empty := &fakeStore{}
	if _, err := newRefresh(t, nil, rec.srv.URL, empty).Token(t.Context()); !errors.Is(err, ErrNoRefreshToken) {
		t.Fatalf("Token(empty store) = %v, want ErrNoRefreshToken", err)
	}
	broken := &fakeStore{loadErr: errStore}
	if _, err := newRefresh(t, nil, rec.srv.URL, broken).Token(t.Context()); !errors.Is(err, broken.loadErr) {
		t.Fatalf("Token(failing store) = %v, want errStore", err)
	}
	if len(rec.requests()) != 0 {
		t.Fatalf("exchanges = %d, want 0 without a refresh token", len(rec.requests()))
	}
}
