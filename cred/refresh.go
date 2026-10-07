package cred

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"sync"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/flight"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// errNilStore refuses a refresh token source without a store.
var errNilStore = fmt.Errorf("%w: nil refresh token store", ErrInvalidConfig)

// RefreshTokenStore persists the refresh token across restarts. It must be safe
// for concurrent use.
type RefreshTokenStore interface {
	// Load returns the stored refresh token, the zero Value while none is stored.
	Load(ctx context.Context) (secret.Value, error)
	// Save stores token, a rotated refresh token; its failure fails the exchange
	// with ErrRotationNotSaved.
	Save(ctx context.Context, token secret.Value) error
}

type refreshToken struct {
	store    RefreshTokenStore
	endpoint tokenEndpoint
	form     url.Values
	timeout  time.Duration
	group    flight.Group[*Token]
	current  secret.Value
	loaded   bool
	unsaved  bool
}

// NewRefreshToken returns a TokenSource for the refresh_token grant, or an error
// wrapping ErrInvalidConfig. Exchanges never overlap and outlive a caller that
// gives up, and a failed Save of a rotated token fails one with ErrRotationNotSaved.
func NewRefreshToken(cfg *ClientConfig, store RefreshTokenStore) (TokenSource, error) {
	var storeErr error
	if store == nil {
		storeErr = errNilStore
	}
	if cfg == nil {
		return nil, errors.Join(errNilConfig, storeErr)
	}
	ep, cfgErr := cfg.endpoint()
	if err := errors.Join(cfgErr, storeErr); err != nil {
		return nil, err
	}
	form := url.Values{oauthwire.ParamGrantType: {oauthwire.GrantRefreshToken}}
	setScopes(form, cfg.Scopes)
	return &refreshToken{store: store, endpoint: ep, form: form, timeout: cmp.Or(cfg.Timeout, defaultTimeout)}, nil
}

// errRefresh wraps a failed refresh token exchange.
const errRefresh = errPrefix + "refresh token: %w"

// Token runs, or joins, the exchange in flight.
func (s *refreshToken) Token(ctx context.Context) (*Token, error) {
	tok, err := s.group.Do(ctx, s.timeout, s.exchange)
	if errors.Is(err, flight.ErrAbandoned) {
		return nil, fmt.Errorf(errRefresh, err)
	}
	return tok, err
}

// exchange runs inside the flight, whose calls never overlap, so it owns
// current, loaded and unsaved; a rotation the store missed is saved before
// the token it holds is presented.
func (s *refreshToken) exchange(ctx context.Context) (*Token, error) {
	if !s.loaded {
		rt, err := s.store.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf(errPrefix+"load refresh token: %w", err)
		}
		s.current, s.loaded = rt, !rt.IsZero()
	}
	if s.current.IsZero() {
		return nil, ErrNoRefreshToken
	}
	if err := s.save(ctx); err != nil {
		return nil, err
	}
	form := maps.Clone(s.form)
	form.Set(oauthwire.ParamRefreshToken, s.current.Reveal())
	resp, err := s.endpoint.post(ctx, form)
	if err != nil {
		return nil, fmt.Errorf(errRefresh, err)
	}
	return s.accept(ctx, &resp)
}

// accept saves the rotation that resp carries, when there is one, and returns
// the access token of resp.
func (s *refreshToken) accept(ctx context.Context, resp *oauthwire.TokenResponse) (*Token, error) {
	if next := secret.New(resp.RefreshToken); !next.IsZero() && !next.Equal(s.current) {
		s.current, s.unsaved = next, true
	}
	if err := s.save(ctx); err != nil {
		return nil, err
	}
	tok, err := tokenFromResponse(resp)
	if err != nil {
		return nil, fmt.Errorf(errRefresh, err)
	}
	return tok, nil
}

// save stores a rotation the store has not saved yet; a failure wraps
// ErrRotationNotSaved and leaves the rotation pending.
func (s *refreshToken) save(ctx context.Context) error {
	if !s.unsaved {
		return nil
	}
	if err := s.store.Save(ctx, s.current); err != nil {
		return fmt.Errorf("%w: %w", ErrRotationNotSaved, err)
	}
	s.unsaved = false
	return nil
}

type memoryStore struct {
	mu    sync.Mutex
	token secret.Value
}

// NewMemoryRefreshStore returns a RefreshTokenStore that keeps the token in
// memory only, starting from initial.
func NewMemoryRefreshStore(initial secret.Value) RefreshTokenStore {
	return &memoryStore{token: initial}
}

// Load returns the stored token.
func (m *memoryStore) Load(context.Context) (secret.Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token, nil
}

// Save stores token for later loads.
func (m *memoryStore) Save(_ context.Context, token secret.Value) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = token
	return nil
}
