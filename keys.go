package authware

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/retry"
)

const maxJWKSBytes = 1 << 20

// keyResolver finds the key that verifies a token.
type keyResolver interface {
	// accepts reports whether tokens signed with alg are verified at all.
	accepts(alg algorithm) bool
	key(ctx context.Context, kid string, alg algorithm, now time.Time) (verificationKey, error)
}

// keySource resolves the keys of jwksURL, or of the issuer's jwks_uri, from a
// cached set; forced paces the refetches a missing kid forces. While a failed
// fetch backs off, waiting refuses a lookup and refetchWaiting a missing kid.
type keySource struct {
	idp *issuer

	waiting        *authError
	refetchWaiting *authError

	jwksURL string

	sets   cache[*jwkSet]
	forced retry.Backoff
}

// newKeySource returns the key source of oc, reaching iss, whose log receives
// the failed key fetches.
func newKeySource(oc *OAuthConfig, iss *issuer) *keySource {
	s := &keySource{
		idp:            iss,
		waiting:        failure(ErrKeysUnavailable, "", errRetryBackoff),
		refetchWaiting: failure(ErrKeysUnavailable, "", refetchFailure(errNoKey, errRetryBackoff)),
		jwksURL:        oc.JWKSURL,
		sets:           cache[*jwkSet]{ttl: oc.KeysCacheTTL, timeout: oc.FetchTimeout},
	}
	s.sets.fetch = s.fetch
	return s
}

// accepts reports whether alg verifies with JWKS keys: every algorithm but HMAC.
func (*keySource) accepts(alg algorithm) bool { return alg.kind != kindOct }

// key returns the key kid and alg select at now. A missing kid is matched in
// the set of the refetch in flight, or of one forced once per retry.After, else
// in the cached set; a failed refetch or backoff leaves the keys unavailable.
func (s *keySource) key(ctx context.Context, kid string, alg algorithm, now time.Time) (verificationKey, error) {
	set, err := s.get(ctx, now)
	if err != nil {
		return nil, err
	}
	key, err := set.match(kid, alg)
	if !errors.Is(err, errNoKey) {
		return key, err
	}
	fresh, refetchErr := s.sets.force(ctx, now, &s.forced)
	switch {
	case errors.Is(errRetryBackoff, refetchErr):
		return nil, s.refetchWaiting
	case refetchErr != nil:
		return nil, failure(ErrKeysUnavailable, "", refetchFailure(err, refetchErr))
	}
	return fresh.match(kid, alg)
}

// refetchFailure joins missing, the failure to find a key, and refetchErr,
// the failure of the refetch it forced.
func refetchFailure(missing, refetchErr error) error {
	return fmt.Errorf("%w; refetching the keys: %w", missing, refetchErr)
}

// get returns the key set at now, or the failure that keys are unavailable.
func (s *keySource) get(ctx context.Context, now time.Time) (*jwkSet, error) {
	set, err := s.sets.get(ctx, now)
	switch {
	case errors.Is(errRetryBackoff, err):
		return nil, s.waiting
	case err != nil:
		return nil, failure(ErrKeysUnavailable, "", err)
	}
	return set, nil
}

// fetch downloads and parses the JWKS, taking its URL from the issuer
// metadata at now when none is configured. It logs its failure, unless the
// metadata lookup failed: the issuer logs that.
func (s *keySource) fetch(ctx context.Context, now time.Time) (*jwkSet, error) {
	jwksURL := s.jwksURL
	if jwksURL == "" {
		md, err := s.idp.metadata.get(ctx, now)
		if err != nil {
			return nil, err
		}
		jwksURL = md.jwksURI
	}
	set, err := s.download(ctx, jwksURL)
	if err != nil {
		s.idp.log.LogAttrs(ctx, slog.LevelWarn, errPrefix+"key fetch failed", slog.Any("error", err))
	}
	return set, err
}

// errNoJWKSURI refuses issuer metadata that names no JWKS.
var errNoJWKSURI = fmt.Errorf("%w: %w: no jwks_uri", errDiscovery, errMetadata)

// download fetches and parses the JWKS at raw, empty when the issuer metadata
// names none.
func (s *keySource) download(ctx context.Context, raw string) (*jwkSet, error) {
	if raw == "" {
		return nil, errNoJWKSURI
	}
	body, err := getDocument(ctx, s.idp.client, raw, maxJWKSBytes)
	if err != nil {
		return nil, err
	}
	return parseJWKS(body)
}
