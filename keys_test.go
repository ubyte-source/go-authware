package authware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// newTestKeySource fetches jwksURL, or discovers it from issuerURL, with the
// default cache TTL.
func newTestKeySource(issuerURL, jwksURL string) *keySource {
	cfg := &Config{OAuth: OAuthConfig{
		Issuer: issuerURL, JWKSURL: jwksURL, KeysCacheTTL: defaultKeysCacheTTL, FetchTimeout: time.Second,
	}}
	return newKeySource(&cfg.OAuth, newIssuer(cfg))
}

func TestNewKeySource(t *testing.T) {
	cfg := &Config{OAuth: OAuthConfig{JWKSURL: testJWKSURL, KeysCacheTTL: time.Hour, FetchTimeout: time.Second}}
	iss := &issuer{}
	s := newKeySource(&cfg.OAuth, iss)
	if s.idp != iss || s.jwksURL != testJWKSURL || s.sets.ttl != time.Hour || s.sets.timeout != time.Second ||
		s.sets.fetch == nil {
		t.Fatalf("newKeySource = %+v, want the issuer, the JWKS URL and a 1h key cache fetching through s", s)
	}
}

func TestNewKeySourceLogsFailures(t *testing.T) {
	srv := newJWKSServer(t, nil)
	srv.set(http.StatusInternalServerError, nil)
	var logs logCapture
	cfg := withDefaults(&Config{ErrorLog: slog.New(&logs), OAuth: OAuthConfig{
		Issuer: testIssuerURL, JWKSURL: srv.URL + testJWKSPath,
	}})
	s := newKeySource(&cfg.OAuth, newIssuer(cfg))
	if _, err := s.get(t.Context(), time.Unix(testUnix, 0)); !errors.Is(err, ErrKeysUnavailable) ||
		!logs.warned("authware: key fetch failed", statusError(http.StatusInternalServerError)) {
		t.Fatalf("get = %v with %+v logged, want ErrKeysUnavailable and the 500 warned once", err, logs.logged())
	}
}

// TestKeySourceFetchLogsOnce fails the discovery of the issuer and then the
// download of a discovered JWKS: each failure is logged once, by its fetch.
func TestKeySourceFetchLogsOnce(t *testing.T) {
	for _, tc := range []struct {
		name, msg string
		docs      map[string]func(string) string
		want      error
	}{
		{"failed discovery", "authware: metadata fetch failed", nil, errDiscovery},
		{"no jwks_uri", "authware: key fetch failed",
			openIDDoc(func(b string) string { return `{"issuer":"` + b + `"}` }), errMetadata},
		{"failed download", "authware: key fetch failed", openIDDoc(func(b string) string { return metadataDoc(b, b) }),
			statusError(http.StatusNotFound)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newMetadataServer(t, tc.docs)
			var logs logCapture
			cfg := withDefaults(&Config{ErrorLog: slog.New(&logs), OAuth: OAuthConfig{Issuer: srv.URL}})
			s := newKeySource(&cfg.OAuth, newIssuer(cfg))
			_, err := s.get(marked(t), time.Unix(testUnix, 0))
			if got := logs.logged(); !errors.Is(err, ErrKeysUnavailable) || !logs.warned(tc.msg, tc.want) ||
				!got[0].inMarked {
				t.Fatalf("get = %v with %+v logged, want ErrKeysUnavailable and one %q record in the caller's "+
					"context", err, got, tc.msg)
			}
		})
	}
}

func TestKeySourceAccepts(t *testing.T) {
	var s keySource
	for _, name := range []string{algRS256, algPS512, algES384, algEdDSA, algHS256, algHS512} {
		if got, want := s.accepts(mustAlgorithm(t, name)), name[0] != 'H'; got != want {
			t.Errorf("accepts(%s) = %v, want %v", name, got, want)
		}
	}
}

// keyStep is one call of key at the offset from testUnix for kid, with the
// error and total server requests expected.
type keyStep struct {
	at     time.Duration
	kid    string
	want   error
	served int32
}

func runKeyStepsRS256(t *testing.T, s *keySource, srv *jwksServer, steps []keyStep) {
	t.Helper()
	for i, st := range steps {
		key, err := s.key(t.Context(), st.kid, mustAlgorithm(t, algRS256), time.Unix(testUnix, 0).Add(st.at))
		if !errors.Is(err, st.want) || (err == nil) == (key == nil) || srv.hits.Load() != st.served {
			t.Fatalf("step %d: key(%s at +%v) = %v, %v after %d requests; want %v after %d",
				i, st.kid, st.at, key, err, srv.hits.Load(), st.want, st.served)
		}
	}
}

// TestKeySourceKey asks for a kid the key set lacks: the set is refetched
// once per retry.After, until a rotation publishes the kid.
func TestKeySourceKey(t *testing.T) {
	srv := newJWKSServer(t, jwksDocument(t, publicJWK(t, testRSAKey(), map[string]any{memberKid: "a"})))
	s := newTestKeySource("", srv.URL)
	runKeyStepsRS256(t, s, srv, []keyStep{
		{at: 0, kid: "a", served: 1},
		{at: time.Second, kid: "b", want: errNoKey, served: 2},
		{at: 2 * time.Second, kid: "b", want: errNoKey, served: 2},
		{at: 31*time.Second - time.Nanosecond, kid: "b", want: errNoKey, served: 2},
	})
	srv.set(http.StatusOK, jwksDocument(t, publicJWK(t, testRSAKey2(), map[string]any{memberKid: "b"})))
	runKeyStepsRS256(t, s, srv, []keyStep{
		{at: 31 * time.Second, kid: "b", served: 3},
		{at: 32 * time.Second, kid: "b", served: 3},
	})
}

// TestKeySourceKeyRefetchFails fails the forced refetch: the keys are
// unavailable, and the answer carries the unknown kid and the failure; while
// the failure backs off, an unknown kid finds the keys unavailable again.
func TestKeySourceKeyRefetchFails(t *testing.T) {
	srv := newJWKSServer(t, jwksDocument(t, publicJWK(t, testRSAKey(), map[string]any{memberKid: "a"})))
	s := newTestKeySource("", srv.URL)
	runKeyStepsRS256(t, s, srv, []keyStep{{at: 0, kid: "a", served: 1}})
	srv.set(http.StatusServiceUnavailable, nil)
	key, err := s.key(t.Context(), "b", mustAlgorithm(t, algRS256), time.Unix(testUnix, 0))
	if !errors.Is(err, ErrKeysUnavailable) || !errors.Is(err, errNoKey) ||
		!errorMatches(err, statusError(http.StatusServiceUnavailable)) || key != nil || srv.hits.Load() != 2 {
		t.Fatalf("key(b) = %v, %v after %d requests, want ErrKeysUnavailable of errNoKey and the 503 after 2", key,
			err, srv.hits.Load())
	}
	runKeyStepsRS256(t, s, srv, []keyStep{
		{at: time.Second, kid: "a", served: 2},
		{at: fetchPause - time.Nanosecond, kid: "b", want: errRetryBackoff, served: 2},
	})
	srv.set(http.StatusOK, jwksDocument(t, publicJWK(t, testRSAKey2(), map[string]any{memberKid: "b"})))
	runKeyStepsRS256(t, s, srv, []keyStep{{at: fetchPause, kid: "b", served: 3}})
}

// TestKeySourceKeyJoinsRefetch rotates the keys while tokens of the new kid
// arrive together: the one refetch they force serves them all.
func TestKeySourceKeyJoinsRefetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := jwksDocument(t, publicJWK(t, testRSAKey(), map[string]any{memberKid: "a"}))
		rotated := jwksDocument(t, publicJWK(t, testRSAKey(), map[string]any{memberKid: "a"}),
			publicJWK(t, testRSAKey2(), map[string]any{memberKid: "b"}))
		release := make(chan struct{})
		var fetches atomic.Int32
		cfg := &Config{
			HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := old
				if fetches.Add(1) > 1 {
					<-release
					body = rotated
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Request: r},
					nil
			})},
			OAuth: OAuthConfig{JWKSURL: testJWKSURL, KeysCacheTTL: defaultKeysCacheTTL, FetchTimeout: time.Second},
		}
		s := newKeySource(&cfg.OAuth, newIssuer(cfg))
		now, alg := time.Unix(testUnix, 0), mustAlgorithm(t, algRS256)
		if _, err := s.key(t.Context(), "a", alg, now); err != nil {
			t.Fatalf("key(a) = %v, want the key", err)
		}
		errs := make(chan error, 8)
		for range 8 {
			go func() {
				_, err := s.key(t.Context(), "b", alg, now.Add(time.Second))
				errs <- err
			}()
		}
		synctest.Wait()
		close(release)
		for range 8 {
			if err := <-errs; err != nil {
				t.Errorf("key(b) during the rotation = %v, want the key of the refetch", err)
			}
		}
		if n := fetches.Load(); n != 2 {
			t.Fatalf("JWKS fetches = %d, want 2: the first and the one forced refetch", n)
		}
	})
}

// unknownKid names no key of the test key sets.
const unknownKid = "z"

// TestKeySourceGetBackingOff refuses, while a failed fetch backs off, with the
// refusal built once.
func TestKeySourceGetBackingOff(t *testing.T) {
	srv := newJWKSServer(t, nil)
	srv.set(http.StatusServiceUnavailable, nil)
	s := newTestKeySource("", srv.URL)
	now := time.Unix(testUnix, 0)
	if _, err := s.get(t.Context(), now); !errorMatches(err, statusError(http.StatusServiceUnavailable)) {
		t.Fatalf("get = %v, want the 503", err)
	}
	if e := s.waiting; !errors.Is(e, ErrKeysUnavailable) || !errors.Is(e, errRetryBackoff) ||
		e.status != http.StatusServiceUnavailable {
		t.Fatalf("waiting = %+v, want a 503 ErrKeysUnavailable caused by errRetryBackoff", e)
	}
	assertAllocs(t, 0, func() {
		if _, err := s.get(t.Context(), now.Add(time.Second)); !errors.Is(err, errRetryBackoff) {
			t.Fatalf("get while backing off = %v, want the refusal of errRetryBackoff", err)
		}
	})
}

// TestKeySourceKeyRefetchBackingOff refuses a missing kid, while the refetch it
// forced backs off, with the refusal built once.
func TestKeySourceKeyRefetchBackingOff(t *testing.T) {
	srv := newJWKSServer(t, jwksDocument(t, publicJWK(t, testRSAKey(), nil)))
	s := newTestKeySource("", srv.URL)
	now, alg := time.Unix(testUnix, 0), mustAlgorithm(t, algRS256)
	if _, err := s.get(t.Context(), now); err != nil {
		t.Fatalf("get = %v, want the key set", err)
	}
	srv.set(http.StatusServiceUnavailable, nil)
	_, err := s.key(t.Context(), unknownKid, alg, now)
	if !errorMatches(err, statusError(http.StatusServiceUnavailable)) {
		t.Fatalf("key(%s) = %v, want the failed refetch", unknownKid, err)
	}
	if e := s.refetchWaiting; !errors.Is(e, errNoKey) || !errors.Is(e, errRetryBackoff) ||
		e.status != http.StatusServiceUnavailable {
		t.Fatalf("refetchWaiting = %+v, want a 503 caused by errNoKey and errRetryBackoff", e)
	}
	assertAllocs(t, 0, func() {
		_, err := s.key(t.Context(), unknownKid, alg, now.Add(time.Second))
		if !errors.Is(err, errRetryBackoff) || !errors.Is(err, errNoKey) {
			t.Fatalf("key(%s) while the refetch backs off = %v, want the refusal of errNoKey and errRetryBackoff",
				unknownKid, err)
		}
	})
}

func TestKeySourceKeyUnavailable(t *testing.T) {
	srv := newJWKSServer(t, nil)
	srv.set(http.StatusServiceUnavailable, nil)
	key, err := newTestKeySource("", srv.URL).key(t.Context(), "", mustAlgorithm(t, algRS256), time.Unix(testUnix, 0))
	if !errors.Is(err, ErrKeysUnavailable) || !errorMatches(err, statusError(http.StatusServiceUnavailable)) ||
		key != nil {
		t.Fatalf("key = %v, %v, want ErrKeysUnavailable caused by the 503", key, err)
	}
}

func TestKeySourceGet(t *testing.T) {
	good := jwksDocument(t, publicJWK(t, testRSAKey(), nil))
	tests := []struct {
		name   string
		status int
		body   []byte
		want   error
	}{
		{"status", http.StatusInternalServerError, good, statusError(http.StatusInternalServerError)},
		{"status 3xx", http.StatusFound, good, statusError(http.StatusFound)},
		{"document", http.StatusOK, []byte(`{"keys":[{"kty":"oct"}]}`), errInvalidJWKS},
		{"latin1", http.StatusOK, []byte(`{"keys":[],"x":"caf\xe9"}`), errInvalidJWKS},
		{"size", http.StatusOK, make([]byte, 1<<20+1), errBodyTooLarge},
	}
	for _, tc := range tests {
		srv := newJWKSServer(t, nil)
		srv.set(tc.status, tc.body)
		set, err := newTestKeySource("", srv.URL).get(t.Context(), time.Unix(testUnix, 0))
		var ae *authError
		if !errorMatches(err, tc.want) || !errors.As(err, &ae) || ae.status != http.StatusServiceUnavailable ||
			set != nil {
			t.Errorf("%s: get = %v, %v, want a 503 ErrKeysUnavailable caused by %v", tc.name, set, err, tc.want)
		}
	}
	srv := newJWKSServer(t, good)
	set, err := newTestKeySource("", srv.URL).get(t.Context(), time.Unix(testUnix, 0))
	if err != nil || len(set.keys) != 1 {
		t.Fatalf("get = %+v, %v, want the one key", set, err)
	}
}

// fetchFailure runs s.fetch at now and returns its error, failing t when the
// set returned beside it is not nil.
func fetchFailure(t *testing.T, s *keySource, now time.Time) error {
	t.Helper()
	set, err := s.fetch(t.Context(), now)
	if set != nil {
		t.Fatalf("fetch = %+v, %v, want a nil set", set, err)
	}
	return err
}

func TestKeySourceFetch(t *testing.T) {
	jwks := jwksDocument(t, publicJWK(t, testRSAKey(), nil))
	now := time.Unix(testUnix, 0)
	srv := newMetadataServer(t, map[string]func(string) string{
		testOpenIDConfiguration: func(b string) string { return metadataDoc(b, b) },
		testJWKSPath:            func(string) string { return string(jwks) },
	})
	if set, err := newTestKeySource(srv.URL, "").fetch(t.Context(), now); err != nil || len(set.keys) != 1 {
		t.Fatalf("fetch = %+v, %v, want the one key", set, err)
	}
	elsewhere := newJWKSServer(t, jwks)
	offOrigin := newMetadataServer(t, map[string]func(string) string{
		testOpenIDConfiguration: func(b string) string {
			return strings.Replace(metadataDoc(b, b), `"`+b+`/jwks"`, `"`+elsewhere.URL+`"`, 1)
		},
	})
	err := fetchFailure(t, newTestKeySource(offOrigin.URL, ""), now)
	if !errors.Is(err, errCrossOrigin) || elsewhere.hits.Load() != 0 {
		t.Fatalf("fetch(off-origin jwks_uri) = %v after %d requests, want errCrossOrigin before any", err,
			elsewhere.hits.Load())
	}
	noJWKS := newMetadataServer(t, map[string]func(string) string{
		testOpenIDConfiguration: func(b string) string { return `{"issuer":"` + b + `"}` },
	})
	err = fetchFailure(t, newTestKeySource(noJWKS.URL, ""), now)
	if !errors.Is(err, errNoJWKSURI) || !errors.Is(err, errMetadata) {
		t.Fatalf("fetch(no jwks_uri) = %v, want errNoJWKSURI, which wraps errDiscovery and errMetadata", err)
	}
	err = fetchFailure(t, newTestKeySource(noJWKS.URL+"/other", ""), now)
	if !errorMatches(err, statusError(http.StatusNotFound)) || !errors.Is(err, errDiscovery) {
		t.Fatalf("fetch(no metadata) = %v, want errDiscovery caused by the 404", err)
	}
	err = fetchFailure(t, newTestKeySource("", noJWKS.URL+testJWKSPath), now)
	if !errorMatches(err, statusError(http.StatusNotFound)) {
		t.Fatalf("fetch(no JWKS) = %v, want the 404", err)
	}
}

// TestKeySourceFetchCachesMetadata refetches the keys after the TTL: the
// metadata is discovered again only once its own TTL passes.
func TestKeySourceFetchCachesMetadata(t *testing.T) {
	jwks := jwksDocument(t, publicJWK(t, testRSAKey(), nil))
	srv := newMetadataServer(t, map[string]func(string) string{
		testOpenIDConfiguration: func(b string) string { return metadataDoc(b, b) },
		testJWKSPath:            func(string) string { return string(jwks) },
	})
	s := newTestKeySource(srv.URL, "")
	now := time.Unix(testUnix, 0)
	for _, at := range []time.Duration{0, time.Second, defaultKeysCacheTTL} {
		if _, err := s.fetch(t.Context(), now.Add(at)); err != nil {
			t.Fatalf("fetch(+%v) = %v, want nil", at, err)
		}
	}
	want := []string{testOpenIDConfiguration, testJWKSPath, testJWKSPath, testOpenIDConfiguration, testJWKSPath}
	if !slices.Equal(srv.paths, want) {
		t.Fatalf("requests = %v, want %v", srv.paths, want)
	}
}

func TestKeySourceFetchSizeLimit(t *testing.T) {
	jwks := jwksDocument(t, publicJWK(t, testRSAKey(), nil))
	exact := newJWKSServer(t, slices.Concat(bytes.Repeat([]byte(" "), 1<<20-len(jwks)), jwks))
	set, err := newTestKeySource("", exact.URL).fetch(t.Context(), time.Unix(testUnix, 0))
	if err != nil || len(set.keys) != 1 {
		t.Fatalf("fetch(1 MiB JWKS) = %+v, %v, want the one key", set, err)
	}
}

// refetchedKeySource returns a source of the RS256 key "a" whose refetch,
// forced by the unknown kid "b" at now, has run, and its JWKS server.
func refetchedKeySource(b *testing.B, alg algorithm, now time.Time) (*keySource, *jwksServer) {
	b.Helper()
	srv := newJWKSServer(b, jwksDocument(b, publicJWK(b, testRSAKey(), map[string]any{memberKid: "a"})))
	s := newTestKeySource("", srv.URL)
	if _, err := s.key(b.Context(), "b", alg, now); !errors.Is(err, errNoKey) {
		b.Fatalf("key(b) = %v, want errNoKey", err)
	}
	return s, srv
}

// BenchmarkKeySourceKey resolves a known kid and, within retry.After of the
// forced refetch, an unknown one.
func BenchmarkKeySourceKey(b *testing.B) {
	now, alg := time.Unix(testUnix, 0), mustAlgorithm(b, algRS256)
	s, srv := refetchedKeySource(b, alg, now)
	for _, tc := range []struct {
		kid  string
		want error
	}{
		{"a", nil},
		{"b", errNoKey},
	} {
		b.Run(tc.kid, func(b *testing.B) {
			if _, err := s.key(b.Context(), tc.kid, alg, now); !errors.Is(err, tc.want) {
				b.Fatalf("key(%s) = %v, want %v", tc.kid, err, tc.want)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.key(b.Context(), tc.kid, alg, now); !errors.Is(err, tc.want) {
					b.Fatalf("key(%s) = %v, want %v", tc.kid, err, tc.want)
				}
			}
		})
	}
	if hits := srv.hits.Load(); hits != 2 {
		b.Fatalf("JWKS requests = %d, want 2", hits)
	}
}

// BenchmarkKeySourceKeyParallel resolves the unknown kid from every
// goroutine within retry.After of the forced refetch.
func BenchmarkKeySourceKeyParallel(b *testing.B) {
	now, alg := time.Unix(testUnix, 0), mustAlgorithm(b, algRS256)
	s, srv := refetchedKeySource(b, alg, now)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := s.key(context.Background(), "b", alg, now); !errors.Is(err, errNoKey) {
				b.Errorf("key(b) = %v, want errNoKey", err)
				return
			}
		}
	})
	if hits := srv.hits.Load(); hits != 2 {
		b.Fatalf("JWKS requests = %d, want 2", hits)
	}
}

func BenchmarkKeySourceGet(b *testing.B) {
	srv := newJWKSServer(b, jwksDocument(b, publicJWK(b, testRSAKey(), map[string]any{memberKid: "a"})))
	s := newTestKeySource("", srv.URL)
	now := time.Unix(testUnix, 0)
	if _, err := s.get(b.Context(), now); err != nil {
		b.Fatalf("get = %v, want the key set", err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := s.get(context.Background(), now); err != nil {
				b.Errorf("get = %v, want the key set", err)
				return
			}
		}
	})
	if hits := srv.hits.Load(); hits != 1 {
		b.Fatalf("JWKS requests = %d, want 1", hits)
	}
}
