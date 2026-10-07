package authware

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

// maxMetadataBytes bounds a discovery document.
const maxMetadataBytes = 256 << 10

// pathOpenIDConfiguration is the OpenID Connect discovery suffix.
const pathOpenIDConfiguration = "/.well-known/openid-configuration"

// Server metadata members that discovery reads and the facade publishes.
const (
	metaIssuer                = "issuer"
	metaAuthorizationEndpoint = "authorization_endpoint"
	metaTokenEndpoint         = "token_endpoint"
	metaJWKSURI               = "jwks_uri"
)

var (
	errDiscovery      = errors.New("discovery failed")
	errMetadata       = errors.New("invalid server metadata")
	errMetadataShape  = jsonobj.Refusal(errMetadata)
	errIssuerMismatch = errors.New("discovered issuer differs")
	errCrossOrigin    = errors.New("endpoint off the issuer origin")
)

// serverMetadata holds the issuer and the endpoints an authorization server
// publishes; each set endpoint shares the scheme, host and port of the issuer.
type serverMetadata struct {
	iss                   string
	jwksURI               string
	authorizationEndpoint string
	tokenEndpoint         string

	derived atomic.Pointer[derivedUpstream]
}

// issuer is the authorization server that tokens name: reached through one
// guarded client, its metadata discovered at most once per TTL, and every
// failure to reach it logged to log.
type issuer struct {
	client   *http.Client
	log      *slog.Logger
	metadata cache[*serverMetadata]

	url string
}

// newIssuer returns the issuer of cfg.OAuth, fetched through a guarded copy
// of cfg.HTTPClient, whose failures go to cfg.ErrorLog.
func newIssuer(cfg *Config) *issuer {
	oc := &cfg.OAuth
	i := &issuer{
		client:   netguard.Client(cfg.HTTPClient, oc.FetchTimeout),
		log:      cmp.Or(cfg.ErrorLog, slog.New(slog.DiscardHandler)),
		metadata: cache[*serverMetadata]{ttl: oc.KeysCacheTTL, timeout: oc.FetchTimeout},
		url:      oc.Issuer,
	}
	i.metadata.fetch = i.fetch
	return i
}

// fetch discovers the metadata of the issuer, logging its failure; the cache
// that calls it keeps the time.
func (i *issuer) fetch(ctx context.Context, _ time.Time) (*serverMetadata, error) {
	md, err := i.discover(ctx)
	if err != nil {
		i.log.LogAttrs(ctx, slog.LevelWarn, errPrefix+"metadata fetch failed", slog.Any("error", err))
	}
	return md, err
}

// discover fetches the metadata of the issuer, first as OpenID Connect
// discovery and then as OAuth authorization server metadata. The document
// issuer must equal the issuer URL exactly.
func (i *issuer) discover(ctx context.Context) (*serverMetadata, error) {
	base, err := netguard.Check(i.url, ErrInsecureURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errDiscovery, err)
	}
	origin := base.Scheme + "://" + base.Host
	path := strings.TrimSuffix(base.EscapedPath(), "/")
	var errs []error
	for _, endpoint := range []string{origin + path + pathOpenIDConfiguration, origin + pathServerMetadata + path} {
		md, err := fetchMetadata(ctx, i.client, endpoint, base)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if md.iss != i.url {
			errs = append(errs, fmt.Errorf("%w: %q", errIssuerMismatch, md.iss))
			continue
		}
		return md, nil
	}
	return nil, fmt.Errorf("%w: %w", errDiscovery, errors.Join(errs...))
}

// fetchMetadata fetches one metadata document whose endpoints share the
// origin of base.
func fetchMetadata(ctx context.Context, client *http.Client, endpoint string, base *url.URL) (
	*serverMetadata, error,
) {
	body, err := getDocument(ctx, client, endpoint, maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	var md serverMetadata
	if err := jsonobj.Iterate(body, errMetadataShape, md.set); err != nil {
		return nil, err
	}
	for _, e := range []string{md.jwksURI, md.authorizationEndpoint, md.tokenEndpoint} {
		if e == "" {
			continue
		}
		if err := sameOrigin(base, e); err != nil {
			return nil, err
		}
	}
	return &md, nil
}

// set records a copy of one metadata member, so the cached metadata does not
// keep the document.
func (md *serverMetadata) set(name, value string) error {
	var dst *string
	switch name {
	case metaIssuer:
		dst = &md.iss
	case metaJWKSURI:
		dst = &md.jwksURI
	case metaAuthorizationEndpoint:
		dst = &md.authorizationEndpoint
	case metaTokenEndpoint:
		dst = &md.tokenEndpoint
	default:
		return nil
	}
	return jsonobj.CopyString(dst, name, value, errMetadata)
}

// sameOrigin requires raw to pass the outbound URL policy and to share the
// scheme, host and effective port of base.
func sameOrigin(base *url.URL, raw string) error {
	u, err := netguard.Check(raw, ErrInsecureURL)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if !netguard.SameOrigin(u, base) {
		return fmt.Errorf("%w: %s", errCrossOrigin, u.Redacted())
	}
	return nil
}
