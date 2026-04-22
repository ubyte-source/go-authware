package authware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	errOIDCDiscoveryFailed = errors.New("OIDC discovery failed")
	errOIDCMissingJWKSURI  = errors.New("OIDC discovery: missing jwks_uri")
)

type oidcConfiguration struct {
	Issuer  string
	JWKSURI string
}

// discoverOIDC fetches {issuer}/.well-known/openid-configuration and
// returns the parsed jwks_uri and issuer.
func discoverOIDC(ctx context.Context, client *http.Client, issuer string) (_ *oidcConfiguration, err error) {
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	//nolint:gosec // G107: endpoint is derived from operator-configured issuer, never from request input
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if reqErr != nil {
		return nil, reqErr
	}
	resp, err := client.Do(req) //nolint:gosec // G704: operator-configured issuer URL, not user input
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", errOIDCDiscoveryFailed, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	jwksURI, ok := findStringField(body, "jwks_uri")
	if !ok || jwksURI == "" {
		return nil, errOIDCMissingJWKSURI
	}
	cfg := &oidcConfiguration{JWKSURI: jwksURI}
	if issuer, found := findStringField(body, "issuer"); found {
		cfg.Issuer = issuer
	}
	return cfg, nil
}
