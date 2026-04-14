package authware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	errOIDCDiscoveryFailed = errors.New("OIDC discovery failed")
	errOIDCMissingJWKSURI  = errors.New("OIDC discovery: missing jwks_uri")
)

type oidcConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverOIDC fetches the OIDC discovery document from
// {issuer}/.well-known/openid-configuration and returns the parsed configuration.
func discoverOIDC(ctx context.Context, client *http.Client, issuer string) (_ *oidcConfiguration, err error) {
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	//nolint:gosec // G704: endpoint is derived from operator-configured issuer, never from request input
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if reqErr != nil {
		return nil, reqErr
	}
	resp, err := client.Do(req) //nolint:gosec // G704: URL is operator-configured (see NewRequestWithContext above)
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
	var cfg oidcConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.JWKSURI == "" {
		return nil, errOIDCMissingJWKSURI
	}
	return &cfg, nil
}
