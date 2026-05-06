package authware

import (
	"context"
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
	Issuer  string
	JWKSURI string
}

// discoverOIDC fetches {issuer}/.well-known/openid-configuration and
// returns the parsed jwks_uri and issuer. Both URLs must use https or
// be a loopback host.
func discoverOIDC(ctx context.Context, client *http.Client, issuer string) (cfg *oidcConfiguration, err error) {
	if schemeErr := requireHTTPS(issuer); schemeErr != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", schemeErr)
	}
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	//nolint:gosec // G704: endpoint built from issuer, HTTPS-gated by requireHTTPS above.
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if reqErr != nil {
		return nil, reqErr
	}

	//nolint:gosec // G704: request URL is operator-configured and HTTPS-gated.
	resp, err := client.Do(req)
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
	body, err := readAllLimited(resp.Body, 256<<10)
	if err != nil {
		return nil, err
	}
	return parseOIDCDocument(body)
}

func parseOIDCDocument(body []byte) (*oidcConfiguration, error) {
	jwksURI, ok := findStringField(body, "jwks_uri")
	if !ok || jwksURI == "" {
		return nil, errOIDCMissingJWKSURI
	}
	if err := requireHTTPS(jwksURI); err != nil {
		return nil, fmt.Errorf("OIDC discovery jwks_uri: %w", err)
	}
	cfg := &oidcConfiguration{JWKSURI: jwksURI}
	if iss, found := findStringField(body, "issuer"); found {
		cfg.Issuer = iss
	}
	return cfg, nil
}
