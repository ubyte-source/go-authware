package authware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ubyte-source/go-jsonfast"
)

var (
	errOIDCDiscoveryFailed = errors.New("OIDC discovery failed")
	errOIDCMissingJWKSURI  = errors.New("OIDC discovery: missing jwks_uri")
)

type oidcConfiguration struct {
	Issuer  string
	JWKSURI string
}

// discoverOIDC fetches the OIDC discovery document from
// {issuer}/.well-known/openid-configuration and returns the parsed configuration.
// Uses jsonfast.FindField instead of encoding/json for zero-reflection parsing.
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
	jwksRaw, ok := jsonfast.FindField(body, "jwks_uri")
	if !ok {
		return nil, errOIDCMissingJWKSURI
	}
	jwksURI := unquote(jwksRaw)
	if jwksURI == "" {
		return nil, errOIDCMissingJWKSURI
	}
	cfg := &oidcConfiguration{JWKSURI: jwksURI}
	if issuerRaw, found := jsonfast.FindField(body, "issuer"); found {
		cfg.Issuer = unquote(issuerRaw)
	}
	return cfg, nil
}
