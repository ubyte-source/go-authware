package cred

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultGCPMetadataHost = "http://metadata.google.internal"
	gcpMetadataFlavor      = "Google"
	gcpDefaultScope        = "https://www.googleapis.com/auth/cloud-platform"

	gcpTokenPath    = "/computeMetadata/v1/instance/service-accounts/default/token"
	gcpIdentityPath = "/computeMetadata/v1/instance/service-accounts/default/identity"
)

// GCPMetadata requests credentials from the Google Compute Engine
// metadata server. Audience set selects ID-token mode (signed JWT for
// peer-to-peer Cloud Run / Functions); empty selects access-token mode.
type GCPMetadata struct {
	Client   *http.Client
	Audience string
	Endpoint string
	Scopes   []string
}

// Token fetches a token from the metadata server.
func (g *GCPMetadata) Token(ctx context.Context) (*Token, error) {
	host := g.Endpoint
	if host == "" {
		host = defaultGCPMetadataHost
	}
	host = strings.TrimRight(host, "/")
	if g.Audience != "" {
		return g.fetchIdentityToken(ctx, host)
	}
	return g.fetchAccessToken(ctx, host)
}

func (g *GCPMetadata) fetchIdentityToken(ctx context.Context, host string) (*Token, error) {
	q := url.Values{
		"audience": {g.Audience},
		"format":   {"full"},
	}
	body, err := g.metadataGet(ctx, host+gcpIdentityPath+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	jwt := strings.TrimSpace(string(body))
	if jwt == "" {
		return nil, fmt.Errorf("%w: empty identity token", ErrInvalidTokenResponse)
	}
	return &Token{Value: jwt, Type: "Bearer"}, nil
}

func (g *GCPMetadata) fetchAccessToken(ctx context.Context, host string) (*Token, error) {
	scopes := g.Scopes
	if len(scopes) == 0 {
		scopes = []string{gcpDefaultScope}
	}
	q := url.Values{"scopes": {strings.Join(scopes, ",")}}
	body, err := g.metadataGet(ctx, host+gcpTokenPath+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	resp := parseTokenResponse(body)
	if resp.AccessToken == "" {
		return nil, fmt.Errorf("%w: missing access_token", ErrInvalidTokenResponse)
	}
	return tokenFromResponse(resp), nil
}

func (g *GCPMetadata) metadataGet(ctx context.Context, fullURL string) (body []byte, err error) {
	client := g.Client
	if client == nil {
		client = sharedHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", gcpMetadataFlavor)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { err = closeBody(resp.Body, err) }()

	body, err = io.ReadAll(io.LimitReader(resp.Body, maxTokenBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &OAuth2Error{
			Status:      resp.StatusCode,
			Code:        "metadata_error",
			Description: strings.TrimSpace(string(body[:min(len(body), 256)])),
		}
	}
	return body, nil
}
