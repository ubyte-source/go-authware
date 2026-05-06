package cred

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ubyte-source/go-jsonfast"
)

const (
	defaultAzureMSIEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
	azureMSIAPIVersion      = "2018-02-01"
	azureLoginHost          = "https://login.microsoftonline.com"
	azureSPNDefaultSuffix   = "/.default"
)

// AzureMSI requests a token from the Azure Instance Metadata Service
// for a VM running with a system- or user-assigned managed identity.
type AzureMSI struct {
	Client   *http.Client
	Resource string
	Endpoint string
}

// Token requests an access token from IMDS for the configured resource.
func (m *AzureMSI) Token(ctx context.Context) (*Token, error) {
	if m.Resource == "" {
		return nil, fmt.Errorf("%w: AzureMSI requires Resource", ErrInvalidTokenResponse)
	}
	endpoint := m.Endpoint
	if endpoint == "" {
		endpoint = defaultAzureMSIEndpoint
	}
	q := url.Values{
		"api-version": {azureMSIAPIVersion},
		"resource":    {m.Resource},
	}
	full := endpoint + "?" + q.Encode()

	client := m.Client
	if client == nil {
		client = sharedHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseOAuth2Error(resp.StatusCode, body)
	}
	return parseAzureMSIResponse(body)
}

// parseAzureMSIResponse parses the IMDS JSON document. expires_on is a
// Unix-epoch timestamp encoded as a string; expires_in (seconds) is
// the fallback when expires_on is absent.
func parseAzureMSIResponse(body []byte) (*Token, error) {
	var (
		access    string
		typ       string
		expiresOn int64
		expiresIn int64
	)
	jsonfast.IterateFields(body, func(key, value []byte) bool {
		switch unquoteKey(key) {
		case "access_token":
			access, _ = jsonfast.DecodeString(value)
		case "token_type":
			typ, _ = jsonfast.DecodeString(value)
		case "expires_on":
			expiresOn = parseInt64Quoted(value)
		case "expires_in":
			expiresIn = parseInt64Quoted(value)
		}
		return true
	})
	if access == "" {
		return nil, fmt.Errorf("%w: missing access_token", ErrInvalidTokenResponse)
	}
	tok := &Token{Value: access, Type: typ}
	switch {
	case expiresOn > 0:
		tok.Expires = time.Unix(expiresOn, 0)
	case expiresIn > 0:
		tok.Expires = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	return tok, nil
}

// AzureSPN authenticates a confidential service principal against
// Azure AD using the OAuth2 client_credentials grant on the v2.0
// endpoint.
type AzureSPN struct {
	Client       *http.Client
	LoginHost    string
	TenantID     string
	ClientID     string
	ClientSecret string
	// Scope is the requested scope. Empty + Resource set selects the
	// resource-qualified default scope "<resource>/.default".
	Scope    string
	Resource string
}

// Token requests an access token from the Azure AD v2.0 token endpoint.
func (s *AzureSPN) Token(ctx context.Context) (*Token, error) {
	if s.TenantID == "" {
		return nil, fmt.Errorf("%w: AzureSPN requires TenantID", ErrInvalidTokenResponse)
	}
	if s.ClientID == "" {
		return nil, fmt.Errorf("%w: AzureSPN requires ClientID", ErrInvalidTokenResponse)
	}
	scope := s.Scope
	if scope == "" {
		if s.Resource == "" {
			return nil, fmt.Errorf("%w: AzureSPN requires Scope or Resource", ErrInvalidTokenResponse)
		}
		scope = strings.TrimRight(s.Resource, "/") + azureSPNDefaultSuffix
	}
	host := s.LoginHost
	if host == "" {
		host = azureLoginHost
	}
	endpoint := strings.TrimRight(host, "/") + "/" + s.TenantID + "/oauth2/v2.0/token"
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.ClientID},
		"client_secret": {s.ClientSecret},
		"scope":         {scope},
	}
	resp, err := postFormToken(ctx, s.Client, endpoint, form, "", "")
	if err != nil {
		return nil, err
	}
	return tokenFromResponse(resp), nil
}

// parseInt64Quoted parses an integer encoded as either a JSON string
// ("1234") or a JSON number (1234). Returns 0 on failure.
func parseInt64Quoted(raw []byte) int64 {
	if len(raw) == 0 {
		return 0
	}
	if raw[0] == '"' {
		s, ok := jsonfast.DecodeString(raw)
		if !ok {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0
		}
		return n
	}
	n, _ := jsonfast.DecodeInt64(raw)
	return n
}
