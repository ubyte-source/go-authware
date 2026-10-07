package cred

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
)

// metadataSource is a TokenSource backed by a cloud metadata service, reached
// with a fixed header and answering in the format that parse reads.
type metadataSource struct {
	client  *http.Client
	parse   func(body string) (*Token, error)
	service string
	target  *url.URL
	header  string
	value   string
}

// Token fetches the target and parses a 2xx answer; any other status becomes
// an *OAuth2Error. Every error names the service.
func (m *metadataSource) Token(ctx context.Context) (*Token, error) {
	tok, err := m.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf(errPrefix+"%s: %w", m.service, err)
	}
	return tok, nil
}

// fetch GETs the target with the header of the service and parses a 2xx
// answer.
func (m *metadataSource) fetch(ctx context.Context) (*Token, error) {
	req := oauthwire.NewGetRequest(ctx, m.target)
	req.Header.Set(m.header, m.value)
	body, err := oauthwire.Fetch(m.client, req, oauthwire.MaxTokenBody, ErrInvalidTokenResponse, newOAuth2Error)
	if err != nil {
		return nil, err
	}
	return m.parse(body)
}

// Hosts of the Azure instance metadata service and the GCE metadata server.
const (
	azureIMDSHost   = "169.254.169.254"
	gcpMetadataHost = "metadata.google.internal"
)

// checkMetadataURL parses raw when the outbound URL policy accepts it, or when
// it is plain http to a link-local address or the GCE metadata name, where
// cloud metadata services listen; else it fails with ErrInsecureTokenURL.
func checkMetadataURL(raw string) (url.URL, error) {
	u, err := netguard.Check(raw, ErrInsecureTokenURL)
	if err == nil {
		return *u, nil
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.Scheme != netguard.SchemeHTTP || u.User != nil || !isMetadataHost(u.Hostname()) {
		return url.URL{}, err
	}
	return *u, nil
}

// metadataURL returns raw, the URL of a metadata service, and its query, and
// records in p why checkMetadataURL refuses raw or url.ParseQuery its query.
func metadataURL(p *problems.List, raw string) (url.URL, url.Values) {
	u, err := checkMetadataURL(raw)
	p.Add(err)
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		p.Wrap("metadata URL query", err)
	}
	return u, q
}

// isMetadataHost accepts the GCE metadata name and link-local unicast addresses.
func isMetadataHost(host string) bool {
	if strings.EqualFold(host, gcpMetadataHost) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLinkLocalUnicast()
}

// The refusals of an expiry member that holds no positive Unix seconds.
var (
	errExpNotPositive       = notPositiveSeconds(claimExp)
	errExpiresOnNotPositive = notPositiveSeconds(msiExpiresOn)
)

// epochMember returns a walker of the members of a metadata answer, or of the
// claims of an ID token a metadata server issues, that parses the member name
// into dst with parseEpoch, refusing with notPositive, and skips the others.
func epochMember(name string, notPositive error, dst *time.Time) func(member, value string) error {
	return func(member, value string) error {
		if member != name {
			return nil
		}
		var err error
		*dst, err = parseEpoch(value, notPositive)
		return err
	}
}

// parseEpoch reads value, a member of a validated metadata answer or ID token,
// as positive Unix seconds, a JSON integer or a string holding one, capped at
// oauthwire.MaxLifetime from now; null yields the zero time, other text notPositive.
func parseEpoch(value string, notPositive error) (time.Time, error) {
	if jsonfast.KindOf(value) == jsonfast.KindNull {
		return time.Time{}, nil
	}
	n, ok := positiveSeconds(oauthwire.NumberText(value))
	if !ok {
		return time.Time{}, notPositive
	}
	if limit := time.Now().Add(oauthwire.MaxLifetime); n > limit.Unix() {
		return limit, nil
	}
	return time.Unix(n, 0), nil
}

// notPositiveSeconds refuses the member name holding no positive Unix seconds.
func notPositiveSeconds(name string) error {
	return fmt.Errorf("%w: %s is not a positive integer", ErrInvalidTokenResponse, name)
}

// positiveSeconds reads the JSON number text as a positive integer, one beyond
// int64 as math.MaxInt64, and reports false for any other number.
func positiveSeconds(text string) (int64, bool) {
	n, ok := jsonfast.DecodeInt64(text)
	switch {
	case ok && n > 0:
		return n, true
	case !ok && text != "" && strings.Trim(text, "0123456789") == "":
		return math.MaxInt64, true
	}
	return 0, false
}
