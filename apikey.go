package authware

import (
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// APIKeyConfig configures ModeAPIKey.
type APIKeyConfig struct {
	// Key (AUTH_APIKEY) is the shared API key: a header value of at least 32
	// bytes.
	Key secret.Value
	// Header (AUTH_APIKEY_HEADER) carries the key; default X-Api-Key. Without
	// it, the key of an Authorization: ApiKey header is read.
	Header string
}

// inUse reports whether any API key setting is present.
func (a *APIKeyConfig) inUse() bool { return !a.Key.IsZero() || a.Header != "" }

// validate requires an API key long enough and sendable as a header value,
// and a valid header name.
func (a *APIKeyConfig) validate(p *problems.List) {
	if longEnough(p, "API key", a.Key) && !syntax.IsFieldValue(a.Key.Reveal()) {
		p.Addf("API key is not a header value")
	}
	if !syntax.IsToken(a.Header) {
		p.Addf("API key header %q is not a valid header name", a.Header)
	}
}
