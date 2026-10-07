package authware

import (
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// BearerConfig configures ModeBearer.
type BearerConfig struct {
	// Token (AUTH_BEARER_TOKEN) is the shared bearer token: at least 32 bytes of
	// a header value without space or tab.
	Token secret.Value
}

// inUse reports whether the bearer token is set.
func (b *BearerConfig) inUse() bool { return !b.Token.IsZero() }

// validate requires a bearer token long enough and sendable after the scheme.
func (b *BearerConfig) validate(p *problems.List) {
	token := b.Token.Reveal()
	sendable := syntax.IsFieldValue(token) && !strings.ContainsAny(token, " \t")
	if longEnough(p, "bearer token", b.Token) && !sendable {
		p.Addf("bearer token is not a header value without space or tab")
	}
}
