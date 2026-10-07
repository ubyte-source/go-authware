package cred

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// errPrefix starts every log message the package writes and the text of every
// error it returns, but the errors of a caller's TokenSource, Signer or base
// transport, which pass through as they are.
const errPrefix = "cred: "

var (
	// ErrCredential wraps every error that stops AsSigner or NewTransport
	// from attaching a credential.
	ErrCredential = errors.New(errPrefix + "credential unavailable")
	// ErrInvalidConfig reports a constructor argument that cannot work.
	ErrInvalidConfig = errors.New(errPrefix + "invalid config")

	// ErrNoToken reports a TokenSource that returned neither a token nor an
	// error.
	ErrNoToken = errors.New(errPrefix + "source returned no token")
	// ErrInvalidTokenResponse reports a success answer of a token endpoint or a
	// metadata service over 1 MiB, not a strict JSON object or without a valid
	// token, or a token already expired when it arrives.
	ErrInvalidTokenResponse = errors.New("invalid token response")
	// ErrInsecureTokenURL reports a token or metadata URL that the outbound
	// policy refuses, or that carries userinfo; it wraps ErrInvalidConfig.
	ErrInsecureTokenURL = fmt.Errorf("%w: insecure token URL", ErrInvalidConfig)
	// ErrBodyTooLarge reports a request body over 1 MiB that a NewSigV4 signer
	// would hash; UnsignedPayload, for the S3 services, signs it unhashed.
	ErrBodyTooLarge = errors.New("body too large")
	// ErrMissingHost reports a request without a host to sign.
	ErrMissingHost = errors.New(errPrefix + "request has no host")

	// ErrInvalidKeyPair reports a certificate and key that cannot be loaded as a
	// pair; it wraps ErrInvalidConfig.
	ErrInvalidKeyPair = fmt.Errorf("%w: invalid key pair", ErrInvalidConfig)
	// ErrEmptyCAFile reports a CA file without any PEM certificate; it wraps
	// ErrInvalidConfig.
	ErrEmptyCAFile = fmt.Errorf("%w: CA file holds no certificate", ErrInvalidConfig)

	// ErrNoRefreshToken reports a store that holds no refresh token.
	ErrNoRefreshToken = errors.New(errPrefix + "no refresh token")
	// ErrRotationNotSaved reports an exchange whose rotated refresh token the
	// store failed to save; the token stays in memory and the next exchange
	// saves it again.
	ErrRotationNotSaved = errors.New(errPrefix + "rotated refresh token not saved")

	errNilConfig = fmt.Errorf("%w: nil config", ErrInvalidConfig)
	errNilToken  = fmt.Errorf("%w: nil token", ErrInvalidConfig)
)

// headerAuthorization is the request header a Token sets by default.
const headerAuthorization = "Authorization"

// paramAudience names the audience a client_credentials grant or a GCE
// identity token asks for.
const paramAudience = "audience"

// Token is an outbound HTTP credential.
type Token struct {
	// Value is the credential itself.
	Value secret.Value
	// Type is the authentication scheme; empty means Bearer unless Bare is set.
	Type string
	// Header is the request header to set; empty means Authorization.
	Header string
	// Expires is the end of the token lifetime; zero means no expiry.
	Expires time.Time

	// rendered and canonicalHeader are the header value and name of owner, built
	// once for a token that the package shares; Apply uses them on owner alone,
	// so a copy builds its own.
	rendered        secret.Value
	canonicalHeader string
	owner           *Token

	// Bare sends Value alone, with no scheme; Type must then be empty.
	Bare bool
}

// Apply sets the token header on r, creating r.Header when it is nil.
func (t *Token) Apply(r *http.Request) {
	if r.Header == nil {
		r.Header = http.Header{}
	}
	if t.owner == t {
		r.Header[t.canonicalHeader] = []string{t.rendered.Reveal()}
		return
	}
	r.Header.Set(cmp.Or(t.Header, headerAuthorization), t.render())
}

// Sign applies t to r, so a fixed token is a Signer.
func (t *Token) Sign(_ context.Context, r *http.Request) error {
	t.Apply(r)
	return nil
}

// Validate reports, joined and wrapping ErrInvalidConfig, a nil token, a Header or
// Type that is set but not a token, a Type on a Bare token and a Value that is not
// a clean header value.
func (t *Token) Validate() error {
	if t == nil {
		return errNilToken
	}
	return t.check(ErrInvalidConfig)
}

// LogValue renders the type and expiry only.
func (t *Token) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", t.Type), slog.Time("expires", t.Expires))
}

// check is Validate with every problem wrapping invalid.
func (t *Token) check(invalid error) error {
	p := problems.New(invalid)
	if t.Header != "" && !syntax.IsToken(t.Header) {
		p.Addf("token header %q is not a valid header name", t.Header)
	}
	if t.Type != "" && t.Bare {
		p.Addf("token type %q is set on a bare token", t.Type)
	}
	if t.Type != "" && !syntax.IsToken(t.Type) {
		p.Addf("token type %q is not a valid scheme", t.Type)
	}
	if !syntax.IsFieldValue(t.Value.Reveal()) {
		p.Addf("token value is empty or not a valid header value")
	}
	return p.Err()
}

// render returns the credential of a Bare token, and otherwise the scheme and
// the credential joined by a space.
func (t *Token) render() string {
	if t.Bare {
		return t.Value.Reveal()
	}
	return cmp.Or(t.Type, defaultTokenType) + " " + t.Value.Reveal()
}

// shared returns a copy of t that owns its header value and canonical header
// name, built once.
func (t *Token) shared() *Token {
	c := *t
	c.rendered, c.owner = secret.New(c.render()), &c
	c.canonicalHeader = textproto.CanonicalMIMEHeaderKey(cmp.Or(c.Header, headerAuthorization))
	return &c
}

// TokenSource produces tokens. Implementations must be safe for concurrent use,
// and a caller must not modify a Token it receives, which may be shared.
type TokenSource interface {
	// Token returns a token, or the error that kept it from producing one.
	Token(ctx context.Context) (*Token, error)
}

// TokenSourceFunc adapts a function to TokenSource.
type TokenSourceFunc func(ctx context.Context) (*Token, error)

// Token calls f.
func (f TokenSourceFunc) Token(ctx context.Context) (*Token, error) { return f(ctx) }

// Signer attaches a credential to a request in place; the Signers of this
// module create r.Header when it is nil. Implementations must be safe for
// concurrent use.
type Signer interface {
	// Sign attaches the credential to r, or returns the error that kept it from
	// doing so.
	Sign(ctx context.Context, r *http.Request) error
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(ctx context.Context, r *http.Request) error

// Sign calls f.
func (f SignerFunc) Sign(ctx context.Context, r *http.Request) error { return f(ctx, r) }

type tokenSigner struct {
	src TokenSource
}

// AsSigner returns a Signer that applies the tokens of src, which must not
// be nil.
func AsSigner(src TokenSource) Signer {
	return &tokenSigner{src: src}
}

// Sign applies a token of the source to r.
func (s *tokenSigner) Sign(ctx context.Context, r *http.Request) error {
	tok, err := fetchToken(ctx, s.src)
	if err != nil {
		return credentialError(err)
	}
	tok.Apply(r)
	return nil
}

// fetchToken asks src for a token and refuses a nil one.
func fetchToken(ctx context.Context, src TokenSource) (*Token, error) {
	tok, err := src.Token(ctx)
	switch {
	case err != nil:
		return nil, err
	case tok == nil:
		return nil, ErrNoToken
	}
	return tok, nil
}

func credentialError(err error) error {
	if errors.Is(err, ErrCredential) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrCredential, err)
}
