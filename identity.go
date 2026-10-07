package authware

import (
	"context"
	"crypto/x509"
	"errors"
	"iter"
	"slices"

	"github.com/ubyte-source/go-jsonfast"
)

// Identity is an authenticated caller. It is immutable and safe to share. Its
// methods accept a nil Identity, which has no subject, mode, scope,
// certificate or claim.
type Identity struct {
	mode    Mode
	subject string
	scopes  []string
	claims  string
	peer    *x509.Certificate
}

// Subject returns the caller's subject, empty for a nil identity and when the
// mode has none.
func (id *Identity) Subject() string {
	if id == nil {
		return ""
	}
	return id.subject
}

// Mode returns the mode that authenticated the caller.
func (id *Identity) Mode() Mode {
	if id == nil {
		return ""
	}
	return id.mode
}

// Scopes returns a copy of the granted scopes.
func (id *Identity) Scopes() []string {
	if id == nil {
		return nil
	}
	return slices.Clone(id.scopes)
}

// HasScope reports whether scope was granted.
func (id *Identity) HasScope(scope string) bool {
	return id != nil && slices.Contains(id.scopes, scope)
}

// PeerCertificate returns the client certificate in ModeMTLS, else nil; the
// certificate is shared and must not be modified.
func (id *Identity) PeerCertificate() *x509.Certificate {
	if id == nil {
		return nil
	}
	return id.peer
}

// Claim returns the named token claim as a string, int64, float64, bool or
// nil, or as its JSON text when it decodes to none of those, as an object, an
// array or a number beyond float64 does.
func (id *Identity) Claim(name string) (value any, ok bool) {
	raw := id.rawClaim(name)
	if raw == "" {
		return nil, false
	}
	return decodeClaimValue(raw), true
}

// ClaimString returns the named claim when it is a JSON string.
func (id *Identity) ClaimString(name string) (value string, ok bool) {
	return jsonfast.DecodeString(id.rawClaim(name))
}

// ClaimInt64 returns the named claim when it is a JSON integer, with no fraction or
// exponent, within int64's range.
func (id *Identity) ClaimInt64(name string) (value int64, ok bool) {
	return jsonfast.DecodeInt64(id.rawClaim(name))
}

// ClaimFloat64 returns the named claim rounded to the nearest float64 when it is a
// JSON number and that float64 is finite.
func (id *Identity) ClaimFloat64(name string) (value float64, ok bool) {
	return jsonfast.DecodeFloat64(id.rawClaim(name))
}

// ClaimBool returns the named claim when it is a JSON boolean.
func (id *Identity) ClaimBool(name string) (value, ok bool) {
	return jsonfast.DecodeBool(id.rawClaim(name))
}

// errClaimsStopped ends the walk of Claims when its consumer stops.
var errClaimsStopped = errors.New("claims iteration stopped")

// Claims returns an iterator over the token claims, each value a string, int64,
// float64, bool or nil, else its JSON text; a nil Identity yields none.
func (id *Identity) Claims() iter.Seq2[string, any] {
	return func(yield func(name string, value any) bool) {
		if id == nil {
			return
		}
		visit := func(name, value string) error {
			if yield(name, decodeClaimValue(value)) {
				return nil
			}
			return errClaimsStopped
		}
		_ = jsonfast.IterateMembers(id.claims, visit) //nolint:errcheck // fails only if yield stops or no claims exist
	}
}

// rawClaim returns the JSON text of the named claim, a substring of
// id.claims, or "" when there is no such claim; member names are unique.
func (id *Identity) rawClaim(name string) string {
	if id == nil {
		return ""
	}
	raw, _ := jsonfast.FindMember(id.claims, name)
	return raw
}

// decodeClaimValue maps a value of validated claims to string, bool, nil,
// int64 or float64, else to its JSON text: objects, arrays and numbers beyond
// float64.
func decodeClaimValue(raw string) any {
	switch jsonfast.KindOf(raw) {
	case jsonfast.KindString:
		s, _ := jsonfast.DecodeString(raw)
		return s
	case jsonfast.KindBool:
		b, _ := jsonfast.DecodeBool(raw)
		return b
	case jsonfast.KindNull:
		return nil
	case jsonfast.KindNumber:
		if n, ok := jsonfast.DecodeInt64(raw); ok {
			return n
		}
		if f, ok := jsonfast.DecodeFloat64(raw); ok {
			return f
		}
		return raw
	default:
		return raw
	}
}

type contextKey struct{}

// WithIdentity returns a copy of ctx carrying id.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// IdentityFromContext returns the identity stored by WithIdentity; ok is
// false, and the identity nil, when there is none or it is nil.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(*Identity)
	return id, ok && id != nil
}
