package authware

import (
	"slices"

	"github.com/ubyte-source/go-jsonfast"
)

// Capability is an admission check over an authenticated Identity. The zero
// Capability denies every identity.
type Capability struct {
	allow  func(*Identity) bool
	denied *authError
}

// NewCapability wraps fn as a Capability; a nil fn denies every identity.
func NewCapability(fn func(*Identity) bool) Capability {
	return Capability{allow: fn, denied: forbidden()}
}

// Allow reports whether id satisfies the capability; a nil id never does.
func (c Capability) Allow(id *Identity) bool {
	return id != nil && c.allow != nil && c.allow(id)
}

// denial is the error reported when the capability denies an identity, one
// per capability; the zero Capability builds it on each call.
func (c Capability) denial() *authError {
	if c.denied == nil {
		return forbidden()
	}
	return c.denied
}

// forbidden rejects an identity that fails a capability naming no scope; its
// 403 carries no challenge.
func forbidden() *authError {
	return failure(ErrInsufficientScope, "capability not satisfied", nil)
}

// scopeCapability names scopes in the challenge written when it denies.
func scopeCapability(scopes []string, fn func(*Identity) bool) Capability {
	return Capability{allow: fn, denied: insufficientScope(scopes)}
}

// HasAnyScope requires at least one of scopes; with none it always denies.
func HasAnyScope(scopes ...string) Capability {
	scopes = slices.Clone(scopes)
	return scopeCapability(scopes, func(id *Identity) bool {
		return slices.ContainsFunc(scopes, id.HasScope)
	})
}

// HasAllScopes requires every scope; with none it admits any identity.
func HasAllScopes(scopes ...string) Capability {
	scopes = slices.Clone(scopes)
	return scopeCapability(scopes, func(id *Identity) bool {
		for _, s := range scopes {
			if !id.HasScope(s) {
				return false
			}
		}
		return true
	})
}

// HasClaim requires the named claim to equal value as a JSON value of T's kind: a
// string, an integer with no fraction or exponent within int64's range, a number
// whose nearest float64 is finite, or a boolean.
func HasClaim[T string | int64 | float64 | bool](name string, value T) Capability {
	return NewCapability(func(id *Identity) bool {
		got, ok := claimOf[T](id.rawClaim(name))
		return ok && got == value
	})
}

// claimOf decodes raw as a JSON value of the kind of T: a string, an int64 written
// with no fraction or exponent, a number whose nearest float64 is finite, or a boolean.
func claimOf[T string | int64 | float64 | bool](raw string) (value T, ok bool) {
	switch p := any(&value).(type) {
	case *string:
		*p, ok = jsonfast.DecodeString(raw)
	case *int64:
		*p, ok = jsonfast.DecodeInt64(raw)
	case *float64:
		*p, ok = jsonfast.DecodeFloat64(raw)
	case *bool:
		*p, ok = jsonfast.DecodeBool(raw)
	}
	return value, ok
}

// HasMode requires the identity to come from mode m.
func HasMode(m Mode) Capability {
	return NewCapability(func(id *Identity) bool { return id.Mode() == m })
}

// HasSubject requires the identity's subject to equal subject.
func HasSubject(subject string) Capability {
	return NewCapability(func(id *Identity) bool { return id.Subject() == subject })
}
