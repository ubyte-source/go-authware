package secret

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
)

const mask = "***"

// Value is a secret string whose text is its mask: *** or, for the zero Value,
// nothing. fmt prints its type instead for %T, and the address it holds for %p, %w
// and in an unexported field. Values are not comparable; only Equal compares them.
type Value struct {
	_ [0]func()
	p *string
}

// New wraps s; New("") is the zero Value.
func New(s string) Value {
	if s == "" {
		return Value{}
	}
	return Value{p: &s}
}

// Reveal returns the secret itself.
func (v Value) Reveal() string {
	if v.p == nil {
		return ""
	}
	return *v.p
}

// IsZero reports whether the secret is empty.
func (v Value) IsZero() bool { return v.p == nil }

// Len returns the length of the secret in bytes.
func (v Value) Len() int { return len(v.Reveal()) }

// Equal reports whether both secrets are equal, in time that depends only
// on their lengths.
func (v Value) Equal(other Value) bool {
	return subtle.ConstantTimeCompare([]byte(v.Reveal()), []byte(other.Reveal())) == 1
}

// String returns the mask.
func (v Value) String() string { return v.masked() }

// GoString returns the mask.
func (v Value) GoString() string { return v.masked() }

// Format writes the mask whatever the verb and flags; fmt calls it for every
// verb but %T, %p and %w.
func (v Value) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, v.masked()) //nolint:errcheck // fmt.Formatter cannot return errors
}

// LogValue renders the mask in log/slog records.
func (v Value) LogValue() slog.Value { return slog.StringValue(v.masked()) }

// MarshalText encodes the mask, which every JSON encoder then quotes.
func (v Value) MarshalText() ([]byte, error) { return []byte(v.masked()), nil }

func (v Value) masked() string {
	if v.p == nil {
		return ""
	}
	return mask
}
