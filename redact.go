package authware

import (
	"context"
	"log/slog"
	"net/http"
)

const redactedValue = "***"

// defaultSensitiveHeaders is the canonical-cased default redaction set.
var defaultSensitiveHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"Set-Cookie",
	"X-Api-Key",
	"X-Auth-Token",
}

// SensitiveHeaders returns a fresh copy of the default redaction set;
// callers may safely append.
func SensitiveHeaders() []string {
	out := make([]string, len(defaultSensitiveHeaders))
	copy(out, defaultSensitiveHeaders)
	return out
}

// canonicaliseHeaders lifts each name to canonical form.
func canonicaliseHeaders(in []string) []string {
	out := make([]string, len(in))
	for i, k := range in {
		out[i] = http.CanonicalHeaderKey(k)
	}
	return out
}

// NewRedactor wraps inner so any slog attribute whose key matches one
// of keys (case-insensitive) is replaced with "***". Empty keys
// returns inner unchanged.
func NewRedactor(inner slog.Handler, keys ...string) slog.Handler {
	if len(keys) == 0 {
		return inner
	}
	lowered := make([]string, len(keys))
	for i, k := range keys {
		lowered[i] = asciiToLower(k)
	}
	return &redactor{inner: inner, keys: lowered}
}

// RedactHeader replaces in-place every value of every header in h whose
// key is listed in keys. Empty keys uses the package default set.
func RedactHeader(h http.Header, keys ...string) http.Header {
	if h == nil {
		return nil
	}
	canon := defaultSensitiveHeaders
	if len(keys) > 0 {
		canon = canonicaliseHeaders(keys)
	}
	for _, k := range canon {
		if values, ok := h[k]; ok {
			for i := range values {
				values[i] = redactedValue
			}
		}
	}
	return h
}

type redactor struct {
	inner slog.Handler
	keys  []string // pre-lowered keys; matched case-insensitively.
}

func (r *redactor) Enabled(ctx context.Context, level slog.Level) bool {
	return r.inner.Enabled(ctx, level)
}

// Handle satisfies slog.Handler.
//
//nolint:gocritic // hugeParam: slog.Handler.Handle signature requires Record by value.
func (r *redactor) Handle(ctx context.Context, record slog.Record) error {
	if record.NumAttrs() == 0 {
		return r.inner.Handle(ctx, record)
	}
	clone := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(a slog.Attr) bool {
		clone.AddAttrs(r.redactAttr(a))
		return true
	})
	return r.inner.Handle(ctx, clone)
}

func (r *redactor) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		cleaned[i] = r.redactAttr(a)
	}
	return &redactor{inner: r.inner.WithAttrs(cleaned), keys: r.keys}
}

func (r *redactor) WithGroup(name string) slog.Handler {
	return &redactor{inner: r.inner.WithGroup(name), keys: r.keys}
}

func (r *redactor) redactAttr(a slog.Attr) slog.Attr {
	if r.matchesKey(a.Key) {
		return slog.String(a.Key, redactedValue)
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		if len(group) == 0 {
			return a
		}
		out := make([]slog.Attr, len(group))
		for i, child := range group {
			out[i] = r.redactAttr(child)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	}
	return a
}

func (r *redactor) matchesKey(key string) bool {
	for _, want := range r.keys {
		if asciiEqualFoldStr(key, want) {
			return true
		}
	}
	return false
}

// asciiToLower lowercases the ASCII letters of s; non-ASCII bytes pass
// through unchanged. Used at construction time only.
func asciiToLower(s string) string {
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b := make([]byte, len(s))
			copy(b, s[:i])
			for j := i; j < len(s); j++ {
				cj := s[j]
				if cj >= 'A' && cj <= 'Z' {
					cj |= 0x20
				}
				b[j] = cj
			}
			return string(b)
		}
	}
	return s
}

// asciiEqualFoldStr reports whether s equals lower (already lower-cased)
// under ASCII case folding.
func asciiEqualFoldStr(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}
