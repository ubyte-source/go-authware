package authware

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

// The masks of a redacted value and of a URL password, the latter as
// URL.Redacted writes it.
const (
	redactedValue    = "***"
	redactedPassword = "xxxxx"
)

// SensitiveHeaders returns the default redaction set, a fresh slice per call.
// It names the default API key header X-Api-Key only: a Gate reading the key
// from another header needs that name added.
func SensitiveHeaders() []string {
	return []string{
		headerAuthorization,
		"Proxy-Authorization",
		"Cookie",
		"Set-Cookie",
		defaultKeyHeader,
		"X-Auth-Token",
	}
}

// nameSet matches header and attribute names case-insensitively.
type nameSet []string

func (s nameSet) has(name string) bool {
	return slices.ContainsFunc(s, func(k string) bool { return strings.EqualFold(k, name) })
}

// mask sets every value of every header of h named in s to ***, in place.
func (s nameSet) mask(h http.Header) http.Header {
	for name, values := range h {
		if s.has(name) {
			for i := range values {
				values[i] = redactedValue
			}
		}
	}
	return h
}

// masked returns a masked copy of h whose URL-valued headers also hold their
// URLs without credentials.
func (s nameSet) masked(h http.Header) http.Header {
	c := s.mask(h.Clone())
	for name, values := range c {
		if urlValued(name) {
			s.maskURLs(values)
		}
	}
	return c
}

// maskURLs renders in place each of values by maskURL, or as *** when it is
// no URL.
func (s nameSet) maskURLs(values []string) {
	for i, v := range values {
		values[i] = redactedValue
		if u, err := url.Parse(v); err == nil {
			values[i] = s.maskURL(u)
		}
	}
}

// urlValued reports whether the header name carries a URL, whose query or
// fragment can hold credentials.
func urlValued(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Location", "Content-Location", "Referer":
		return true
	}
	return false
}

// maskedValue renders a value that can carry credentials without them: a
// header as a masked copy, a request or a response as a group of its method
// or status, URL and header, masked, and a URL, userinfo or query masked.
func (s nameSet) maskedValue(v slog.Value) slog.Value {
	switch x := v.Any().(type) {
	case http.Header:
		return slog.AnyValue(s.masked(x))
	case map[string][]string:
		return slog.AnyValue(s.masked(x))
	case *http.Header:
		if x != nil {
			return slog.AnyValue(s.masked(*x))
		}
	case *http.Request:
		if x != nil {
			return s.request(x)
		}
	case *http.Response:
		if x != nil {
			return s.response(x)
		}
	}
	return s.maskedLocation(v)
}

// maskedLocation renders a URL, its userinfo or query values without
// credentials; any other value is returned as it is.
func (s nameSet) maskedLocation(v slog.Value) slog.Value {
	switch x := v.Any().(type) {
	case url.Values:
		return slog.AnyValue(s.maskParams(x))
	case *url.URL:
		return slog.StringValue(s.maskURL(x))
	case url.URL:
		return slog.StringValue(s.maskURL(&x))
	case *url.Userinfo:
		if x != nil {
			return slog.StringValue(maskUserinfo(x))
		}
	}
	return v
}

// request renders r as its method, masked URL and masked header.
func (s nameSet) request(r *http.Request) slog.Value {
	return slog.GroupValue(slog.String("method", r.Method), slog.String("url", s.maskURL(r.URL)),
		slog.Any("header", s.masked(r.Header)))
}

// response renders resp as its status, the masked URL of its request and its
// masked header.
func (s nameSet) response(resp *http.Response) slog.Value {
	status, header := slog.Int("status", resp.StatusCode), slog.Any("header", s.masked(resp.Header))
	if resp.Request == nil {
		return slog.GroupValue(status, header)
	}
	return slog.GroupValue(status, slog.String("url", s.maskURL(resp.Request.URL)), header)
}

// maskURL renders u redacted, its password as URL.Redacted writes it and the
// value of every query or fragment parameter that maskedParam names as ***.
func (s nameSet) maskURL(u *url.URL) string {
	if u == nil || u.RawQuery == "" && u.Fragment == "" {
		return u.Redacted()
	}
	c := *u
	c.RawQuery, c.Fragment, c.RawFragment = s.maskQuery(u.RawQuery), "", ""
	if u.Fragment == "" {
		return c.Redacted()
	}
	return c.Redacted() + "#" + s.maskQuery(u.EscapedFragment())
}

// maskQuery returns the raw query with the value of every parameter that
// maskedParam names as ***, keeping the rest as it is spelled.
func (s nameSet) maskQuery(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	sep := ""
	for pair := range strings.SplitSeq(raw, "&") {
		b.WriteString(sep)
		sep = "&"
		name, _, _ := strings.Cut(pair, "=")
		if key, err := url.QueryUnescape(name); err == nil && s.maskedParam(key) {
			b.WriteString(name)
			b.WriteString("=" + redactedValue)
			continue
		}
		b.WriteString(pair)
	}
	return b.String()
}

// maskParams returns a copy of vals with the values of every parameter that
// maskedParam names as ***.
func (s nameSet) maskParams(vals url.Values) url.Values {
	out := make(url.Values, len(vals))
	for name, values := range vals {
		if s.maskedParam(name) {
			values = slices.Repeat([]string{redactedValue}, len(values))
		}
		out[name] = values
	}
	return out
}

// maskedParam reports whether the query parameter name, in any case, is in s
// or carries a credential.
func (s nameSet) maskedParam(name string) bool {
	for _, credential := range [...]string{
		oauthwire.ParamAccessToken, oauthwire.ParamRefreshToken, oauthwire.ParamIDToken, paramCode,
		paramCodeVerifier, oauthwire.ParamClientSecret, "client_assertion", "password", "api_key",
	} {
		if strings.EqualFold(name, credential) {
			return true
		}
	}
	return s.has(name)
}

// maskUserinfo renders u with its password, when it has one, as
// URL.Redacted writes it.
func maskUserinfo(u *url.Userinfo) string {
	if _, ok := u.Password(); ok {
		return url.UserPassword(u.Username(), redactedPassword).String()
	}
	return u.String()
}

// RedactHeader masks in place the values of the headers named by keys, or
// by SensitiveHeaders when keys is empty, and returns h.
func RedactHeader(h http.Header, keys ...string) http.Header {
	return redactionKeys(keys).mask(h)
}

// redactionKeys returns keys, or SensitiveHeaders when keys is empty.
func redactionKeys(keys []string) nameSet {
	if len(keys) == 0 {
		return SensitiveHeaders()
	}
	return keys
}

// redactor is the slog.Handler built by NewRedactor.
type redactor struct {
	inner slog.Handler
	names nameSet
}

// NewRedactor wraps inner, not nil, so attributes, headers and URL parameters named
// by keys, or SensitiveHeaders, and credential parameters of URL queries, fragments
// and URL-valued headers log as "***" at any depth, passwords as URL.Redacted does.
func NewRedactor(inner slog.Handler, keys ...string) slog.Handler {
	return &redactor{inner: inner, names: slices.Clone(redactionKeys(keys))}
}

// Enabled reports whether the inner handler handles level.
func (r *redactor) Enabled(ctx context.Context, level slog.Level) bool {
	return r.inner.Enabled(ctx, level)
}

// Handle passes a copy of record with its attributes redacted.
//
//nolint:gocritic // hugeParam: slog.Handler requires the Record by value.
func (r *redactor) Handle(ctx context.Context, record slog.Record) error {
	clone := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(a slog.Attr) bool {
		clone.AddAttrs(r.redactAttr(a))
		return true
	})
	return r.inner.Handle(ctx, clone)
}

// WithAttrs returns a redactor over the inner handler with attrs redacted.
func (r *redactor) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		cleaned[i] = r.redactAttr(a)
	}
	return &redactor{inner: r.inner.WithAttrs(cleaned), names: r.names}
}

// WithGroup returns a redactor over the inner handler opened on group name,
// or r itself when name is empty.
func (r *redactor) WithGroup(name string) slog.Handler {
	if name == "" {
		return r
	}
	return &redactor{inner: r.inner.WithGroup(name), names: r.names}
}

// redactAttr masks a sensitive key, then walks the resolved value: groups
// recursively, and any other value through maskedValue.
func (r *redactor) redactAttr(a slog.Attr) slog.Attr {
	if r.names.has(a.Key) {
		return slog.String(a.Key, redactedValue)
	}
	a.Value = a.Value.Resolve()
	switch a.Value.Kind() {
	case slog.KindGroup:
		group := a.Value.Group()
		out := make([]slog.Attr, len(group))
		for i, child := range group {
			out[i] = r.redactAttr(child)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindAny:
		return slog.Attr{Key: a.Key, Value: r.names.maskedValue(a.Value)}
	default:
		return a
	}
}
