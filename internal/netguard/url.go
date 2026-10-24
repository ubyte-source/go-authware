package netguard

import (
	"cmp"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// The schemes of the URLs the policy admits.
const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

// Check parses raw and returns it when it is an absolute https URL, or an
// http URL to a loopback host, with a host and no userinfo. Errors wrap
// insecure and never echo raw, which may carry credentials.
func Check(raw string, insecure error) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: unparseable", insecure)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: userinfo not allowed", insecure)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: missing host", insecure)
	}
	switch {
	case u.Scheme == SchemeHTTPS:
		return u, nil
	case u.Scheme == SchemeHTTP && isLoopback(host):
		return u, nil
	}
	return nil, fmt.Errorf("%w: scheme %q to host %q", insecure, u.Scheme, host)
}

// isLoopback accepts localhost, 127.0.0.0/8 and ::1 in their literal forms.
func isLoopback(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return strings.EqualFold(host, "localhost")
	}
	return addr == netip.IPv6Loopback() || (addr.Is4() && addr.IsLoopback())
}

// SameOrigin reports whether the parsed http or https URLs a and b share scheme,
// host compared case-insensitively, and effective port.
func SameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

// effectivePort returns the explicit port of u or the default of its scheme.
func effectivePort(u *url.URL) string {
	return cmp.Or(u.Port(), DefaultPort(u.Scheme))
}

// DefaultPort returns the port that a URL of scheme, http or https, leaves
// implicit.
func DefaultPort(scheme string) string {
	if scheme == SchemeHTTP {
		return "80"
	}
	return "443"
}
