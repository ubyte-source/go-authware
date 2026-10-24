package netguard

import (
	"cmp"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
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

// SplitZone returns host around the zone of an IPv6 literal, from the first "%" before
// the last "]" up to that "]": head+tail holds no zone that net/http's HTTP/1.1 writer
// cuts. A host without a zone is head, tail empty.
func SplitZone(host string) (head, tail string) {
	if !strings.HasPrefix(host, "[") {
		return host, ""
	}
	end := strings.LastIndexByte(host, ']')
	if end == -1 {
		return host, ""
	}
	zone := strings.IndexByte(host[:end], '%')
	if zone == -1 {
		return host, ""
	}
	return host[:zone], host[end:]
}

// hostPunctuation holds the bytes beside the unreserved ones that the Host header check
// of net/http admits.
const hostPunctuation = "!$%&'()*+,:;=[]"

// SentAsIs reports whether the Host header check of net/http admits every byte of host,
// an unreserved one or one of hostPunctuation, so that net/http sends host as it is but
// for an IPv6 zone; every byte outside ASCII fails it.
func SentAsIs(host string) bool {
	for i := range len(host) {
		if c := host[i]; !syntax.IsUnreserved(c) && strings.IndexByte(hostPunctuation, c) < 0 {
			return false
		}
	}
	return true
}
