package netguard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// loopbackOctet starts every IPv4 loopback address.
const loopbackOctet = 127

// errInsecure is the error the tests pass for a refused URL.
var errInsecure = errors.New("test: insecure URL")

func TestCheckAccepts(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://idp.example.com/.well-known/jwks.json",
		"HTTPS://IDP.example.com/x",
		"https://10.0.0.1:8443/keys",
		"http://localhost:8080/token",
		"http://LocalHost/token",
		"http://127.0.0.1/x",
		"http://127.255.0.9:1/x",
		"http://[::1]:9000/x",
	} {
		u, err := Check(raw, errInsecure)
		if err != nil {
			t.Fatalf("Check(%q) = %v, want nil", raw, err)
		}
		if u == nil || u.Host == "" {
			t.Fatalf("Check(%q) = %v, want a URL with a host", raw, u)
		}
	}
}

func TestCheckRejects(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"",
		"/relative/path",
		"//idp.example.com/x",
		"https://",
		"https://:443/x",
		"https:opaque",
		"ftp://idp.example.com/x",
		"http://idp.example.com/x",
		"http://10.0.0.1/x",
		"http://0.0.0.0/x",
		"http://[::ffff:127.0.0.1]/x",
		"http://[::1%25lo]/x",
		"http://127.1/x",
		"http://2130706433/x",
		"http://localhost.evil.test/x",
		"http://localhost./x",
		"https://user@idp.example.com/x",
		"https://user:pw@idp.example.com/x",
		"http://@localhost/x",
		"http://:pw@127.0.0.1/x",
		"http://@@localhost/x",
		"https://idp.example.com:bad/x",
		"%zz",
	} {
		if _, err := Check(raw, errInsecure); !errors.Is(err, errInsecure) {
			t.Fatalf("Check(%q) err = %v, want errInsecure", raw, err)
		}
	}
}

func TestCheckHidesUserinfo(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://svc:S3cr3tP4ss@idp.example.com/x",
		"http://svc:S3cr3tP4ss@idp.example.com/x",
		"https://svc:S3cr3tP4ss@idp.example.com:bad/x",
		"https://svc:S3cr3tP4ss@@idp.example.com/x",
	} {
		_, err := Check(raw, errInsecure)
		if err == nil || !errors.Is(err, errInsecure) {
			t.Fatalf("Check(%q) = %v, want errInsecure", raw, err)
		}
		if msg := err.Error(); strings.Contains(msg, "S3cr3tP4ss") || strings.Contains(msg, "svc") {
			t.Fatalf("Check error = %s, want no userinfo", msg)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"localhost":        true,
		"LOCALHOST":        true,
		"127.0.0.1":        true,
		"127.10.20.30":     true,
		"::1":              true,
		"::1%lo":           false,
		"::ffff:127.0.0.1": false,
		"128.0.0.1":        false,
		"::2":              false,
		"example.com":      false,
		"":                 false,
	}
	for host, want := range cases {
		if got := isLoopback(host); got != want {
			t.Fatalf("isLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	t.Parallel()
	const idp = "https://idp.example/tenant"
	tests := []struct {
		a, b string
		same bool
	}{
		{idp, "https://idp.example/keys", true},
		{idp, "HTTPS://IDP.example:443/keys", true},
		{"http://localhost/x", "http://LOCALHOST:80/y", true},
		{"http://[::1]:81/x", "http://[::1]:81/y", true},
		{idp, "https://idp.example:8443/keys", false},
		{idp, "https://other.example/keys", false},
		{idp, "https://idp.example.evil/keys", false},
		{idp, "http://idp.example/keys", false},
		{"https://idp.example:80/x", "http://idp.example/x", false},
		{"http://idp.example:443/x", "https://idp.example/x", false},
		{"http://localhost/x", "http://localhost:443/x", false},
		{"http://localhost:8080/x", "http://127.0.0.1:8080/x", false},
	}
	for _, tc := range tests {
		a, errA := url.Parse(tc.a)
		b, errB := url.Parse(tc.b)
		if errA != nil || errB != nil {
			t.Fatalf("Parse = %v, %v, want two URLs", errA, errB)
		}
		if got, rev := SameOrigin(a, b), SameOrigin(b, a); got != tc.same || rev != tc.same {
			t.Errorf("SameOrigin(%s, %s) = %v (reversed %v), want %v", tc.a, tc.b, got, rev, tc.same)
		}
	}
}

func TestDefaultPort(t *testing.T) {
	t.Parallel()
	for scheme, want := range map[string]string{SchemeHTTP: "80", SchemeHTTPS: "443"} {
		if got := DefaultPort(scheme); got != want {
			t.Errorf("DefaultPort(%q) = %q, want %q", scheme, got, want)
		}
	}
}

// ipv6Zone matches an IPv6 literal host around its zone, from the first "%" to
// the last "]".
var ipv6Zone = regexp.MustCompile(`(?s)^(\[[^%]*)%.*(\][^\]]*)$`)

// wireHost returns the Host a server reads from a request net/http writes for
// host, and false when net/http refuses to write it.
func wireHost(host string) (string, bool) {
	r := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: SchemeHTTP, Host: host, Path: "/"}, Host: host}
	var wire bytes.Buffer
	if r.Write(&wire) != nil {
		return "", false
	}
	got, err := http.ReadRequest(bufio.NewReader(&wire))
	if err != nil {
		return "", false
	}
	return got.Host, true
}

// settledHost returns the host net/http sends for host once it sends one as it
// is, writing each host it changes again, and false when it refuses one.
func settledHost(host string) (string, bool) {
	for {
		sent, ok := wireHost(host)
		if !ok || sent == host {
			return sent, ok
		}
		host = sent
	}
}

func TestSplitZone(t *testing.T) {
	t.Parallel()
	for host, want := range map[string][2]string{
		"a.example:80": {"a.example:80", ""}, "[fe80::1%eth0]:8080": {"[fe80::1", "]:8080"},
		"[fe80::1%en0]": {"[fe80::1", "]"}, "[fe80::1%en%31]": {"[fe80::1", "]"}, "[::1]:80": {"[::1]:80", ""},
		"[a%b%c]:1": {"[a", "]:1"}, "[a%b]%c": {"[a", "]%c"}, "[a]b%c]d": {"[a]b", "]d"}, "[%]": {"[", "]"},
		"[fe80::1%en0": {"[fe80::1%en0", ""}, "x%y]:80": {"x%y]:80", ""}, "[]": {"[]", ""}, "": {"", ""},
	} {
		head, tail := SplitZone(host)
		if head != want[0] || tail != want[1] {
			t.Errorf("SplitZone(%q) = %q, %q; want %q, %q", host, head, tail, want[0], want[1])
		}
		if settled, ok := settledHost(host); !ok || head+tail != settled {
			t.Errorf("SplitZone(%q) joins to %q, want %q, the host net/http settles on", host, head+tail, settled)
		}
	}
}

// FuzzSplitZone checks SplitZone against ipv6Zone for every host, and against
// the host net/http settles on for every valid ASCII host: net/http sends an
// invalid one empty.
func FuzzSplitZone(f *testing.F) {
	for _, seed := range []string{
		"a.example:80", "[fe80::1%en0]:80", "[a%b%c]:1", "[a%b]%c", "[a]b%c]d", "[x", "x%y]:80", "a b", "[\xff%\n]",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		head, tail := SplitZone(host)
		want := ipv6Zone.ReplaceAllString(host, "$1$2")
		if head+tail != want || (tail == "") != (want == host) || !strings.HasPrefix(host, head) {
			t.Fatalf("SplitZone(%q) = %q, %q; want %q joined, the tail empty only without a zone", host, head,
				tail, want)
		}
		settled, ok := settledHost(host)
		nonASCII := strings.ContainsFunc(host, func(c rune) bool { return c >= utf8.RuneSelf })
		if !ok || (settled == "" && host != "") || nonASCII {
			return
		}
		if head+tail != settled {
			t.Fatalf("SplitZone(%q) joins to %q, want %q, the host net/http settles on", host, head+tail, settled)
		}
	})
}

func TestEffectivePort(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"https://a.example": "443", "HTTP://localhost": "80", "https://a.example:8443": "8443", "http://[::1]:81": "81",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q) = %v, want a URL", raw, err)
		}
		if got := effectivePort(u); got != want {
			t.Errorf("effectivePort(%q) = %q, want %q", raw, got, want)
		}
	}
}

// referenceLoopback restates the loopback rule with package net: localhost,
// an IPv4 literal in 127.0.0.0/8, or the IPv6 literal ::1 without a zone.
func referenceLoopback(host string) bool {
	ip := net.ParseIP(host)
	switch {
	case strings.EqualFold(host, "localhost"):
		return true
	case ip == nil:
		return false
	case strings.Contains(host, ":"):
		return ip.Equal(net.IPv6loopback) && ip.To4() == nil
	}
	return ip[len(ip)-net.IPv4len] == loopbackOctet
}

// referenceCheck returns the URL Check must accept for raw, else the text of
// the error it must return.
func referenceCheck(raw string) (want *url.URL, text string) {
	const prefix = "test: insecure URL: "
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, prefix + "unparseable"
	case u.User != nil:
		return nil, prefix + "userinfo not allowed"
	case u.Hostname() == "":
		return nil, prefix + "missing host"
	case u.Scheme == "https", u.Scheme == "http" && referenceLoopback(u.Hostname()):
		return u, ""
	}
	return nil, fmt.Sprintf(prefix+"scheme %q to host %q", u.Scheme, u.Hostname())
}

func FuzzCheck(f *testing.F) {
	for _, raw := range []string{
		"https://idp.example.com/x", "http://localhost:8080/t", "http://127.0.0.2/x", "http://[::1]/x",
		"http://[::ffff:127.0.0.1]/x", "http://[0:0:0:0:0:0:0:1]/x", "http://[::1%25lo]/x", "http://127.1/x",
		"https://u:p@idp.example.com/x", "http://@localhost/x", "ftp://h/x", "https://:443/x", "%zz", "",
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := Check(raw, errInsecure)
		want, text := referenceCheck(raw)
		if want != nil && (err != nil || got == nil || got.String() != want.String()) {
			t.Fatalf("Check(%q) = %v, %v; want %v", raw, got, err, want)
		}
		if want == nil && (got != nil || !errors.Is(err, errInsecure) || err.Error() != text) {
			t.Fatalf("Check(%q) = %v, %v; want %q", raw, got, err, text)
		}
	})
}

// hostLetter is the byte TestSentAsIs puts around each byte it tries in a host.
const hostLetter = "a"

// TestSentAsIs compares SentAsIs with what net/http sends for a host holding each
// byte, and for hosts outside ASCII, which it converts to punycode or refuses.
func TestSentAsIs(t *testing.T) {
	check := func(host string) {
		sent, ok := wireHost(host)
		if got, want := SentAsIs(host), ok && sent == host; got != want {
			t.Errorf("SentAsIs(%q) = %t, want %t: net/http sends it as %q, written %t", host, got, want, sent, ok)
		}
	}
	for _, host := range []string{"", "b\u00fccher.example", "\u00e9", "x\xff", "[::1]:8443", "a%zz"} {
		check(host)
	}
	for c := range math.MaxUint8 + 1 {
		check(hostLetter + string([]byte{byte(c)}) + hostLetter)
	}
}
