package netguard

import (
	"bufio"
	"bytes"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

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
