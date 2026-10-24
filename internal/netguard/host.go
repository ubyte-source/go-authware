package netguard

import (
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

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
