package syntax

import (
	"encoding/base64"
	"strings"
)

// AppendSegment appends to dst the decoding of s as unpadded base64url whose
// unused trailing bits are zero. It reports false, returning dst, for any
// other input, line breaks included.
func AppendSegment(dst []byte, s string) ([]byte, bool) {
	// The decoder refuses every byte outside the alphabet but skips line breaks.
	if strings.IndexByte(s, '\n') >= 0 || strings.IndexByte(s, '\r') >= 0 {
		return dst, false
	}
	b, err := base64.RawURLEncoding.Strict().AppendDecode(dst, []byte(s))
	if err != nil {
		return dst, false
	}
	return b, true
}
