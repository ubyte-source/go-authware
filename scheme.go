package authware

// parseAuthScheme extracts the credential payload from an Authorization
// header whose scheme matches a lower-case literal. Scheme matching is
// ASCII case-insensitive and the scheme/credential separator is a
// single space; both invariants are enforced without allocation.
func parseAuthScheme(header, scheme string) (string, bool) {
	n := len(scheme)
	if len(header) <= n+1 || header[n] != ' ' {
		return "", false
	}
	for i := range n {
		if header[i]|0x20 != scheme[i] {
			return "", false
		}
	}
	return header[n+1:], true
}
