package syntax

import "strings"

// symbolChars lists the characters a token allows besides the unreserved ones.
const symbolChars = "!#$%&'*+^`|"

// IsUnreserved reports whether c is an unreserved URI character: a letter,
// a digit, '-', '.', '_' or '~'.
func IsUnreserved(c byte) bool {
	return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// asciiDEL is DEL, the ASCII control byte above the printable range.
const asciiDEL = 0x7F

// IsControl reports whether c is an ASCII control byte.
func IsControl(c byte) bool {
	return c < ' ' || c == asciiDEL
}

// IsToken reports whether s is a non-empty run of the characters a header
// name or an authentication scheme allows.
func IsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if c := s[i]; !IsUnreserved(c) && strings.IndexByte(symbolChars, c) < 0 {
			return false
		}
	}
	return true
}

// IsScope reports whether s is a non-empty scope token: printable ASCII
// except space, double quote and backslash.
func IsScope(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c <= ' ' || c == '"' || c == '\\' || c >= asciiDEL {
			return false
		}
	}
	return true
}

// IsFieldValue reports whether s is a non-empty HTTP field value: no control
// byte but an inner tab, and no space or tab at either end, so a credential
// read with a trailing newline is refused instead of sent altered.
func IsFieldValue(s string) bool {
	if s == "" || isBlank(s[0]) || isBlank(s[len(s)-1]) {
		return false
	}
	for i := range len(s) {
		if c := s[i]; IsControl(c) && c != '\t' {
			return false
		}
	}
	return true
}

// isBlank reports whether c is a space or a tab, the bytes HTTP trims around a
// field value.
func isBlank(c byte) bool {
	return c == ' ' || c == '\t'
}
