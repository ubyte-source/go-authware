package authware

import (
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

const scopeSeparator = " "

// scopeTokens splits s on spaces, the only scope separator, dropping empty
// tokens.
func scopeTokens(s string) []string {
	tokens := make([]string, 0, strings.Count(s, scopeSeparator)+1)
	for token := range strings.SplitSeq(s, scopeSeparator) {
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

// scopeList reports whether every field scopeTokens splits s into is a scope
// token.
func scopeList(s string) bool {
	for field := range strings.SplitSeq(s, scopeSeparator) {
		if field != "" && !syntax.IsScope(field) {
			return false
		}
	}
	return true
}
