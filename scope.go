package authware

import "strings"

// scopeTokens splits s on spaces, the only scope separator, dropping empty
// tokens.
func scopeTokens(s string) []string {
	tokens := make([]string, 0, strings.Count(s, " ")+1)
	for token := range strings.SplitSeq(s, " ") {
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}
