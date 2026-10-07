package authware

import (
	"slices"
	"testing"
)

func TestScopeTokens(t *testing.T) {
	for in, want := range map[string][]string{
		"":             nil,
		"  a  b ":      {scopeA, scopeB},
		"admin\tx b":   {"admin\tx", scopeB},
		"admin\u00a0x": {"admin\u00a0x"},
		"admin\nx":     {"admin\nx"},
		"admin\u0085x": {"admin\u0085x"},
	} {
		if got := scopeTokens(in); !slices.Equal(got, want) {
			t.Errorf("scopeTokens(%q) = %q, want %q", in, got, want)
		}
	}
	// One allocation: the tokens are counted before the split.
	assertAllocs(t, 1, func() { scopeTokens("orders.read orders.write admin") })
}
