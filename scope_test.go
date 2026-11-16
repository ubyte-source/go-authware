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

// TestScopeList accepts the lists whose fields are all scope tokens, the empty
// list among them, and reads a list without allocating.
func TestScopeList(t *testing.T) {
	for in, want := range map[string]bool{
		"": true, " ": true, "  a  b ": true, "orders.read orders:write !#[]~": true, "admin\tx b": false,
		"admin\nx": false, "a \x7f": false, `a"b`: false, `a b\c`: false, "caf\u00e9": false, "a \u00a0": false,
		"a \x1f b": false,
	} {
		if got := scopeList(in); got != want {
			t.Errorf("scopeList(%q) = %t, want %t", in, got, want)
		}
	}
	assertAllocs(t, 0, func() { scopeList("orders.read orders.write admin") })
}
