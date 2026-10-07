package syntax

import (
	"strings"
	"testing"
)

func TestSplitJWS(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]JWS{
		"h.c.s":  {Header: "h", Payload: "c", Signature: "s"},
		"..":     {},
		"h..":    {Header: "h"},
		"a b.!.": {Header: "a b", Payload: "!"},
	} {
		if got, ok := SplitJWS(in); !ok || got != want {
			t.Errorf("SplitJWS(%q) = %+v, %v, want %+v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "h", "h.p", "h.p.s.x", "...."} {
		if got, ok := SplitJWS(in); ok || got != (JWS{}) {
			t.Errorf("SplitJWS(%q) = %+v, %v, want a refusal", in, got, ok)
		}
	}
}

func FuzzSplitJWS(f *testing.F) {
	for _, s := range []string{"h.p.s", "..", "h.p", "h.p.s.x", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		parts := strings.Split(s, ".")
		got, ok := SplitJWS(s)
		if ok != (len(parts) == 3) {
			t.Fatalf("SplitJWS(%q) ok = %v, want %v for %d parts", s, ok, len(parts) == 3, len(parts))
		}
		if ok && got != (JWS{Header: parts[0], Payload: parts[1], Signature: parts[2]}) {
			t.Fatalf("SplitJWS(%q) = %+v, want %q", s, got, parts)
		}
	})
}
