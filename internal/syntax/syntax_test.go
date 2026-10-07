package syntax

import (
	"strings"
	"testing"
)

// The values of a byte, and DEL, the one ASCII control byte above the
// printable range.
const (
	byteValues = 256
	del        = 0x7f
)

func TestIsUnreserved(t *testing.T) {
	t.Parallel()
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for c := range byteValues {
		if got, want := IsUnreserved(byte(c)), strings.IndexByte(unreserved, byte(c)) >= 0; got != want {
			t.Errorf("IsUnreserved(%q) = %v, want %v", byte(c), got, want)
		}
	}
}

func TestIsControl(t *testing.T) {
	t.Parallel()
	for c := range byteValues {
		if got, want := IsControl(byte(c)), c < ' ' || c == del; got != want {
			t.Errorf("IsControl(%#x) = %v, want %v", c, got, want)
		}
	}
}

func TestIsToken(t *testing.T) {
	t.Parallel()
	const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~"
	if IsToken("") {
		t.Error(`IsToken("") = true, want false`)
	}
	for c := range byteValues {
		want := strings.IndexByte(token, byte(c)) >= 0
		for _, s := range []string{string([]byte{byte(c)}), "X-" + string([]byte{byte(c)})} {
			if got := IsToken(s); got != want {
				t.Errorf("IsToken(%q) = %v, want %v", s, got, want)
			}
		}
	}
}

func TestIsScope(t *testing.T) {
	t.Parallel()
	if IsScope("") {
		t.Error(`IsScope("") = true, want false`)
	}
	for c := range byteValues {
		want := c >= '!' && c <= '~' && c != '"' && c != '\\'
		for _, s := range []string{string([]byte{byte(c)}), "mcp:" + string([]byte{byte(c)})} {
			if got := IsScope(s); got != want {
				t.Errorf("IsScope(%q) = %v, want %v", s, got, want)
			}
		}
	}
}

func TestIsFieldValue(t *testing.T) {
	t.Parallel()
	if IsFieldValue("") {
		t.Error(`IsFieldValue("") = true, want false`)
	}
	for c := range byteValues {
		b := string([]byte{byte(c)})
		edge := c > ' ' && c != del
		inner := edge || c == ' ' || c == '\t'
		for s, want := range map[string]bool{b: edge, b + "a": edge, "a" + b: edge, "a" + b + "b": inner} {
			if got := IsFieldValue(s); got != want {
				t.Errorf("IsFieldValue(%q) = %v, want %v", s, got, want)
			}
		}
	}
	// Multi-byte edges are obs-text bytes, field-vchar whatever rune they encode.
	for _, s := range []string{"a\u200b", "a\u00ad", "a\u00a0", "\u3000a", "\u0085a", "a\u2028", "a\xff"} {
		if !IsFieldValue(s) {
			t.Errorf("IsFieldValue(%q) = false, want true: only a space or a tab is barred at either end", s)
		}
	}
}
