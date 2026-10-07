package syntax

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// prefix is the text AppendSegment appends to.
const prefix = "p"

func TestAppendSegment(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"": "", "AA": "\x00", "_-8": "\xff\xef", "eyJhIjoxfQ": `{"a":1}`,
	} {
		if got, ok := AppendSegment([]byte(prefix), in); !ok || string(got) != prefix+want {
			t.Errorf("AppendSegment(p, %q) = %q, %v, want %q", in, got, ok, prefix+want)
		}
	}
	for _, in := range []string{"AB", "AA==", "A", "A\nA", "A\rA", "\nAA", "\rAA", "A A", "+/AA", "AA."} {
		if got, ok := AppendSegment([]byte(prefix), in); ok || string(got) != prefix {
			t.Errorf("AppendSegment(p, %q) = %q, %v, want p and a refusal", in, got, ok)
		}
	}
}

func FuzzAppendSegment(f *testing.F) {
	for _, s := range []string{"", "AA", "AB", "_-8", "A\nA", "AA==", "+/AA", "eyJhIjoxfQ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		lenient, err := base64.RawURLEncoding.DecodeString(s)
		want := err == nil && strings.Trim(s, alphabet) == "" && base64.RawURLEncoding.EncodeToString(lenient) == s
		got, ok := AppendSegment([]byte(prefix), s)
		if ok != want || (ok && !bytes.Equal(got, append([]byte(prefix), lenient...))) || (!ok &&
			string(got) != prefix) {
			t.Fatalf("AppendSegment(p, %q) = %q, %v; want p%q, %v", s, got, ok, lenient, want)
		}
	})
}

func BenchmarkAppendSegment(b *testing.B) {
	claims := `{"iss":"https://idp.example.com/tenant","sub":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",` +
		`"aud":"api://orders","iat":1700000000,"nbf":1700000000,"exp":1700003600,"scope":"orders.read orders.write"}`
	segment := base64.RawURLEncoding.EncodeToString([]byte(claims))
	buf := make([]byte, 0, len(claims))
	if got, ok := AppendSegment(buf, segment); !ok || string(got) != claims {
		b.Fatalf("AppendSegment = %q, %v, want the claims", got, ok)
	}
	b.ReportAllocs()
	for b.Loop() {
		AppendSegment(buf, segment)
	}
}
