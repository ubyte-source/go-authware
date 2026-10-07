package oauthwire

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Literals of the error tests: the documented 256-byte cut of an excerpt, a run
// of padding, a description and a one-byte text.
const (
	excerptBytes = 256
	padding      = 300
	downText     = "upstream down"
	oneByte      = "x"
)

// errorParts is what errorMembers returns.
type errorParts struct {
	code, description string
}

func TestErrorMembers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		body string
		want errorParts
	}{
		{`{"error":"invalid_grant","error_description":"expired\tcode"}`, errorParts{"invalid_grant", "expired\tcode"}},
		{` {"error_description":"d","error":"invalid_client"} `, errorParts{"invalid_client", "d"}},
		{`{"message":"nope"}`, errorParts{"", `{"message":"nope"}`}},
		{`{"error":"invalid_grant"`, errorParts{"", `{"error":"invalid_grant"`}},
		{`{"error":"slow_down","error_description":null,"x":{}}`, errorParts{"slow_down", ""}},
		{`{"error":null,"error_description":"d"}`, errorParts{"", `{"error":null,"error_description":"d"}`}},
		{`{"error":"a","error":"b"}`, errorParts{"", `{"error":"a","error":"b"}`}},
		{`{"error":"a","x":{"k":1,"k":2}}`, errorParts{"", `{"error":"a","x":{"k":1,"k":2}}`}},
		{`{"error":7}`, errorParts{"", `{"error":7}`}},
		{`{"error":" ","error_description":"d"}`, errorParts{"", `{"error":" ","error_description":"d"}`}},
		{`{"error":"a","error_description":[]}`, errorParts{"", `{"error":"a","error_description":[]}`}},
		{"  upstream down\n", errorParts{"", downText}},
		{"", errorParts{}},
	}
	for _, tc := range cases {
		code, description := errorMembers([]byte(tc.body))
		if got := (errorParts{code, description}); got != tc.want {
			t.Fatalf("errorMembers(%q) = %+v, want %+v", tc.body, got, tc.want)
		}
	}
}

func TestErrorMembersTruncates(t *testing.T) {
	t.Parallel()
	x254, x256 := strings.Repeat(oneByte, excerptBytes-2), strings.Repeat(oneByte, excerptBytes)
	cases := []struct {
		body string
		want string
	}{
		{x256, x256},
		{x256 + "y", x256},
		{x254 + "\xff", x254},
		{x254 + " é", x254},
		{x254 + "xé", x254 + oneByte},
		{strings.Repeat(" ", padding) + downText, downText},
		{"\xff\t upstream down \xff", downText},
	}
	for _, tc := range cases {
		if _, description := errorMembers([]byte(tc.body)); description != tc.want {
			t.Fatalf("errorMembers(%q) description = %q, want %q", tc.body, description, tc.want)
		}
	}
	long := oneByte + strings.Repeat("é", 1<<16)
	code, description := errorMembers([]byte(`{"error":"` + long + `","error_description":"` + long + `"}`))
	for _, s := range []string{code, description} {
		if s != long[:excerptBytes-1] {
			t.Fatalf("JSON excerpt of %d bytes: %q, want the 255 bytes before the split rune", len(s), s)
		}
	}
}

// TestExcerptCopies pins the one allocation of an excerpt: the copy that
// frees the body.
func TestExcerptCopies(t *testing.T) {
	assertAllocs(t, 1, func() { excerpt("upstream unavailable for maintenance") })
}

// FuzzErrorMembers checks errorMembers against oauthError, a reference that
// picks the class of the body from the body itself.
func FuzzErrorMembers(f *testing.F) {
	for _, body := range []string{
		`{"error":"invalid_grant","error_description":"d"}`, `{"error":null}`, `{"ERROR":"x"}`, `{"error":"  "}`,
		`{"error":"a","error":"b"}`, "  upstream down", `{"error":"x","error_description":7}`, `{"error":"\ud800"}`,
		`{"error":"x","error_description":null}`, `{"error":7}`, `[{"error":"x"}]`,
		`{"error":"x","y":[{"k":1,"k":2}]}`, `{"error":"x","y":[{"k":1},{"k":2}]}`,
	} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		code, description := errorMembers([]byte(body))
		if got, want := (errorParts{code, description}), oauthError(t, body); got != want {
			t.Fatalf("errorMembers(%q) = %+v, want %+v", body, got, want)
		}
	})
}

// oauthError decodes with encoding/json a strict object whose error is a string
// and whose error_description is absent, null or a string into their excerpts,
// unless the code's is empty; any other body gives its own excerpt.
func oauthError(t *testing.T, body string) errorParts {
	t.Helper()
	plain := errorParts{description: excerptOf(body)}
	if !strictObject(body) {
		return plain
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatalf("encoding/json decoding %q, a strict object, = %v, want nil", body, err)
	}
	var code, description *string
	if json.Unmarshal(fields[ParamError], &code) != nil || code == nil {
		return plain
	}
	if raw, ok := fields[ParamErrorDescription]; ok && json.Unmarshal(raw, &description) != nil {
		return plain
	}
	want := errorParts{code: excerptOf(*code)}
	if want.code == "" {
		return plain
	}
	if description != nil {
		want.description = excerptOf(*description)
	}
	return want
}

// excerptOf is the documented excerpt of s, built rune by rune: the valid
// runes that end within the first 256 bytes after its leading space, trimmed.
func excerptOf(s string) string {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if i+n > excerptBytes {
			break
		}
		if r != utf8.RuneError || n > 1 {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return strings.TrimSpace(b.String())
}
