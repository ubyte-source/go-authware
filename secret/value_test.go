package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
)

// plain is a secret, and wantMask the text a non-zero Value renders as.
const (
	plain    = "hunter2-secret"
	wantMask = "***"
)

type holder struct {
	Exported Value
	hidden   Value
}

func TestNew(t *testing.T) {
	t.Parallel()
	v := New(plain)
	if v.Reveal() != plain || v.IsZero() || v.Len() != len(plain) {
		t.Fatalf("New(%q) = Reveal %q, IsZero %v, Len %d, want the secret, false, %d",
			plain, v.Reveal(), v.IsZero(), v.Len(), len(plain))
	}
	for _, empty := range []Value{New(""), {}} {
		if empty.Reveal() != "" || !empty.IsZero() || empty.Len() != 0 {
			t.Fatalf("empty value = Reveal %q, IsZero %v, Len %d, want empty, true, 0",
				empty.Reveal(), empty.IsZero(), empty.Len())
		}
	}
}

func TestValueIncomparable(t *testing.T) {
	t.Parallel()
	if reflect.TypeFor[Value]().Comparable() {
		t.Fatal(`Value godoc: "Values are not comparable": reflect.Type.Comparable = true, want false`)
	}
}

func TestValueFormat(t *testing.T) {
	t.Parallel()
	v := New(plain)
	h := holder{Exported: v, hidden: v}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10s", "%-8v"} {
		for _, arg := range []any{v, &v, h, &h, []Value{v}, map[string]Value{"k": v}} {
			out := fmt.Sprintf(verb, arg)
			if strings.Contains(out, plain) || strings.Contains(out, fmt.Sprintf("%x", plain)) {
				t.Fatalf("Sprintf(%s, %T) = %s, want no secret", verb, arg, out)
			}
		}
		if out := fmt.Sprintf(verb, v); out != wantMask {
			t.Fatalf("Sprintf(%s) = %q, want %q", verb, out, wantMask)
		}
	}
	if out := fmt.Sprintf("[%v]", Value{}); out != "[]" {
		t.Fatalf("Sprintf([%%v], Value{}) = %q, want []", out)
	}
}

// TestValueFormatUncalled formats a Value with the verbs fmt handles before it
// calls Format: %T prints the type, and %p and %w, from a variable vet would
// refuse as a constant, print the address the Value holds, never the secret.
func TestValueFormatUncalled(t *testing.T) {
	t.Parallel()
	v := New(plain)
	if out, want := fmt.Sprintf("%T", v), "secret.Value"; out != want {
		t.Errorf("package comment and Value godoc: fmt prints its type for %%T; Format godoc: fmt calls it "+
			"for every verb but %%T, %%p and %%w: Sprintf(%%T) = %q, want %q", out, want)
	}
	for _, verb := range []string{"%p", "%w"} {
		prefix := "%!" + verb[1:] + "(secret.Value={[] 0x"
		if out := fmt.Sprintf(verb, v); !strings.HasPrefix(out, prefix) || strings.Contains(out, plain) {
			t.Errorf("Value godoc: fmt prints \"the address it holds for %%p, %%w and in an unexported field\": "+
				"%s: got %q, want the prefix %q and no secret", verb, out, prefix)
		}
	}
}

func TestValueString(t *testing.T) {
	t.Parallel()
	if got := New(plain).String(); got != wantMask {
		t.Fatalf("String = %q, want %q", got, wantMask)
	}
	if got := New(plain).GoString(); got != wantMask {
		t.Fatalf("GoString = %q, want %q", got, wantMask)
	}
	if got := New("").String() + New("").GoString(); got != "" {
		t.Fatalf("String and GoString of the zero Value = %q, want empty", got)
	}
}

func TestValueLogValue(t *testing.T) {
	t.Parallel()
	v := New(plain)
	var buf bytes.Buffer
	h := holder{Exported: v, hidden: v}
	for _, handler := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		logger := slog.New(handler)
		logger.Info("boot", slog.Any("token", v), slog.Group("cfg", slog.Any("secret", v)), slog.Any("holder", h),
			slog.Any("ptr", &v))
		logger.Info("any", slog.Any("holder", &h))
	}
	out := buf.String()
	if strings.Contains(out, plain) {
		t.Fatalf("slog output = %s, want no secret", out)
	}
	if !strings.Contains(out, "token="+wantMask) || !strings.Contains(out, `"token":"`+wantMask+`"`) {
		t.Fatalf("slog output = %s, want the mask in text and JSON", out)
	}
	if got := v.LogValue(); got.Kind() != slog.KindString || got.String() != wantMask {
		t.Fatalf("LogValue = %v, want the string %q", got, wantMask)
	}
	if got := New("").LogValue().String(); got != "" {
		t.Fatalf("LogValue of the zero Value = %q, want empty", got)
	}
}

// TestValueMarshalTextEncodesJSON writes the mask, quoted, wherever a JSON
// encoder meets a Value: a field, an empty Value and a pointer.
func TestValueMarshalTextEncodesJSON(t *testing.T) {
	t.Parallel()
	out, err := json.Marshal(struct {
		Token Value  `json:"token"`
		Empty Value  `json:"empty"`
		Ptr   *Value `json:"ptr"`
	}{Token: New(plain), Ptr: &Value{}})
	if err != nil {
		t.Fatalf("Marshal = %v, want JSON", err)
	}
	if want := `{"token":"***","empty":"","ptr":""}`; string(out) != want {
		t.Fatalf("json = %s, want %s", out, want)
	}
}

func TestValueMarshalText(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		v    Value
		want string
	}{{New(plain), wantMask}, {Value{}, ""}} {
		got, err := c.v.MarshalText()
		if err != nil || string(got) != c.want {
			t.Fatalf("MarshalText = %q, %v; want %q", got, err, c.want)
		}
	}
}

func TestValueEqual(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b  string
		equal bool
	}{
		{plain, plain, true},
		{"", "", true},
		{plain, plain + "x", false},
		{plain, "hunter3-secret", false},
		{plain, "", false},
		{"", plain, false},
	}
	for _, tc := range cases {
		if got := New(tc.a).Equal(New(tc.b)); got != tc.equal {
			t.Fatalf("Equal(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.equal)
		}
	}
	if !New("").Equal(Value{}) {
		t.Fatal("New(\"\").Equal(Value{}) = false, want true")
	}
}

func ExampleNew() {
	token := New("s3cr3t")
	fmt.Println(token, token.Len(), token.Reveal())
	slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})).Info("call", slog.Any("token", token))
	// Output:
	// *** 6 s3cr3t
	// level=INFO msg=call token=***
}

// tokenBytes is the length of a typical access token.
const tokenBytes = 1024

// TestValueAllocs reads and compares secrets as long as an access token:
// Reveal returns the stored string and Equal compares in place.
func TestValueAllocs(t *testing.T) {
	token := strings.Repeat("k", tokenBytes)
	v, same := New(token), New(token)
	assertAllocs(t, 0, func() {
		if len(v.Reveal()) != tokenBytes {
			t.Fatalf("Reveal = %d bytes, want %d", len(v.Reveal()), tokenBytes)
		}
	})
	assertAllocs(t, 0, func() {
		if !v.Equal(same) {
			t.Fatal("Equal(same text) = false, want true")
		}
	})
}

// benchValue benchmarks read after checking that it returns want.
func benchValue[T comparable](b *testing.B, name string, read func() T, want T) {
	b.Helper()
	b.Run(name, func(b *testing.B) {
		if got := read(); got != want {
			b.Fatalf("%s of a %d-byte secret = %v, want %v", name, tokenBytes, got, want)
		}
		b.ReportAllocs()
		for b.Loop() {
			read()
		}
	})
}

func BenchmarkValue(b *testing.B) {
	token := strings.Repeat("k", tokenBytes)
	v, same := New(token), New(token)
	benchValue(b, "Reveal", v.Reveal, token)
	benchValue(b, "Equal", func() bool { return v.Equal(same) }, true)
}
