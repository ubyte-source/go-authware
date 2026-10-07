package jsonobj

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// A \\u escape of a UTF-16 unit in hex, and the members of the test object.
const (
	uEscapeLen  = 6
	hexBase     = 16
	utf16Bits   = 16
	wantMembers = 4
)

var (
	errTest = errors.New("test: invalid")
	errStop = errors.New("test: stop")
)

const (
	repeatedName = `{"a":1,"a":2}`
	jsonNull     = "null"
)

// levels is the documented nesting bound, the top object included.
const levels = 32

// sharedNames is a document whose objects share names but repeat none.
const sharedNames = `{"k":{"k":{"k":1}},"a":[{"k":1},{"k":[{"k":2}]}]}`

// nest returns n nested arrays.
func nest(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }

// memberPairs lists the name=value pairs Iterate hands over for body.
func memberPairs(body string) ([]string, error) {
	var got []string
	err := Iterate(body, errTest, func(name, value string) error {
		got = append(got, name+"="+value)
		return nil
	})
	return got, err
}

func TestIterate(t *testing.T) {
	t.Parallel()
	got, err := memberPairs(" \t\r\n{\"a\":\"x\",\"b\\u0063\":[1,{\"n\":null}],\"e\":{}} \n")
	want := []string{`a="x"`, `bc=[1,{"n":null}]`, `e={}`}
	if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("Iterate = %q, %v, want %q", got, err, want)
	}
	if got, err := memberPairs(`{}`); err != nil || len(got) != 0 {
		t.Fatalf("Iterate({}) = %q, %v, want no member", got, err)
	}
	if got, err := memberPairs(`{"a":` + nest(levels-1) + `}`); err != nil || len(got) != 1 {
		t.Fatalf("Iterate(%d levels) = %q, %v, want one member", levels, got, err)
	}
	// A name may repeat in different objects.
	if got, err := memberPairs(sharedNames); err != nil || len(got) != 2 {
		t.Fatalf("Iterate(%s) = %q, %v, want two members", sharedNames, got, err)
	}
}

func TestIterateRejects(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		``, `null`, `42`, `["a"]`, nest(levels), nest(levels + 1),
		`{"a":"x"`, `{"a":"x",}`, `{a:"x"}`, `{"a":"x"} {"b":"y"}`, `{"a":tru}`, `{"a":01}`,
		`{"a":"\x"}`, "{\"a\":\"x\ty\"}", "{\"a\":\"\xff\"}", "{\"\x87\":[]}",
		`{"a":"\ud800"}`, `{"\udc00":1}`, `{"a":` + nest(levels) + `}`,
		repeatedName, `{"a":1,"\u0061":2}`, `{"r":{"k":1,"k":2}}`, `{"r":{"o":{"k":1,"\u006b":2}}}`,
		`{"r":[{"k":1,"k":2}]}`, `{"r":{"a":[1,[{"o":{"k":1,"k":2}}]]}}`, `{"r":{"k":1,"k":2},"x":tru}`,
	} {
		if _, err := memberPairs(body); !errors.Is(err, errTest) || err.Error() != errTest.Error() {
			t.Errorf("Iterate(%q) err = %v, want errTest itself", body, err)
		}
	}
}

// TestIterateRefusalAllocs refuses, without allocating, a document of each fault whose
// walk allocates nothing: no JSON, no object, nested too deep, a name repeated.
func TestIterateRefusalAllocs(t *testing.T) {
	fn := func(_, _ string) error { return nil }
	for _, body := range []string{
		`{"a":"x",}`, `["a"]`, arrayDocument(1, levels-1), repeatedName, `{"r":{"k":1,"k":2}}`,
	} {
		assertAllocs(t, 0, func() {
			if err := Iterate(body, errTest, fn); !errors.Is(err, errTest) {
				t.Fatalf("Iterate(%q) = %v, want errTest", body, err)
			}
		})
	}
}

func TestRefusal(t *testing.T) {
	t.Parallel()
	refused := Refusal(errTest)
	want := errTest.Error() + ": not one UTF-8 JSON object nested at most " + strconv.Itoa(levels) +
		" deep in which no object repeats a name"
	if !errors.Is(refused, errTest) || refused.Error() != want {
		t.Fatalf("Refusal(errTest) = %v, want %q wrapping errTest", refused, want)
	}
	if err := Iterate(repeatedName, refused, func(_, _ string) error { return nil }); !errors.Is(err, errTest) ||
		err.Error() != want {
		t.Fatalf("Iterate(%s, Refusal(errTest)) = %v, want %q", repeatedName, err, want)
	}
}

func TestIterateCallbackError(t *testing.T) {
	t.Parallel()
	calls := 0
	err := Iterate(`{"a":1,"b":2}`, errTest, func(_, _ string) error {
		calls++
		return errStop
	})
	if !errors.Is(err, errStop) || errors.Is(err, errTest) || calls != 1 {
		t.Fatalf("Iterate = %v after %d calls, want errStop alone after 1", err, calls)
	}
}

func TestIterateManyMembers(t *testing.T) {
	t.Parallel()
	const many = 100
	parts := make([]string, 0, many+1)
	for i := range many {
		parts = append(parts, `"a`+strconv.Itoa(i)+`":0`)
	}
	body := "{" + strings.Join(parts, ",") + "}"
	if got, err := memberPairs(body); err != nil || len(got) != many {
		t.Fatalf("Iterate over %d distinct members = %d, %v; want all", many, len(got), err)
	}
	repeat := "{" + strings.Join(append(parts, `"a`+strconv.Itoa(many-1)+`":1`), ",") + "}"
	if _, err := memberPairs(repeat); !errors.Is(err, errTest) {
		t.Fatalf("Iterate with member %d repeated = %v, want errTest", many-1, err)
	}
}

// Shape and bounds of TestIterateCostIsLinear: a document holds costItems empty arrays,
// or costScale times as many, nested 1 or levels-2 arrays deep; a run over the larger
// may take costMargin*costScale times as long, and over the deeper costMargin times.
const (
	costItems    = 1 << 12
	costScale    = 8
	costMargin   = 3
	costTrials   = 5
	costAttempts = 3
)

// arrayDocument returns an object whose one member holds items empty arrays inside
// depth nested arrays, so the document is levels deep at depth levels-2.
func arrayDocument(items, depth int) string {
	return `{"items":` + strings.Repeat("[", depth) + strings.Repeat("[],", items-1) + "[]" +
		strings.Repeat("]", depth) + "}"
}

// fastestRun returns the time of the fastest of costTrials runs of Iterate over body.
func fastestRun(t *testing.T, body string) time.Duration {
	t.Helper()
	var fastest time.Duration
	for trial := range costTrials {
		start := time.Now()
		if err := Iterate(body, errTest, func(_, _ string) error { return nil }); err != nil {
			t.Fatalf("Iterate(%.40q) = %v, want nil", body, err)
		}
		if elapsed := time.Since(start); trial == 0 || elapsed < fastest {
			fastest = elapsed
		}
	}
	return fastest
}

func TestIterateCostIsLinear(t *testing.T) {
	shallow, deep := arrayDocument(costItems, 1), arrayDocument(costItems, levels-2)
	large := arrayDocument(costScale*costItems, levels-2)
	if raceEnabled() {
		fastestRun(t, large)
		return
	}
	var got string
	for range costAttempts {
		base, deeper, larger := fastestRun(t, shallow), fastestRun(t, deep), fastestRun(t, large)
		if deeper <= costMargin*base && larger <= costMargin*costScale*deeper {
			return
		}
		got = deeper.String() + " deep and " + larger.String() + " for " + strconv.Itoa(costScale) +
			" times the items, against " + base.String()
	}
	t.Errorf("Iterate took %s, want at most %d and %d times (PERF-3.1: O(n) at any depth)",
		got, costMargin, costMargin*costScale)
}

// escapedSiblings returns an object whose one member holds n objects in an array,
// each named "k" by an escape, so Iterate decodes n names but holds one at a time.
func escapedSiblings(n int) string {
	return `{"a":[` + strings.Repeat(`{"\u006b":0},`, n-1) + `{"\u006b":0}]}`
}

func TestIterateAllocsFollowTheOpenNames(t *testing.T) {
	fn := func(_, _ string) error { return nil }
	for _, n := range []int{costItems, costScale * costItems} {
		body := escapedSiblings(n)
		assertAllocs(t, 1, func() {
			if err := Iterate(body, errTest, fn); err != nil {
				t.Fatalf("Iterate(%d escaped siblings) = %v, want nil", n, err)
			}
		})
	}
}

func TestIterateAllocs(t *testing.T) {
	body := `{"access_token":"t","token_type":"Bearer","expires_in":3600,"scope":"a b","x":[{"k":{"k":1}},{"k":2}]}`
	fn := func(_, _ string) error { return nil }
	assertAllocs(t, 0, func() {
		if err := Iterate(body, errTest, fn); err != nil {
			t.Fatalf("Iterate = %v, want nil", err)
		}
	})
}

func TestString(t *testing.T) {
	t.Parallel()
	if s, err := String("kid", `"k\u0031"`, errTest); err != nil || s != "k1" {
		t.Fatalf(`String("k1") = %q, %v, want k1`, s, err)
	}
	s, err := String("kid", `7`, errTest)
	if want := "test: invalid: kid is not a string"; s != "" || err == nil || err.Error() != want {
		t.Fatalf("String(7) = %q, %v, want %q", s, err, want)
	}
	if !errors.Is(err, errTest) {
		t.Fatalf("String(7) err = %v, want errTest", err)
	}
}

// loneSurrogate reports whether the JSON text raw, which holds no escaped
// backslash outside strings, escapes a surrogate that is not half of a pair.
func loneSurrogate(raw string) bool {
	var units []rune
	for i := 0; i < len(raw); i++ {
		unit := rune(0)
		if strings.HasPrefix(raw[i:], `\u`) {
			v, err := strconv.ParseUint(raw[i+len(`\u`):i+uEscapeLen], hexBase, utf16Bits)
			if err != nil {
				return true
			}
			unit = rune(v)
			i += uEscapeLen - 1
		} else if raw[i] == '\\' {
			i++
		}
		units = append(units, unit)
	}
	for i := 0; i < len(units); i++ {
		if !utf16.IsSurrogate(units[i]) {
			continue
		}
		if i+1 == len(units) || utf16.DecodeRune(units[i], units[i+1]) == utf8.RuneError {
			return true
		}
		i++
	}
	return false
}

// referenceMember is a top-level member as encoding/json reads it.
type referenceMember struct {
	name  string
	value json.RawMessage
}

// String renders m as its quoted name, a colon and its value.
func (m referenceMember) String() string {
	return strconv.Quote(m.name) + ":" + string(m.value)
}

// referenceDepth returns how deep the valid JSON document data nests.
func referenceDepth(data string) int {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	depth, deepest := 0, 0
	for tok, err := dec.Token(); err == nil; tok, err = dec.Token() {
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
			deepest = max(deepest, depth)
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return deepest
}

// referenceMembers reads the top-level members of the valid JSON object data.
func referenceMembers(data string) []referenceMember {
	dec := json.NewDecoder(strings.NewReader(data))
	if _, err := dec.Token(); err != nil {
		return nil
	}
	var members []referenceMember
	for dec.More() {
		tok, err := dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok {
			break
		}
		m := referenceMember{name: name}
		if err = dec.Decode(&m.value); err != nil {
			break
		}
		members = append(members, m)
	}
	return members
}

// referenceIterate returns the members Iterate must hand over for data, or
// false when it must refuse data.
func referenceIterate(data string) ([]referenceMember, bool) {
	if !json.Valid([]byte(data)) || !strings.HasPrefix(strings.TrimLeft(data, " \t\r\n"), "{") ||
		!utf8.ValidString(data) || loneSurrogate(data) || referenceDepth(data) > levels {
		return nil, false
	}
	return referenceMembers(data), !repeatsAnyName(json.NewDecoder(strings.NewReader(data)))
}

// repeatsAnyName reads the next value of dec, which decodes valid JSON, and
// reports whether an object in that value repeats a name.
func repeatsAnyName(dec *json.Decoder) bool {
	open, err := dec.Token()
	if err != nil || open != json.Delim('{') && open != json.Delim('[') {
		return false
	}
	names, repeated := map[string]bool{}, false
	for dec.More() {
		if open == json.Delim('{') {
			name := referenceName(dec)
			repeated = repeated || names[name]
			names[name] = true
		}
		repeated = repeatsAnyName(dec) || repeated
	}
	if _, err := dec.Token(); err != nil {
		return false
	}
	return repeated
}

// referenceName reads the next member name of dec, which decodes valid JSON.
func referenceName(dec *json.Decoder) string {
	tok, err := dec.Token()
	if name, ok := tok.(string); ok && err == nil {
		return name
	}
	return ""
}

func FuzzIterate(f *testing.F) {
	for _, s := range []string{
		`{}`, ` {"a":"x","b\u0063":[1,{"n":null}]} `, repeatedName, `{"a":1,"\u0061":2}`,
		`{"\ud800":1}`, `{"\ud83d\ude00":1}`, `{"a":"\ud800"}`, `{"a":"\\ud800"}`, `{"a":` + nest(levels-1) + `}`,
		`{"a":` + nest(levels) + `}`, `[1]`, `{"a":1}}`, `]{}`, "{\"a\":\"\xff\"}",
		`{"o":{"b":"x\u0079","b\u0063":null},"r":{"k":1,"\u006b":2},"n":null,"s":"t\tu","e":{}}`,
		`{"o":{"b":"x\u0079","b\u0063":null},"n":null,"s":"t\tu","e":{}}`, sharedNames,
		`{"r":[{"k":1,"k":2}]}`, `{"r":{"a":[1,[{"o":{"k":1,"\u006b":2}}]]}}`,
		"{\"a\" : [1, 2 ] ,\"o\":\n\t{ \"b\" : [ \"x\" ,\n3 ] } }",
		`{"x":1e400,"a":` + nest(levels) + `,"z":0}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		members, want := referenceIterate(data)
		var got []referenceMember
		err := Iterate(data, errTest, func(name, value string) error {
			got = append(got, referenceMember{name: name, value: json.RawMessage(value)})
			return nil
		})
		if (err == nil) != want || (err != nil && (!errors.Is(err, errTest) || err.Error() != errTest.Error())) {
			t.Fatalf("Iterate(%q) = %v, want accepted %v, else errTest itself", data, err, want)
		}
		if err == nil && !sameMembers(got, members) {
			t.Fatalf("Iterate(%q) handed %v, want %v", data, got, members)
		}
		for _, m := range got {
			checkMember(t, m.name, string(m.value))
		}
	})
}

// checkMember fails unless String, CopyString and, for an object, Iterate read value, a
// member of a document Iterate accepted, as encoding/json does.
func checkMember(t *testing.T, name, value string) {
	t.Helper()
	checkString(t, name, value)
	checkCopyString(t, name, value)
	if value[0] == '{' {
		checkNested(t, value)
	}
}

// referenceString decodes value with encoding/json, false when it is no string.
func referenceString(value string) (string, bool) {
	var s string
	return s, value[0] == '"' && json.Unmarshal([]byte(value), &s) == nil
}

// checkString fails unless String decodes a string value as encoding/json does
// and refuses any other value.
func checkString(t *testing.T, name, value string) {
	t.Helper()
	want, ok := referenceString(value)
	got, err := String(name, value, errTest)
	if ok && (err != nil || got != want) || !ok && (got != "" || !errors.Is(err, errTest)) {
		t.Fatalf("String(%s) = %q, %v; want %q, a string %t", value, got, err, want, ok)
	}
}

// checkCopyString fails unless CopyString copies a string value as
// encoding/json decodes it, keeps its destination for null and refuses any
// other value.
func checkCopyString(t *testing.T, name, value string) {
	t.Helper()
	const unset = "kept"
	want, ok := referenceString(value)
	if !ok {
		want = unset
	}
	got := unset
	err := CopyString(&got, name, value, errTest)
	accepted := ok || value == jsonNull
	if got != want || accepted != (err == nil) || err != nil && !errors.Is(err, errTest) {
		t.Fatalf("CopyString(%s) = %q, %v; want %q, accepted %t", value, got, err, want, accepted)
	}
}

// checkNested fails unless Iterate accepts obj, an object of a document Iterate
// accepted, and hands over its members as encoding/json reads them.
func checkNested(t *testing.T, obj string) {
	t.Helper()
	members := referenceMembers(obj)
	var got []referenceMember
	err := Iterate(obj, errTest, func(name, value string) error {
		got = append(got, referenceMember{name: name, value: json.RawMessage(value)})
		return nil
	})
	if err != nil || !sameMembers(got, members) {
		t.Fatalf("Iterate(%s) = %v, %v; want %v", obj, got, err, members)
	}
}

// sameMembers reports whether got and want name the same members in order,
// with the same raw values, byte for byte.
func sameMembers(got, want []referenceMember) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i].name != want[i].name || string(got[i].value) != string(want[i].value) {
			return false
		}
	}
	return true
}

func BenchmarkIterate(b *testing.B) {
	body := `{"access_token":"t","token_type":"Bearer","expires_in":3600,"scope":"a b"}`
	members := 0
	fn := func(_, _ string) error {
		members++
		return nil
	}
	if err := Iterate(body, errTest, fn); err != nil || members != wantMembers {
		b.Fatalf("Iterate = %v after %d members, want nil after 4", err, members)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := Iterate(body, errTest, fn); err != nil {
			b.Fatalf("Iterate = %v, want nil", err)
		}
	}
}

// testName is the member name of the CopyString tests.
const testName = "scope"

func TestCopyString(t *testing.T) {
	t.Parallel()
	const tabbed = "a\tb"
	var s string
	if err := CopyString(&s, testName, `"a\tb"`, errTest); err != nil || s != tabbed {
		t.Fatalf("CopyString = %q, %v, want %q", s, err, tabbed)
	}
	if err := CopyString(&s, testName, jsonNull, errTest); err != nil || s != tabbed {
		t.Fatalf("CopyString(null) = %q, %v; want s untouched", s, err)
	}
	err := CopyString(&s, testName, "7", errTest)
	if !errors.Is(err, errTest) || err.Error() != errTest.Error()+": "+testName+" is not a string" || s != tabbed {
		t.Fatalf("CopyString(7) = %q, %v; want errTest and s untouched", s, err)
	}
}

// TestCopyStringCopies pins the one allocation of a plain value: the copy that
// frees the body.
func TestCopyStringCopies(t *testing.T) {
	var s string
	plain := `"a plain value of 32 bytes, long"`
	assertAllocs(t, 1, func() {
		if err := CopyString(&s, testName, plain, errTest); err != nil {
			t.Fatalf("CopyString(%s) = %v, want nil", plain, err)
		}
	})
}
