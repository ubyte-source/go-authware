package authware

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// testMissing names a claim no fixture holds.
const testMissing = "missing"

// claimsIdentity returns an OAuth identity carrying the JSON object claims.
func claimsIdentity(claims string) *Identity {
	return &Identity{mode: ModeOAuth, subject: testUser, scopes: []string{testRead}, claims: claims}
}

func TestIdentityAccessors(t *testing.T) {
	cert := &x509.Certificate{}
	id := &Identity{mode: ModeMTLS, subject: testUser, scopes: []string{testRead}, peer: cert}
	if id.Subject() != testUser || id.Mode() != ModeMTLS || id.PeerCertificate() != cert {
		t.Fatalf("accessors = %q %q %p, want %q %q %p", id.Subject(), id.Mode(), id.PeerCertificate(), testUser,
			ModeMTLS, cert)
	}
	if granted := []bool{id.HasScope(testRead), id.HasScope(testWrite)}; !slices.Equal(granted, []bool{true, false}) {
		t.Fatalf("HasScope(read, write) = %v, want [true false]", granted)
	}
	scopes := id.Scopes()
	if len(scopes) != 1 {
		t.Fatalf("Scopes = %v, want one scope", scopes)
	}
	scopes[0] = testAdmin
	if !slices.Equal(id.Scopes(), []string{testRead}) {
		t.Fatalf("Scopes after the caller edits its copy = %v, want [%s]", id.Scopes(), testRead)
	}
}

func TestIdentityNilReceiver(t *testing.T) {
	var id *Identity
	if id.Subject() != "" || id.Mode() != "" || id.Scopes() != nil || id.HasScope(testRead) ||
		id.PeerCertificate() != nil {
		t.Fatalf("accessors of a nil Identity = %q %q %v %t %v, want zero values", id.Subject(), id.Mode(),
			id.Scopes(), id.HasScope(testRead), id.PeerCertificate())
	}
	if v, ok := id.Claim(claimSub); ok || v != nil {
		t.Fatalf("Claim of a nil Identity = %#v, %v, want nil, false", v, ok)
	}
	for name := range id.Claims() {
		t.Fatalf("Claims of a nil Identity yielded %q, want no claim", name)
	}
}

// Claim names and values of the accessor tests.
const (
	nameInt     = "i"
	nameFloat   = "f"
	nameString  = "s"
	claimInt    = 7
	claimFloat  = 1.5
	negativeInt = 42
	exactFloat  = 2.25
	intAsFloat  = 3
)

func TestIdentityClaim(t *testing.T) {
	id := claimsIdentity(`{"s":"a\"b","i":7,"f":1.5,"t":true,"n":null,"o":{"k":1},"a":[1,2],"u\u0073":"esc"}`)
	tests := []struct {
		name string
		want any
	}{
		{nameString, `a"b`}, {nameInt, int64(claimInt)}, {nameFloat, claimFloat}, {"t", true}, {"n", nil},
		{"o", `{"k":1}`}, {"a", `[1,2]`}, {"us", "esc"},
	}
	for _, tc := range tests {
		got, ok := id.Claim(tc.name)
		if !ok || got != tc.want {
			t.Errorf("Claim(%q) = %#v, %v, want %#v, true", tc.name, got, ok, tc.want)
		}
	}
	if v, ok := id.Claim(testMissing); ok || v != nil {
		t.Errorf("Claim(missing) = %#v, %v, want nil, false", v, ok)
	}
}

func TestIdentityClaimString(t *testing.T) {
	id := claimsIdentity(`{"s":"x\u0041","i":7,"b":"true"}`)
	if v, ok := id.ClaimString(nameString); !ok || v != "xA" {
		t.Errorf("ClaimString(s) = %q, %v, want xA, true", v, ok)
	}
	for _, name := range []string{nameInt, testMissing} {
		if v, ok := id.ClaimString(name); ok || v != "" {
			t.Errorf("ClaimString(%q) = %q, %v, want \"\", false", name, v, ok)
		}
	}
}

func TestIdentityClaimInt64(t *testing.T) {
	id := claimsIdentity(`{"i":-42,"f":1.5,"s":"7","e":1e2,"h":9223372036854775808}`)
	if v, ok := id.ClaimInt64(nameInt); !ok || v != -negativeInt {
		t.Errorf("ClaimInt64(i) = %d, %v, want -42, true", v, ok)
	}
	for _, name := range []string{nameFloat, nameString, "e", "h", testMissing} {
		if v, ok := id.ClaimInt64(name); ok || v != 0 {
			t.Errorf("ClaimInt64(%q) = %d, %v, want 0, false", name, v, ok)
		}
	}
}

func TestIdentityClaimFloat64(t *testing.T) {
	id := claimsIdentity(`{"f":2.25,"i":3,"s":"1.5","h":1e400}`)
	if v, ok := id.ClaimFloat64(nameFloat); !ok || v != exactFloat {
		t.Errorf("ClaimFloat64(f) = %v, %v, want 2.25, true", v, ok)
	}
	if v, ok := id.ClaimFloat64(nameInt); !ok || v != intAsFloat {
		t.Errorf("ClaimFloat64(i) = %v, %v, want 3, true", v, ok)
	}
	for _, name := range []string{nameString, "h", testMissing} {
		if v, ok := id.ClaimFloat64(name); ok || math.Float64bits(v) != 0 {
			t.Errorf("ClaimFloat64(%q) = %v, %v, want +0, false", name, v, ok)
		}
	}
}

func TestIdentityClaimBool(t *testing.T) {
	id := claimsIdentity(`{"t":true,"f":false,"s":"true","n":null}`)
	if v, ok := id.ClaimBool("t"); !ok || !v {
		t.Errorf("ClaimBool(t) = %v, %v, want true, true", v, ok)
	}
	if v, ok := id.ClaimBool(nameFloat); !ok || v {
		t.Errorf("ClaimBool(f) = %v, %v, want false, true", v, ok)
	}
	for _, name := range []string{nameString, "n", testMissing} {
		if v, ok := id.ClaimBool(name); ok || v {
			t.Errorf("ClaimBool(%q) = %v, %v, want false, false", name, v, ok)
		}
	}
}

// TestWithIdentityKeepsTheContext stores the identity in a child of the
// context it gets.
func TestWithIdentityKeepsTheContext(t *testing.T) {
	id := scoped(testRead)
	ctx := WithIdentity(marked(t), id)
	if got, ok := IdentityFromContext(ctx); !ok || got != id || !isMarked(ctx) {
		t.Fatalf("WithIdentity = identity %v (%t), marked %t; want the identity in the caller's context", got, ok,
			isMarked(ctx))
	}
}

func TestIdentityClaims(t *testing.T) {
	id := claimsIdentity(`{"a":1,"b\u0063":"x","c":true}`)
	got := maps.Collect(id.Claims())
	if want := map[string]any{"a": int64(1), "bc": "x", "c": true}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Claims = %v, want %v", got, want)
	}
	var names []string
	for name := range id.Claims() {
		names = append(names, name)
		if name == "bc" {
			break
		}
	}
	if !slices.Equal(names, []string{"a", "bc"}) {
		t.Fatalf("Claims names up to a break at bc = %v, want [a bc]", names)
	}
	for name := range (&Identity{mode: ModeBearer, subject: testUser}).Claims() {
		t.Fatalf("Claims of an identity without a token yielded %q, want no claim", name)
	}
}

// claimsAllocs is the cost of a walk of Claims over scoped's scopedClaims claims:
// the boxed string and float; small integers and booleans box for free.
const (
	claimsAllocs = 2
	scopedClaims = 4
)

// TestIdentityAccessorsAllocs pins the cost of each accessor: Scopes copies
// the scopes, Claim boxes a string value, and the others allocate nothing.
func TestIdentityAccessorsAllocs(t *testing.T) {
	id := scoped(testRead)
	var (
		text   string
		scopes []string
		value  any
		ok     bool
	)
	assertAllocs(t, 0, func() { text = id.Subject() })
	assertAllocs(t, 0, func() { text = string(id.Mode()) })
	assertAllocs(t, 1, func() { scopes = id.Scopes() })
	assertAllocs(t, 0, func() { ok = id.HasScope(testRead) })
	assertAllocs(t, 0, func() { ok = id.PeerCertificate() == nil })
	assertAllocs(t, 1, func() { value, ok = id.Claim(claimTeam) })
	assertAllocs(t, 0, func() { text, ok = id.ClaimString(claimTeam) })
	assertAllocs(t, 0, func() { _, ok = id.ClaimInt64(claimLvl) })
	assertAllocs(t, 0, func() { _, ok = id.ClaimFloat64(claimRatio) })
	assertAllocs(t, 0, func() { _, ok = id.ClaimBool(claimOn) })
	walked := 0
	assertAllocs(t, claimsAllocs, func() {
		walked = 0
		for range id.Claims() {
			walked++
		}
	})
	if text != testTeam || !ok || value != testTeam || !slices.Equal(scopes, []string{testRead}) ||
		walked != scopedClaims {
		t.Fatalf("accessors = %q, %v, %v, %v, %d claims; want %s, true, %s, [%s], %d", text, ok, value, scopes,
			walked, testTeam, testTeam, testRead, scopedClaims)
	}
}

// claimRead is what a claim accessor returns: the value and whether it is
// there.
type claimRead[T any] struct {
	claimValue T
	claimFound bool
}

func claimReadOf[T any](v T, found bool) claimRead[T] { return claimRead[T]{v, found} }

// benchAccessor benchmarks read on scoped(testRead) after checking that it
// returns expected.
func benchAccessor[T any](b *testing.B, name string, read func() T, expected T) {
	b.Helper()
	b.Run(name, func(b *testing.B) {
		if got := read(); !reflect.DeepEqual(got, expected) {
			b.Fatalf("%s of scoped(%s) = %v, want %v", name, testRead, got, expected)
		}
		b.ReportAllocs()
		for b.Loop() {
			read()
		}
	})
}

// BenchmarkIdentity reads each accessor of an OAuth identity.
func BenchmarkIdentity(b *testing.B) {
	id := scoped(testRead)
	benchAccessor(b, "Subject", id.Subject, testUser)
	benchAccessor(b, "Mode", id.Mode, ModeOAuth)
	benchAccessor(b, "Scopes", id.Scopes, []string{testRead})
	benchAccessor(b, "HasScope", func() bool { return id.HasScope(testRead) }, true)
	benchAccessor(b, "PeerCertificate", id.PeerCertificate, nil)
	benchAccessor(b, "Claim", func() claimRead[any] { return claimReadOf(id.Claim(claimTeam)) },
		claimRead[any]{testTeam, true})
	benchAccessor(b, "ClaimString", func() claimRead[string] { return claimReadOf(id.ClaimString(claimTeam)) },
		claimRead[string]{testTeam, true})
	benchAccessor(b, "ClaimInt64", func() claimRead[int64] { return claimReadOf(id.ClaimInt64(claimLvl)) },
		claimRead[int64]{lvl, true})
	benchAccessor(b, "ClaimFloat64", func() claimRead[float64] { return claimReadOf(id.ClaimFloat64(claimRatio)) },
		claimRead[float64]{ratio, true})
	benchAccessor(b, "ClaimBool", func() claimRead[bool] { return claimReadOf(id.ClaimBool(claimOn)) },
		claimRead[bool]{true, true})
	benchAccessor(b, "Claims", func() map[string]any { return maps.Collect(id.Claims()) },
		map[string]any{claimLvl: int64(5), claimRatio: 0.5, claimTeam: testTeam, claimOn: true})
}

func TestDecodeClaimValue(t *testing.T) {
	for raw, want := range claimValues() {
		if got := decodeClaimValue(raw); !sameValue(got, want) {
			t.Errorf("decodeClaimValue(%q) = %#v, want %#v", raw, got, want)
		}
	}
}

func TestWithIdentity(t *testing.T) {
	id := &Identity{mode: ModeNone}
	got, ok := IdentityFromContext(WithIdentity(context.Background(), id))
	if !ok || got != id {
		t.Fatalf("IdentityFromContext = %v, %v, want %v, true", got, ok, id)
	}
}

func TestIdentityFromContext(t *testing.T) {
	if id, ok := IdentityFromContext(context.Background()); ok || id != nil {
		t.Fatalf("IdentityFromContext(empty) = %v, %v, want nil, false", id, ok)
	}
	if id, ok := IdentityFromContext(WithIdentity(context.Background(), nil)); ok || id != nil {
		t.Fatalf("IdentityFromContext(nil identity) = %v, %v, want nil, false", id, ok)
	}
}

// FuzzDecodeClaimValue checks every JSON value that claims validation accepts,
// without surrounding space, against encoding/json: strings, booleans and null
// decode alike, an int64 wins over a float64, and anything else is JSON text.
func FuzzDecodeClaimValue(f *testing.F) {
	seeds := []string{`"hello"`, `"\ud800"`, `"\ufffd"`, "\"\ufffd\"", `123`, `-9.9`, `1e400`, `true`, jsonNull,
		`{"a":1}`}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if !json.Valid([]byte(raw)) || !utf8.ValidString(raw) || hasLoneSurrogate(raw) ||
			len(strings.TrimSpace(raw)) != len(raw) {
			return
		}
		if got, want := decodeClaimValue(raw), referenceClaimValue(t, raw); !sameValue(got, want) {
			t.Fatalf("decodeClaimValue(%s) = %#v, want %#v", raw, got, want)
		}
	})
}

// referenceClaimValue decodes raw with encoding/json to a string, int64, float64,
// bool or nil, else returns raw.
func referenceClaimValue(t *testing.T, raw string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("Decode(%s) = %v, want a JSON value", raw, err)
	}
	switch v := v.(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
		return raw
	case map[string]any, []any:
		return raw
	}
	return v
}

// ExampleIdentityFromContext reads the identity WithIdentity stored in the request
// context.
func ExampleIdentityFromContext() {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, pathRoot, http.NoBody)
	r = r.WithContext(WithIdentity(r.Context(), scoped("orders.read")))
	id, ok := IdentityFromContext(r.Context())
	fmt.Println(ok, id.Subject(), id.Mode(), id.Scopes(), id.HasScope("orders.read"))
	team, ok := id.ClaimString("team")
	fmt.Println(team, ok)
	// Output:
	// true user oauth [orders.read] true
	// platform-engineering true
}
