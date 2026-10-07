package authware

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"testing"
)

func TestCapabilityAllow(t *testing.T) {
	always := NewCapability(func(*Identity) bool { return true })
	if always.Allow(nil) {
		t.Fatal("Allow(nil) = true, want false")
	}
	if !always.Allow(scoped()) {
		t.Fatal("Allow = false, want the true of fn")
	}
	if (Capability{}).Allow(scoped()) || NewCapability(nil).Allow(scoped()) {
		t.Fatal("Allow without a check = true, want false")
	}
}

func TestCapabilityDenial(t *testing.T) {
	for _, c := range []Capability{{}, NewCapability(func(*Identity) bool { return false }), HasMode(ModeNone)} {
		if e := c.denial(); !errors.Is(e, ErrInsufficientScope) || e.status != http.StatusForbidden ||
			e.code != "" || e.scope != "" {
			t.Fatalf("denial = %+v, want a 403 without challenge code or scope", e)
		}
	}
	e := HasAllScopes(testRead, testWrite).denial()
	scope := testRead + " " + testWrite
	if e.status != http.StatusForbidden || e.code != codeInsufficientScope || e.scope != scope {
		t.Fatalf("denial = %+v, want a 403 insufficient_scope naming %q", e, scope)
	}
}

func TestForbidden(t *testing.T) {
	e := forbidden()
	if !errors.Is(e, ErrInsufficientScope) || e.status != http.StatusForbidden || e.code != "" || e.scope != "" ||
		e.msg != "capability not satisfied" {
		t.Fatalf("forbidden = %+v, want a 403 capability failure without challenge code", e)
	}
	if forbidden() == e {
		t.Fatal("forbidden() = the same value twice, want a fresh one per call")
	}
}

func TestHasAnyScope(t *testing.T) {
	scopes := []string{testRead, testWrite}
	c := HasAnyScope(scopes...)
	scopes[0] = testAdmin
	allowed := []bool{c.Allow(scoped(testWrite)), c.Allow(scoped(testRead)), c.Allow(scoped(testAdmin))}
	if !slices.Equal(allowed, []bool{true, true, false}) {
		t.Fatalf("HasAnyScope.Allow(write, read, admin) = %v, want [true true false] after the slice edit", allowed)
	}
	if got, want := c.denial().scope, testRead+" "+testWrite; got != want {
		t.Fatalf("denial scope = %q, want %q", got, want)
	}
	if HasAnyScope().Allow(scoped(testRead)) {
		t.Fatal("HasAnyScope().Allow = true, want false")
	}
}

func TestHasAllScopes(t *testing.T) {
	scopes := []string{testRead, testWrite}
	c := HasAllScopes(scopes...)
	scopes[0] = testAdmin
	allowed := []bool{c.Allow(scoped(testRead, testWrite)), c.Allow(scoped(testRead)),
		c.Allow(scoped(testAdmin, testWrite))}
	if !slices.Equal(allowed, []bool{true, false, false}) {
		t.Fatalf("HasAllScopes.Allow(read write, read, admin write) = %v, want [true false false] after the slice edit",
			allowed)
	}
	if !HasAllScopes().Allow(scoped()) {
		t.Fatal("HasAllScopes().Allow = false, want true")
	}
	one := HasAllScopes(testRead)
	allowed = []bool{one.Allow(scoped(testRead)), one.Allow(scoped(testWrite)),
		HasAllScopes("").Allow(scoped(testRead))}
	if !slices.Equal(allowed, []bool{true, false, false}) {
		t.Fatalf(`HasAllScopes(read).Allow(read, write), HasAllScopes("").Allow(read) = %v, want [true false false]`,
			allowed)
	}
	if got := one.denial().scope; got != testRead {
		t.Fatalf("denial scope = %q, want %q", got, testRead)
	}
}

func TestHasClaim(t *testing.T) {
	id := scoped()
	pass := []Capability{
		HasClaim(claimLvl, int64(lvl)), HasClaim(claimLvl, float64(lvl)), HasClaim(claimRatio, ratio),
		HasClaim(claimTeam, testTeam), HasClaim(claimOn, true),
	}
	for i, c := range pass {
		if !c.Allow(id) {
			t.Errorf("pass[%d].Allow = false, want true", i)
		}
	}
	fail := []Capability{
		HasClaim(claimLvl, int64(lvl+1)), HasClaim(claimLvl, lvl+ratio), HasClaim(claimRatio, int64(0)),
		HasClaim(claimTeam, testTeam[1:]), HasClaim("missing", ""),
	}
	for i, c := range fail {
		if c.Allow(id) {
			t.Errorf("fail[%d].Allow = true, want false", i)
		}
	}
	if HasClaim("o", `{"k":1}`).Allow(&Identity{claims: `{"o":{"k":1}}`}) {
		t.Error(`HasClaim(o, {"k":1}).Allow(object claim) = true, want false: only a JSON string equals a string`)
	}
}

func BenchmarkHasClaim(b *testing.B) {
	id := scoped()
	for _, tc := range []struct {
		name string
		c    Capability
	}{
		{"string", HasClaim(claimTeam, testTeam)},
		{"int64", HasClaim(claimLvl, int64(lvl))},
	} {
		b.Run(tc.name, func(b *testing.B) {
			if !tc.c.Allow(id) {
				b.Fatalf("HasClaim(%s).Allow = false, want true", tc.name)
			}
			b.ReportAllocs()
			for b.Loop() {
				tc.c.Allow(id)
			}
		})
	}
}

// TestCapabilityAllowAllocs admits an identity through each kind of
// capability without allocating.
func TestCapabilityAllowAllocs(t *testing.T) {
	id := scoped(testRead)
	for name, c := range map[string]Capability{
		"scope": HasAnyScope(testRead), "all scopes": HasAllScopes(testRead), "mode": HasMode(ModeOAuth),
		"subject": HasSubject(testUser), "string claim": HasClaim(claimTeam, testTeam),
		"int64 claim": HasClaim(claimLvl, int64(lvl)),
	} {
		assertAllocs(t, 0, func() {
			if !c.Allow(id) {
				t.Fatalf("%s capability Allow = false, want true", name)
			}
		})
	}
}

func TestHasMode(t *testing.T) {
	allowed := []bool{HasMode(ModeOAuth).Allow(scoped()), HasMode(ModeBearer).Allow(scoped())}
	if !slices.Equal(allowed, []bool{true, false}) {
		t.Fatalf("HasMode(oauth, bearer).Allow(oauth identity) = %v, want [true false]", allowed)
	}
}

func TestHasSubject(t *testing.T) {
	allowed := []bool{HasSubject(testUser).Allow(scoped()), HasSubject(testAdmin).Allow(scoped())}
	if !slices.Equal(allowed, []bool{true, false}) {
		t.Fatalf("HasSubject(user, admin).Allow(user identity) = %v, want [true false]", allowed)
	}
}

// float64Bits is the size strconv.ParseFloat rounds a claim to.
const float64Bits = 64

// TestClaimOf decodes every claim value as each kind: a float64 reads any
// number, integers included, as strconv.ParseFloat reads it.
func TestClaimOf(t *testing.T) {
	for raw, want := range claimValues() {
		checkClaimOf[string](t, raw, want)
		checkClaimOf[int64](t, raw, want)
		checkClaimOf[bool](t, raw, want)
		if _, integer := want.(int64); integer {
			f, err := strconv.ParseFloat(raw, float64Bits)
			if err != nil {
				t.Fatalf("ParseFloat(%s) = %v, want the float of an integer claim", raw, err)
			}
			want = f
		}
		checkClaimOf[float64](t, raw, want)
	}
}

// checkClaimOf requires claimOf[T](raw) to return want and true exactly when want
// is a T other than the JSON text of raw, and the zero T and false otherwise.
func checkClaimOf[T string | int64 | float64 | bool](t *testing.T, raw string, want any) {
	t.Helper()
	w, isT := want.(T)
	isT = isT && want != any(raw)
	if !isT {
		var zero T
		w = zero
	}
	if got, ok := claimOf[T](raw); ok != isT || !sameValue(any(got), any(w)) {
		t.Errorf("claimOf[%T](%s) = %v, %v, want %v, %v", w, raw, got, ok, w, isT)
	}
}
