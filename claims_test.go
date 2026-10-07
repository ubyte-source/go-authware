package authware

import (
	"errors"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Literals of the claims tests: scopeA as a JSON string written as a unicode
// escape, the start of a JSON object and times in seconds.
const (
	escapedScopeA = `"\u0061"`
	objectOpen    = "{"
	twoMinutes    = 120
	quarter       = time.Second / 4
)

// Documented spellings of claims the subject and marker checks read.
const (
	testClaimAzp    = "azp"
	testClaimRoles  = "roles"
	testClaimAtHash = "at_hash"
)

// testPolicy accepts testClaims at testUnix with a skew of policySkew seconds.
func testPolicy() *claimPolicy {
	return &claimPolicy{iss: testIssuerURL, audience: testMCPServer, skew: policySkew * time.Second}
}

func TestClaimPolicyValidateClaims(t *testing.T) {
	skew := int64(policySkew)
	rw := []string{testRead, testWrite}
	tests := []struct {
		name    string
		claims  map[string]any
		subject string
		scopes  []string
	}{
		{"valid", testClaims(), testUser, rw},
		{"client_id", claimsWith(map[string]any{claimSub: nil, claimClientID: "c"}), "c", rw},
		{"azp", claimsWith(map[string]any{claimSub: "", testClaimAzp: "z"}), "z", rw},
		{"client_id before azp", claimsWith(map[string]any{claimSub: nil, claimClientID: "c", testClaimAzp: "z"}), "c",
			rw},
		{"sub before client_id", claimsWith(map[string]any{claimClientID: "c"}), testUser, rw},
		{"no subject", claimsWith(map[string]any{claimSub: nil}), "", rw},
		{"aud array last", claimsWith(map[string]any{claimAud: []string{"x", testMCPServer}}), testUser, rw},
		{"aud array first", claimsWith(map[string]any{claimAud: []string{testMCPServer, "x"}}), testUser, rw},
		{"exp 2^53", claimsWith(map[string]any{claimExp: 1 << 53}), testUser, rw},
		{"exp at skew", claimsWith(map[string]any{claimExp: testUnix - skew}), testUser, rw},
		{"exp fraction", claimsWith(map[string]any{claimExp: float64(testUnix-skew) + 0.5}), testUser, rw},
		{"at skew", claimsWith(map[string]any{testClaimNbf: testUnix + skew, claimIat: testUnix + skew}), testUser, rw},
		{"epoch", claimsWith(map[string]any{testClaimNbf: 0, claimIat: 0}), testUser, rw},
		{"nonce with scope", claimsWith(map[string]any{testClaimNonce: "n"}), testUser, rw},
		{"nonce with scp", claimsWith(map[string]any{testClaimNonce: "n", claimScope: nil, claimScp: scopeA}), testUser,
			[]string{scopeA}},
		{"nonce with roles", claimsWith(map[string]any{testClaimNonce: "n", claimScope: nil,
			testClaimRoles: []string{"r"}}), testUser, nil},
		{"scope spaces", claimsWith(map[string]any{claimScope: "  a  b "}), testUser, []string{scopeA, scopeB}},
		{"scope wins", claimsWith(map[string]any{claimScope: scopeA, claimScp: scopeB}), testUser, []string{scopeA}},
		{"scp array", claimsWith(map[string]any{claimScope: nil, claimScp: []string{scopeA, "b c", "", "d\te"}}),
			testUser, []string{scopeA, scopeB, "c", "d\te"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := testPolicy().validateClaims(mustJSON(t, tc.claims), time.Unix(testUnix, 0))
			if err != nil || c.subject != tc.subject || !slices.Equal(c.scopes, tc.scopes) {
				t.Fatalf("validateClaims = %+v, %v; want %q %q", c, err, tc.subject, tc.scopes)
			}
		})
	}
}

func TestClaimPolicyValidateClaimsRejects(t *testing.T) {
	skew := int64(policySkew)
	tests := []struct {
		name   string
		claims map[string]any
		want   error
	}{
		{"sub number", claimsWith(map[string]any{claimSub: 7}), errMalformedClaims},
		{"azp bool", claimsWith(map[string]any{claimSub: nil, testClaimAzp: true}), errMalformedClaims},
		{"no iss", claimsWith(map[string]any{claimIss: nil}), errIssuer},
		{"iss slash", claimsWith(map[string]any{claimIss: testIssuerURL + "/"}), errIssuer},
		{"iss case", claimsWith(map[string]any{claimIss: strings.ToUpper(testIssuerURL)}), errIssuer},
		{"iss number", claimsWith(map[string]any{claimIss: 1}), errMalformedClaims},
		{"no aud", claimsWith(map[string]any{claimAud: nil}), errAudience},
		{"aud other", claimsWith(map[string]any{claimAud: "x"}), errAudience},
		{"aud empty", claimsWith(map[string]any{claimAud: []string{}}), errAudience},
		{"aud near", claimsWith(map[string]any{claimAud: []string{testMCPServer + " "}}), errAudience},
		{"aud case", claimsWith(map[string]any{claimAud: strings.ToUpper(testMCPServer)}), errAudience},
		{"aud array case", claimsWith(map[string]any{claimAud: []string{strings.ToUpper(testMCPServer)}}), errAudience},
		{"aud mixed", claimsWith(map[string]any{claimAud: []any{testMCPServer, 1}}), errMalformedClaims},
		{"aud number", claimsWith(map[string]any{claimAud: 3}), errMalformedClaims},
		{"no exp", claimsWith(map[string]any{claimExp: nil}), errMissingExpiry},
		{"exp string", claimsWith(map[string]any{claimExp: strconv.Itoa(testUnix + 60)}), errMalformedClaims},
		{"exp negative", claimsWith(map[string]any{claimExp: -1}), errMalformedClaims},
		{"exp beyond 2^53", claimsWith(map[string]any{claimExp: 1e16}), errMalformedClaims},
		{"exp past skew", claimsWith(map[string]any{claimExp: testUnix - skew - 1}), ErrTokenExpired},
		{"exp fraction past skew", claimsWith(map[string]any{claimExp: float64(testUnix-skew) - 0.5}), ErrTokenExpired},
		{"nbf past skew", claimsWith(map[string]any{testClaimNbf: testUnix + skew + 1}), errNotYetValid},
		{"iat past skew", claimsWith(map[string]any{claimIat: testUnix + skew + 1}), errIssuedInFuture},
		{"nbf string", claimsWith(map[string]any{testClaimNbf: "0"}), errMalformedClaims},
		{"nbf negative", claimsWith(map[string]any{claimIat: nil, testClaimNbf: -5}), errMalformedClaims},
		{"iat string", claimsWith(map[string]any{claimIat: "0"}), errMalformedClaims},
		{"iat negative", claimsWith(map[string]any{claimIat: -1}), errMalformedClaims},
		{testClaimAtHash, claimsWith(map[string]any{testClaimAtHash: "h"}), errIDToken},
		{claimCHash, claimsWith(map[string]any{claimCHash: "h"}), errIDToken},
		{"nonce alone", claimsWith(map[string]any{testClaimNonce: "n", claimScope: nil}), errIDToken},
		{"scope number", claimsWith(map[string]any{claimScope: 1}), errMalformedClaims},
		{"scp mixed", claimsWith(map[string]any{claimScope: nil, claimScp: []any{scopeA, 2}}), errMalformedClaims},
		{"scp object", claimsWith(map[string]any{claimScope: nil, claimScp: map[string]any{}}), errMalformedClaims},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := testPolicy().validateClaims(mustJSON(t, tc.claims), time.Unix(testUnix, 0))
			if !reflect.ValueOf(c).IsZero() || !errors.Is(err, tc.want) {
				t.Fatalf("validateClaims = %+v, %v; want the zero claims, %v", c, err, tc.want)
			}
		})
	}
}

func TestClaimPolicyValidateClaimsEncoding(t *testing.T) {
	now := time.Unix(testUnix, 0)
	valid := `"iss":"https:\/\/issuer.example.com","aud":["` + escape('m') + `cp-server"],"exp":1800000060`
	tests := map[string]error{
		objectOpen + valid + `,"scp":["a\/b"],"sub":"` + escape('u') + `ser"}`: nil,
		objectOpen + valid + `,"sub":"a","s` + escape('u') + `b":"b"}`:         errClaimsShape,
		objectOpen + valid + `,"sub":"a","sub":"b"}`:                           errClaimsShape,
		objectOpen + valid + `}x`:                                              errClaimsShape,
		objectOpen + valid:                                                     errClaimsShape,
		`[` + valid + `]`:                                                      errClaimsShape,
		objectOpen + valid + `,"sub":"bad \x escape"}`:                         errClaimsShape,
		objectOpen + valid + `,"sub":"` + "\xff" + `"}`:                        errClaimsShape,
		objectOpen + valid + `,"\ud800":1}`:                                    errClaimsShape,
	}
	for payload, want := range tests {
		c, err := testPolicy().validateClaims(payload, now)
		if !errors.Is(err, want) || (err == nil) == reflect.ValueOf(c).IsZero() {
			t.Errorf("validateClaims(%s) = %+v, %v, want %v and claims only without error", payload, c, err, want)
		}
		if err == nil && (c.subject != testUser || !slices.Equal(c.scopes, []string{"a/b"})) {
			t.Errorf("validateClaims(%s) = %+v, want subject %s and scope a/b", payload, c, testUser)
		}
	}
}

// TestClaimPolicyValidateClaimsNamesTheClaim refuses each string claim that holds a
// number with the refusal that names that claim.
func TestClaimPolicyValidateClaimsNamesTheClaim(t *testing.T) {
	t.Parallel()
	for claim, want := range map[string]error{
		claimIss: errIssNotString, claimSub: errSubNotString, claimClientID: errClientIDNotString,
		testClaimAzp: errAzpNotString, claimScope: errScopeNotString,
	} {
		members := map[string]any{claimSub: nil}
		members[claim] = 1
		payload := mustJSON(t, claimsWith(members))
		if _, err := testPolicy().validateClaims(payload, time.Unix(testUnix, 0)); !errors.Is(err, want) {
			t.Errorf("validateClaims(%s: 1) = %v, want %v", claim, err, want)
		}
	}
}

func TestClaimPolicyValidateClaimsSkew(t *testing.T) {
	now := time.Unix(testUnix, 0)
	fails := map[string]error{claimExp: ErrTokenExpired, testClaimNbf: errNotYetValid, claimIat: errIssuedInFuture}
	for skew, ok := range map[time.Duration]bool{0: false, time.Minute: false, 2 * time.Minute: true} {
		p := testPolicy()
		p.skew = skew
		for name, fail := range fails {
			at := int64(testUnix + 120)
			if name == claimExp {
				at = testUnix - twoMinutes
			}
			claims := maps.Clone(testClaims())
			claims[name] = at
			want := fail
			if ok {
				want = nil
			}
			c, err := p.validateClaims(mustJSON(t, claims), now)
			if !errors.Is(err, want) || (err == nil) == reflect.ValueOf(c).IsZero() {
				t.Errorf("validateClaims(skew %v, %s %d) = %+v, %v, want %v and claims only without error", skew, name,
					at, c, err, want)
			}
		}
	}
}

func TestNumericDate(t *testing.T) {
	tests := []struct {
		raw  string
		want time.Time
		err  error
	}{
		{"0", time.Unix(0, 0), nil},
		{"1.5", time.Unix(1, 0).Add(time.Second / 2), nil},
		{"1.25", time.Unix(1, 0).Add(quarter), nil},
		{"9007199254740992", time.Unix(1<<53, 0), nil},
		{"9007199254740994", time.Time{}, errMalformedClaims},
		{"-0.5", time.Time{}, errMalformedClaims},
		{`"1"`, time.Time{}, errMalformedClaims},
	}
	for _, tc := range tests {
		got, err := numericDate(tc.raw, errExpTime)
		if !errors.Is(err, tc.err) || !got.Equal(tc.want) {
			t.Errorf("numericDate(%s) = %v, %v; want %v, %v", tc.raw, got, err, tc.want, tc.err)
		}
	}
	if got, err := numericDate("", errExpTime); !errors.Is(err, errExpTime) || !got.IsZero() {
		t.Errorf("numericDate(\"\") = %v, %v, want the zero Time, errMalformedClaims", got, err)
	}
}

// FuzzClaimPolicyValidateClaims checks every payload against
// referenceClaims: the subject and scopes of claims testPolicy accepts at
// testUnix, else the class of the refusal.
func FuzzClaimPolicyValidateClaims(f *testing.F) {
	for _, c := range []map[string]any{
		testClaims(), claimsWith(map[string]any{claimAud: []string{testMCPServer}, claimScp: []string{"x"}}),
		claimsWith(map[string]any{testClaimNonce: "n", testClaimRoles: []string{"r"}, testClaimNbf: testUnix,
			claimIat: 1.5}),
		claimsWith(map[string]any{claimScope: " a  b ", claimScp: []string{"c"}}),
		claimsWith(map[string]any{claimScp: []string{"a b", "", "c"}, testClaimNbf: testUnix + policySkew,
			claimIat: testUnix + policySkew + 1}),
		claimsWith(map[string]any{testClaimNonce: "n", claimCHash: "h"}),
		claimsWith(map[string]any{claimSub: "", claimClientID: "c", testClaimAzp: 7}),
		claimsWith(map[string]any{claimExp: testUnix - policySkew - 1, claimAud: []any{testMCPServer, 1}}),
	} {
		f.Add(mustJSON(f, c))
	}
	f.Add(strings.TrimSuffix(mustJSON(f, testClaims()), "}") + `,"x":{"a":1,"a":1}}`)
	f.Add(strings.TrimSuffix(mustJSON(f, testClaims()), "}") + `,"x":1e400,"y":[{"a":-1E+999}]}`)
	now := time.Unix(testUnix, 0)
	f.Fuzz(func(t *testing.T, payload string) {
		c, err := testPolicy().validateClaims(payload, now)
		want, wantErr := referenceClaims(payload)
		if !errors.Is(err, wantErr) || (wantErr == nil) != (err == nil) || c.subject != want.subject ||
			!slices.Equal(c.scopes, want.scopes) {
			t.Fatalf("validateClaims(%q) = %+v, %v; want %+v, %v", payload, c, err, want, wantErr)
		}
	})
}

func TestEachString(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
		ok   bool
	}{
		{`"x y"`, []string{"x y"}, true},
		{escapedScopeA, []string{scopeA}, true},
		{`["a",""]`, []string{scopeA, ""}, true},
		{jsonEmptyArray, nil, true},
		{`["a",1]`, []string{scopeA}, false},
		{`{}`, nil, false},
		{`1`, nil, false},
		{`"a"x`, nil, false},
	}
	for _, tc := range tests {
		var got []string
		ok := eachString(tc.raw, func(s string) { got = append(got, s) })
		if ok != tc.ok || !slices.Equal(got, tc.want) {
			t.Errorf("eachString(%s) = %q, %v, want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestHoldsString(t *testing.T) {
	tests := []struct {
		raw       string
		found, ok bool
	}{
		{`"a"`, true, true},
		{escapedScopeA, true, true},
		{`"b"`, false, true},
		{`["b","a"]`, true, true},
		{`["a","b"]`, true, true},
		{`["b"]`, false, true},
		{jsonEmptyArray, false, true},
		{`["a",1]`, false, false},
		{`[1,"a"]`, false, false},
		{`{"a":"a"}`, false, false},
		{`1`, false, false},
	}
	for _, tc := range tests {
		if found, ok := holdsString(tc.raw, scopeA); found != tc.found || ok != tc.ok {
			t.Errorf("holdsString(%s, a) = %v, %v, want %v, %v", tc.raw, found, ok, tc.found, tc.ok)
		}
	}
}
