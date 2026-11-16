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
		{"aud array last", claimsWith(map[string]any{claimAud: []string{"x", testMCPServer}}), testUser, rw},
		{"aud array first", claimsWith(map[string]any{claimAud: []string{testMCPServer, "x"}}), testUser, rw},
		{"exp 2^53", claimsWith(map[string]any{claimExp: int64(maxDate)}), testUser, rw},
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
		{"scp array", claimsWith(map[string]any{claimScope: nil, claimScp: []string{scopeA, "b c", "", "d:e/f"}}),
			testUser, []string{scopeA, scopeB, "c", "d:e/f"}},
		{"subject inner space and tab", claimsWith(map[string]any{claimSub: "a b\tc"}), "a b\tc", rw},
		{"subject beyond ASCII", claimsWith(map[string]any{claimSub: "caf\u00e9"}), "caf\u00e9", rw},
		{"scope token bounds", claimsWith(map[string]any{claimScope: "!#[]~"}), testUser, []string{"!#[]~"}},
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

// claimRefusal is a payload and the refusal validateClaims answers it with.
type claimRefusal struct {
	name   string
	claims map[string]any
	want   error
}

// expectRefusals fails t unless testPolicy refuses each payload at testUnix with
// its refusal and the zero claims.
func expectRefusals(t *testing.T, tests []claimRefusal) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := testPolicy().validateClaims(mustJSON(t, tc.claims), time.Unix(testUnix, 0))
			if !reflect.ValueOf(c).IsZero() || !errors.Is(err, tc.want) {
				t.Fatalf("validateClaims = %+v, %v; want the zero claims, %v", c, err, tc.want)
			}
		})
	}
}

func TestClaimPolicyValidateClaimsRejects(t *testing.T) {
	skew := int64(policySkew)
	expectRefusals(t, []claimRefusal{
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
	})
}

// TestClaimPolicyValidateClaimsRejectsSubjects refuses a token that names no
// subject, and one whose subject, in any of its claims, is no header value.
func TestClaimPolicyValidateClaimsRejectsSubjects(t *testing.T) {
	expectRefusals(t, []claimRefusal{
		{"no subject", claimsWith(map[string]any{claimSub: nil}), errMissingSubject},
		{"empty subjects", claimsWith(map[string]any{claimSub: "", claimClientID: "", testClaimAzp: ""}),
			errMissingSubject},
		{"subject space first", claimsWith(map[string]any{claimSub: " user"}), errSubjectValue},
		{"subject space last", claimsWith(map[string]any{claimSub: "user "}), errSubjectValue},
		{"subject tab last", claimsWith(map[string]any{claimSub: "user\t"}), errSubjectValue},
		{"subject line feed", claimsWith(map[string]any{claimSub: "a\nb"}), errSubjectValue},
		{"subject only spaces", claimsWith(map[string]any{claimSub: "  "}), errSubjectValue},
		{"subject DEL", claimsWith(map[string]any{claimSub: "a\x7fb"}), errSubjectValue},
		{"blank sub before client_id", claimsWith(map[string]any{claimSub: " ", claimClientID: "c"}),
			errSubjectValue},
		{"client_id control", claimsWith(map[string]any{claimSub: "", claimClientID: "c\x00"}), errSubjectValue},
		{"azp space", claimsWith(map[string]any{claimSub: nil, testClaimAzp: "z "}), errSubjectValue},
	})
}

// TestClaimPolicyValidateClaimsRejectsScopes refuses a token one of whose
// scopes, in scope or scp, is no scope token.
func TestClaimPolicyValidateClaimsRejectsScopes(t *testing.T) {
	expectRefusals(t, []claimRefusal{
		{"scope tab", claimsWith(map[string]any{claimScope: "a\tb"}), errScopeToken},
		{"scope line break", claimsWith(map[string]any{claimScope: "read\r\nadmin"}), errScopeToken},
		{"scope quote", claimsWith(map[string]any{claimScope: `a"b`}), errScopeToken},
		{"scope backslash", claimsWith(map[string]any{claimScope: `a\b`}), errScopeToken},
		{"scope beyond ASCII", claimsWith(map[string]any{claimScope: "caf\u00e9"}), errScopeToken},
		{"scope DEL", claimsWith(map[string]any{claimScope: "a\x7f"}), errScopeToken},
		{"scp tab", claimsWith(map[string]any{claimScope: nil, claimScp: []string{scopeA, "d\te"}}), errScopeToken},
		{"scp tabs first", claimsWith(map[string]any{claimScope: nil, claimScp: []string{"d\te", "f\tg", scopeA}}),
			errScopeToken},
		{"scp string control", claimsWith(map[string]any{claimScope: nil, claimScp: "a \x01"}), errScopeToken},
	})
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
		members := map[string]any{claimSub: nil, testClaimAzp: "z"}
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
		claimsWith(map[string]any{claimSub: nil}), claimsWith(map[string]any{claimSub: "", testClaimAzp: ""}),
		claimsWith(map[string]any{claimSub: " u"}), claimsWith(map[string]any{claimSub: "a\tb", claimScope: "a\tb"}),
		claimsWith(map[string]any{claimSub: "", claimClientID: "c\n"}),
		claimsWith(map[string]any{claimScope: nil, claimScp: []string{`a"`, scopeA}}),
		claimsWith(map[string]any{claimScope: nil, claimScp: []string{"x y", "z"}}),
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

// TestScpStrings passes fn each string up to the first fault: a value or an
// element that is no string, or the string fn fails on, here "stop".
func TestScpStrings(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
		err  error
	}{
		{`"x y"`, []string{"x y"}, nil},
		{escapedScopeA, []string{scopeA}, nil},
		{`["a",""]`, []string{scopeA, ""}, nil},
		{jsonEmptyArray, nil, nil},
		{`["a",1]`, []string{scopeA}, errScopeType},
		{`[1,"a"]`, nil, errScopeType},
		{`{}`, nil, errScopeType},
		{`1`, nil, errScopeType},
		{`"a"x`, nil, errScopeType},
		{`"stop"`, nil, errOther},
		{`["a","stop","b"]`, []string{scopeA}, errOther},
		{`["a","stop",1]`, []string{scopeA}, errOther},
	}
	for _, tc := range tests {
		var got []string
		err := scpStrings(tc.raw, func(s string) error {
			if s == "stop" {
				return errOther
			}
			got = append(got, s)
			return nil
		})
		if !errors.Is(err, tc.err) || (err == nil) != (tc.err == nil) || !slices.Equal(got, tc.want) {
			t.Errorf("scpStrings(%s) = %q, %v, want %q, %v", tc.raw, got, err, tc.want, tc.err)
		}
	}
}

// TestRawClaimsSubject returns the first non-empty of sub, client_id and azp,
// and no subject with the refusal of the first fault of the claims it reads.
func TestRawClaimsSubject(t *testing.T) {
	tests := []struct {
		name               string
		sub, clientID, azp string
		want               string
		err                error
	}{
		{"sub", `"u"`, `"c"`, `"z"`, "u", nil},
		{"client_id", `""`, `"c"`, `"z"`, "c", nil},
		{"azp", "", `""`, `"z"`, "z", nil},
		{"sub before a client_id that is no string", `"u"`, `1`, "", "u", nil},
		{"none", "", `""`, "", "", errMissingSubject},
		{"sub number", `1`, `"c"`, "", "", errSubNotString},
		{"azp number", "", "", `1`, "", errAzpNotString},
		{"sub space last", `"u "`, `"c"`, "", "", errSubjectValue},
		{"client_id line feed", "", `"c\n"`, `"z"`, "", errSubjectValue},
	}
	for _, tc := range tests {
		got, err := (&rawClaims{sub: tc.sub, clientID: tc.clientID, azp: tc.azp}).subject()
		if got != tc.want || !errors.Is(err, tc.err) || (err == nil) != (tc.err == nil) {
			t.Errorf("%s: subject = %q, %v, want %q, %v", tc.name, got, err, tc.want, tc.err)
		}
	}
}

// TestRawClaimsScopes returns the tokens the claims grant, and no token with
// the refusal of the first fault of scope or scp.
func TestRawClaimsScopes(t *testing.T) {
	tests := []struct {
		name       string
		scope, scp string
		want       []string
		err        error
	}{
		{"neither", "", "", nil, nil},
		{"scope", `" a  b "`, `"c"`, []string{scopeA, scopeB}, nil},
		{"scp string", "", `"a b"`, []string{scopeA, scopeB}, nil},
		{"scp array", "", `["a","b c",""]`, []string{scopeA, scopeB, "c"}, nil},
		{"scope number", `1`, "", nil, errScopeNotString},
		{"scope tab", `"a\tb"`, "", nil, errScopeToken},
		{"scp number", "", `1`, nil, errScopeType},
		{"scp bad token last", "", `["a","d\te"]`, nil, errScopeToken},
		{"scp bad token first", "", `["d\te","a"]`, nil, errScopeToken},
		{"scp bad token before a number", "", `["d\te",2]`, nil, errScopeToken},
		{"scp number before a bad token", "", `["a",2,"d\te"]`, nil, errScopeType},
	}
	for _, tc := range tests {
		got, err := (&rawClaims{scope: tc.scope, scp: tc.scp}).scopes()
		if !errors.Is(err, tc.err) || (err == nil) != (tc.err == nil) || !slices.Equal(got, tc.want) ||
			(err != nil && got != nil) {
			t.Errorf("%s: scopes = %q, %v, want %q, %v", tc.name, got, err, tc.want, tc.err)
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
