package authware

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// skewSeconds is the default clock skew in seconds.
const skewSeconds = 30

func TestDefaultRealm(t *testing.T) {
	g := mustGate(t, &Config{Mode: ModeBearer, Bearer: BearerConfig{Token: secret.New(testLongSecret)}})
	if g.realm != "restricted" {
		t.Fatalf("realm = %q, want %q", g.realm, "restricted")
	}
}

// TestDefaultClockSkew checks a default OAuth config admits, at testUnix, a token
// expired 30s ago and refuses one expired 31s ago as ErrTokenExpired.
func TestDefaultClockSkew(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Unix(testUnix, 0)))
		a := newTestOAuth(t, &validOAuth().OAuth, nil)
		for age, want := range map[int]error{skewSeconds: nil, skewSeconds + 1: ErrTokenExpired} {
			expired := signToken(t, algHS256, []byte(testLongSecret), "",
				claimsWith(map[string]any{claimExp: testUnix - age}))
			id, err := a.validateToken(t.Context(), expired)
			if !errors.Is(err, want) || (err == nil) == (id == nil) {
				t.Errorf("validateToken(expired %ds ago) = %+v, %v, want %v and an identity only without error", age,
					id, err, want)
			}
		}
	})
}

// limitsHeading opens the limits table of the security policy.
const limitsHeading = "## Operational Limits"

// limitProbes maps the parameter of each row of the limits table to the tests, each
// named by its package directory, that pin its value at the bound and one past it.
func limitProbes() map[string][]string {
	probes := map[string][]string{
		"JWT length": {".:TestParseJWS", ".:TestOAuthAuthenticatorValidateTokenHMAC"},
		"JWKS body":  {".:TestKeySourceFetchSizeLimit", ".:TestKeySourceGet"},
		"Reasons a refused JWKS keeps for its unusable keys": {
			".:TestParseJWKSKeepsTheFirstReasons", ".:TestParseJWKSRefusalIsBounded",
		},
		"Discovery document": {".:TestIssuerDiscover", ".:TestIssuerDiscoverRejects"},
		"JSON nesting":       {"internal/jsonobj:TestIterate", "internal/jsonobj:TestIterateRejects"},
		"Facade `/register` and `/token` request bodies": {
			".:TestFacadeServeRegisterBodyLimit", ".:TestFacadeServeTokenBodyLimit",
		},
		"Facade `/token` `code_verifier`": {".:TestValidVerifier"},
		"Time claims":                     {".:TestNumericDate"},
		"RSA modulus":                     {".:TestParseJWK", ".:TestParseJWKRejects"},
		"RSA exponent":                    {".:TestParseJWK", ".:TestParseJWKNamesTheFault"},
		"EC curves":                       {".:TestParseJWKKeys", ".:TestParseJWKRejects", ".:TestParseECKeyRejects"},
	}
	maps.Copy(probes, answerProbes())
	maps.Copy(probes, secretProbes())
	maps.Copy(probes, timeProbes())
	return probes
}

// answerProbes maps the rows that bound what is read of an answer, a body or a file
// to their probes.
func answerProbes() map[string][]string {
	return map[string][]string{
		"Token endpoint response (`cred`, facade relay)": {
			"cred:TestTokenEndpointPostBodyLimit", ".:TestFacadeServeTokenAnswerLimit",
			"internal/oauthwire:TestSendRejects",
		},
		"Cloud metadata response": {"cred:TestMetadataSourceTokenOversized"},
		"Token endpoint, metadata and discovery error answer read (`cred`, root)": {
			"internal/oauthwire:TestReadHead", "internal/oauthwire:TestFetchReadsTheStatusFirst",
		},
		"`cred.NewTransport` 401 answer drained before its retry": {"cred:TestDrain"},
		"Token endpoint error code and description kept":          {"internal/oauthwire:TestErrorMembersTruncates"},
		"`replay` body read":           {"replay:TestSignerSignBodyLimit", "replay:TestBodyDigest"},
		"Secrets file (`secret.File`)": {"secret:TestDecodeFileLimit", "secret:TestFileRefusesSpecialFiles"},
		"`cred.NewSigV4` signed body": {
			"cred:TestSigV4PayloadHashLimit", "cred:TestSigV4SignRefusesBodies", "cred:TestSigV4SignUnsignedPayload",
		},
		"`replay` canonical input kept between calls": {"replay:TestMACScratchPut"},
	}
}

// secretProbes maps the rows of the shortest secrets and of the nonce store to
// their probes.
func secretProbes() map[string][]string {
	return map[string][]string{
		"Bearer token, API key, replay key": {
			".:TestMinSecretLen", ".:TestLongEnough", ".:TestBearerConfigValidate", ".:TestAPIKeyConfigValidate",
			"replay:TestNewSigner", "replay:TestNewVerifier",
		},
		"HMAC secret":                      {".:TestMinSecretLen", ".:TestHMACKeyFits"},
		"`replay.NewMemoryStore` capacity": {"replay:TestNewMemoryStore", "replay:TestMemoryStoreSeenCapacity"},
	}
}

// timeProbes maps the rows of the lifetimes, the defaults and the pauses to their
// probes.
func timeProbes() map[string][]string {
	return map[string][]string{
		"Token lifetime": {
			"internal/oauthwire:TestParseExpiresIn", "cred:TestParseEpochCap", "cred:TestParseMSIResponseFarExpiresOn",
		},
		"Clock skew (`ClockSkew`)":       {".:TestDefaultClockSkew", ".:TestConfigApplyDefaults"},
		"Key cache TTL (`KeysCacheTTL`)": {".:TestConfigApplyDefaults", ".:TestCacheGetStale"},
		"Fetch timeout (`FetchTimeout`, `Timeout` of each `cred` source)": {
			".:TestConfigApplyDefaults", "cred:TestDefaultTimeout", "cred:TestNewCachedSourceDefaults",
		},
		"Stale keys and issuer metadata served while fetches fail": {".:TestStale", ".:TestCacheGetStale"},
		"Backoff after a failed key or metadata fetch, or `cred.CachedSource` refresh": {
			"internal/retry:TestBackoffWaiting", ".:TestCacheGetStale", "cred:TestCachedSourceTokenBackoff",
		},
		"Forced key refresh interval": {".:TestOAuthAuthenticatorValidateTokenRenewsKeys"},
		"`replay` window": {
			"replay:TestWithWindow", "replay:TestNewVerifierConfigRejects", "replay:TestNewVerifierConfigDefaults",
			"replay:TestVerifierVerifyWindow",
		},
		"`cred.NewCachedSource` refresh skew": {
			"cred:TestNewCachedSourceDefaults", "cred:TestCachedSourceToken", "cred:TestCachedSourceTokenShortLifetime",
		},
	}
}

// limitConstants maps the parameter of a row to the candidate limit constants, each
// named by its package directory, that hold its bounds, and "" to those that bound
// no input.
func limitConstants() map[string][]string {
	return map[string][]string{
		"JWT length": {".:maxTokenSize"},
		"JWKS body":  {".:maxJWKSBytes"},
		"Reasons a refused JWKS keeps for its unusable keys": {".:maxSkippedReasons"},
		"Discovery document": {".:maxMetadataBytes"},
		"JSON nesting":       {"internal/jsonobj:maxDepth"},
		"Facade `/register` and `/token` request bodies": {".:maxFacadeBodyBytes"},
		"Facade `/token` `code_verifier`":                {".:minVerifierLen", ".:maxVerifierLen"},
		"Token endpoint response (`cred`, facade relay)": {"internal/oauthwire:MaxTokenBody"},
		"Token endpoint, metadata and discovery error answer read (`cred`, root)": {
			"internal/oauthwire:maxErrorBody",
		},
		"`cred.NewTransport` 401 answer drained before its retry": {"cred:maxDrain"},
		"Token endpoint error code and description kept":          {"internal/oauthwire:maxErrorExcerpt"},
		"Token lifetime":                              {"internal/oauthwire:MaxLifetime"},
		"Bearer token, API key, replay key":           {".:minSecretLen", "replay:minKeyLen"},
		"Time claims":                                 {".:maxNumericDate"},
		"RSA modulus":                                 {".:minRSABits", ".:maxRSABits"},
		"RSA exponent":                                {".:minRSAExponentBits", ".:maxRSAExponentBits"},
		"`replay` body read":                          {"replay:maxBodyBytes"},
		"Secrets file (`secret.File`)":                {"secret:maxFileBytes"},
		"`cred.NewSigV4` signed body":                 {"cred:maxSignedBody"},
		"`replay` window":                             {"replay:minWindowSeconds", "replay:maxWindowSeconds"},
		"`replay` canonical input kept between calls": {"replay:maxPooledInput"},
		"": {
			".:maxChallengeParams", ".:minArcs", ".:maxDERBody", ".:derSignatureSize", "internal/netguard:maxRoom",
			"replay:nonceBytes",
		},
	}
}

// limitName matches the names that mark a numeric constant as a limit.
var limitName = regexp.MustCompile(`(?i)^(max|min)|limit|(cap|size|bytes|depth)$`)

// limitRows returns the text of each row of the limits table by its parameter.
func limitRows(t *testing.T) map[string]string {
	t.Helper()
	text, err := os.ReadFile("SECURITY.md")
	if err != nil {
		t.Fatalf("ReadFile(SECURITY.md) = %v, want the document", err)
	}
	_, table, _ := strings.Cut(string(text), "\n"+limitsHeading+"\n")
	rows := map[string]string{}
	for k, line := range strings.Split(strings.TrimLeft(table, "\n"), "\n") {
		if !strings.HasPrefix(line, "|") {
			break
		}
		if param, _, _ := strings.Cut(strings.TrimPrefix(line, "| "), " | "); k > 1 {
			rows[param] = line
		}
	}
	if len(rows) == 0 {
		t.Fatalf("SECURITY.md: the table under %q has no row, want the limits", limitsHeading)
	}
	return rows
}

// moduleDecls parses the Go files of the module and returns, each named by its
// package directory, the tests and, for each constant of the code, whether it holds
// a number.
func moduleDecls(t *testing.T) (tests, consts map[string]bool) {
	t.Helper()
	tests, consts = map[string]bool{}, map[string]bool{}
	err := filepath.WalkDir(".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		pkg := filepath.ToSlash(filepath.Dir(path)) + ":"
		if strings.HasSuffix(path, "_test.go") {
			fileTests(pkg, f, tests)
		} else {
			fileConsts(pkg, f, consts)
		}
		return nil
	})
	if err != nil || len(consts) == 0 {
		t.Fatalf("parsing the module = %d constants, %v, want its declarations", len(consts), err)
	}
	return tests, consts
}

// fileTests files in tests each function that the test file f declares in pkg.
func fileTests(pkg string, f *ast.File, tests map[string]bool) {
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			tests[pkg+fn.Name.Name] = true
		}
	}
}

// fileConsts files in consts each constant that f declares in pkg, and whether it
// holds a number; a spec without values repeats the values before it.
func fileConsts(pkg string, f *ast.File, consts map[string]bool) {
	text := func(e ast.Expr) bool { return isText(pkg, e, consts) }
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		var values []ast.Expr
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if len(vs.Values) > 0 {
				values = vs.Values
			}
			for _, name := range vs.Names {
				consts[pkg+name.Name] = !slices.ContainsFunc(values, text)
			}
		}
	}
}

// isText reports whether the constant expression e of pkg is a string: a string
// literal, a sum of one, or a string constant of consts.
func isText(pkg string, e ast.Expr, consts map[string]bool) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.BinaryExpr:
		return v.Op == token.ADD && (isText(pkg, v.X, consts) || isText(pkg, v.Y, consts))
	case *ast.Ident:
		numeric, declared := consts[pkg+v.Name]
		return declared && !numeric
	}
	return false
}

// checkLimitProbes fails t on a row of rows without a probe, and on a probe that is no
// test of tests or belongs to no row.
func checkLimitProbes(t *testing.T, rows map[string]string, tests map[string]bool) {
	t.Helper()
	probes := limitProbes()
	for param := range rows {
		if len(probes[param]) == 0 {
			t.Errorf("the limits row %q has no probe, want the tests that pin it", param)
		}
	}
	for param, names := range probes {
		for _, name := range names {
			_, test, _ := strings.Cut(name, ":")
			if !tests[name] || !strings.HasPrefix(test, "Test") || rows[param] == "" {
				t.Errorf("the probe %s of %q is no test of a row, want both", name, param)
			}
		}
	}
}

// listedLimits returns the constants that limitConstants lists, and fails t on an
// entry that is no row of rows or no constant of consts.
func listedLimits(t *testing.T, rows map[string]string, consts map[string]bool) map[string]bool {
	t.Helper()
	listed := map[string]bool{}
	for param, names := range limitConstants() {
		if param != "" && rows[param] == "" {
			t.Errorf("limitConstants[%q] is no row, want a row of the limits table", param)
		}
		for _, name := range names {
			if _, declared := consts[name]; !declared {
				t.Errorf("limitConstants lists %s, want a constant of the module", name)
			}
			listed[name] = true
		}
	}
	return listed
}

// checkLimitConstants fails t on a constant that a row of rows names, or a numeric
// one whose name marks a limit, that limitConstants does not list.
func checkLimitConstants(t *testing.T, rows map[string]string, consts map[string]bool) {
	t.Helper()
	listed := listedLimits(t, rows, consts)
	for name, numeric := range consts {
		_, short, _ := strings.Cut(name, ":")
		named := slices.ContainsFunc(slices.Collect(maps.Values(rows)), func(row string) bool {
			return strings.Contains(row, "`"+short+"`")
		})
		if (named || numeric && limitName.MatchString(short)) && !listed[name] {
			t.Errorf("limitConstants lacks %s, want it under its row, or under \"\" for no limit", name)
		}
	}
}

func TestDefaultClockSkewAndEveryOtherLimitHaveARowAndAProbe(t *testing.T) {
	rows := limitRows(t)
	tests, consts := moduleDecls(t)
	checkLimitProbes(t, rows, tests)
	checkLimitConstants(t, rows, consts)
}
