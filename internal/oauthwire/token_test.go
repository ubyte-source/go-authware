package oauthwire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// escUnderscore is the JSON escape of '_'.
const escUnderscore = `\` + "u005f"

const jsonNull = "null"

// errInvalid is the error the token tests pass for an invalid response.
var errInvalid = errors.New("test: invalid token response")

func TestParseTokenResponse(t *testing.T) {
	t.Parallel()
	body := ` {"access_token":"at` + escUnderscore + `1","token_type":"Bearer","refresh_token":"rt",
		"id_token":"idt","scope":"a b","expires_in":3600,"ext":{"n":[1,{"x":null}]}}` + "\n"
	var extra []string
	got, err := ParseTokenResponse(body, errInvalid, func(name, _ string) error {
		extra = append(extra, name)
		return nil
	})
	if err != nil {
		t.Fatalf("ParseTokenResponse = %v, want a response", err)
	}
	want := TokenResponse{AccessToken: "at_1", TokenType: "Bearer", RefreshToken: "rt", ExpiresIn: time.Hour}
	if got != want || strings.Join(extra, "|") != "id_token|scope|ext" {
		t.Fatalf("got %+v with extra %q, want %+v with id_token, scope and ext", got, extra, want)
	}
}

func TestParseTokenResponseEscapedKey(t *testing.T) {
	t.Parallel()
	got, err := ParseTokenResponse(`{"access`+escUnderscore+`token":"at","expires`+
		escUnderscore+`in":"60"}`, errInvalid, nil)
	if err != nil || got.AccessToken != "at" || got.ExpiresIn != time.Minute {
		t.Fatalf("ParseTokenResponse = %+v, %v, want at expiring in 60s", got, err)
	}
}

// Durations and sizes of the token tests: a day, the nanoseconds nearest to
// 2^-12 s, a thousand, a nesting past the parser's bound, the base and
// precision of the reference parse and the drift float64 seconds allow.
const (
	day            = 24 * time.Hour
	nearestNanos   = 244140
	kilo           = 1000
	jsonDepth      = 64
	decimalBase    = 10
	floatPrecision = 128
	driftNanos     = 8
)

func TestParseExpiresIn(t *testing.T) {
	t.Parallel()
	const year = 365 * 24 * time.Hour
	cases := map[string]time.Duration{
		`3600`:               time.Hour,
		`"3600"`:             time.Hour,
		`3600.5`:             time.Hour + time.Second/2,
		`86400.000244140625`: day + nearestNanos*time.Nanosecond,
		jsonNull:             0,
		`"1e3"`:              kilo * time.Second,
		`1`:                  time.Second,
		`0.5`:                time.Second / 2,
		`1e-300`:             time.Nanosecond,
		`1e-400`:             time.Nanosecond,
		`"1E-400"`:           time.Nanosecond,
		`1e-999999999999`:    time.Nanosecond,
		`0.00001e-400`:       time.Nanosecond,
		`31536000`:           year,
		`31536001`:           year,
		`1e300`:              year,
		`"1e300"`:            year,
		`1e400`:              year,
		`"1e400"`:            year,
	}
	for raw, want := range cases {
		got, err := parseExpiresIn(raw, errInvalid)
		if err != nil || got != want {
			t.Fatalf("parseExpiresIn(%s) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{`"3600s"`, `" 3600"`, `""`, `true`, `[3600]`, `{}`, `"0x10"`,
		`"+5"`, `"01"`, `"1."`, `"-"`, `"5 "`, `"Inf"`, `"NaN"`, `0`, `-0`, `"0"`, `-5`, `"-5"`, `-1e-300`,
		`-1e400`, `"-1e400"`, `-1e-400`, `0.0`, `0e5`, `0E5`, `"0.000e-3"`, `0e999999999999`} {
		got, err := parseExpiresIn(raw, errInvalid)
		if !errors.Is(err, errInvalid) || got != 0 {
			t.Fatalf("parseExpiresIn(%s) = %v, %v; want 0 and errInvalid", raw, got, err)
		}
	}
}

func TestParseTokenResponseNullIsAbsent(t *testing.T) {
	t.Parallel()
	got, err := ParseTokenResponse(`{"access_token":"at","refresh_token":null,"expires_in":null}`, errInvalid, nil)
	if err != nil || got.RefreshToken != "" || got.ExpiresIn != 0 {
		t.Fatalf("ParseTokenResponse = %+v, %v, want the null members absent", got, err)
	}
}

func TestParseTokenResponseRejects(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		``,
		`   `,
		`null`,
		`"at"`,
		`[{"access_token":"at"}]`,
		`{"access_token":"at"`,
		`{"access_token":"at",`,
		`{"access_token":"at"} x`,
		`{"access_token":"at"}{"access_token":"b"}`,
		`{"access_token":"at",}`,
		`{"access_token":"at" "scope":"a"}`,
		`{"access_token":"at","ext":[1,,2]}`,
		`{"access_token":"at","ext":tru}`,
		`{"access_token":"a","access_token":"b"}`,
		`{"access_token":"a","access` + escUnderscore + `token":"b"}`,
		`{"access_token":"a","x":1,"x":2}`,
		`{"access_token":"a","x":{"k":1,"k":2}}`,
		`{"access_token":"a","x":[{"k_":1,"k` + escUnderscore + `":2}]}`,
		`{"access_token":""}`,
		`{"access_token":null}`,
		`{"token_type":"Bearer"}`,
		`{"access_token":42}`,
		`{"access_token":"at","token_type":1}`,
		`{"access_token":"at","refresh_token":{}}`,
		`{"access_token":"at","expires_in":"soon"}`,
		`{"access_token":"at","ext":` + strings.Repeat("[", jsonDepth) + strings.Repeat("]", jsonDepth) + `}`,
	} {
		got, err := ParseTokenResponse(body, errInvalid, nil)
		if !errors.Is(err, errInvalid) || got != (TokenResponse{}) {
			t.Fatalf("ParseTokenResponse(%q) = %+v, %v, want errInvalid", body, got, err)
		}
	}
	const want = "test: invalid token response: missing access_token"
	_, err := ParseTokenResponse(`{"token_type":"Bearer"}`, errInvalid, nil)
	if err == nil || !errors.Is(err, errInvalid) || err.Error() != want {
		t.Fatalf("ParseTokenResponse without access_token = %v, want %q", err, want)
	}
}

func TestParseTokenResponseExtra(t *testing.T) {
	t.Parallel()
	var extra []string
	got, err := ParseTokenResponse(`{"expires_on":"1700000000","access_token":"at","ext":null,"scope":["s"],`+
		`"id_token":true}`, errInvalid, func(name, value string) error {
		extra = append(extra, name+"="+value)
		return nil
	})
	if err != nil || got != (TokenResponse{AccessToken: "at"}) ||
		strings.Join(extra, "|") != `expires_on="1700000000"|ext=null|scope=["s"]|id_token=true` {
		t.Fatalf("ParseTokenResponse = %+v, %v with extra %q; want at and the four other members", got, err, extra)
	}
	got, err = ParseTokenResponse(`{"access_token":"at","ext":1}`, errInvalid,
		func(_, _ string) error { return errNotOAuth })
	if !errors.Is(err, errNotOAuth) || got != (TokenResponse{}) {
		t.Fatalf("ParseTokenResponse with a failing extra = %+v, %v; want errNotOAuth", got, err)
	}
}

func TestTokenResponseSet(t *testing.T) {
	t.Parallel()
	var r TokenResponse
	if err := r.set("unknown", `{"any":1}`, errInvalid, nil); err != nil {
		t.Fatalf("set(unknown) = %v, want nil", err)
	}
	if r != (TokenResponse{}) {
		t.Fatalf("response after set(unknown) = %+v, want it unchanged", r)
	}
	unused := func(name, _ string) error { return fmt.Errorf("%w: extra got %s", errNotOAuth, name) }
	if err := r.set(ParamRefreshToken, `"rt"`, errInvalid, unused); err != nil || r.RefreshToken != "rt" {
		t.Fatalf("refresh_token = %q, %v; want rt without extra", r.RefreshToken, err)
	}
	if err := r.set(ParamScope, `"s"`, errInvalid, unused); !errors.Is(err, errNotOAuth) {
		t.Fatalf("set(scope) = %v, want the scope handed to extra", err)
	}
}

func TestNumberText(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		`"3600"`: "3600", `3600`: "3600", `"36\u0030\u0030"`: "3600", `"-1.5e3"`: "-1.5e3", `-0`: "-0",
		`""`: "", jsonNull: "", `"\ud800"`: "", `" 5"`: "", `"5 "`: "", `"0x10"`: "", `true`: "", `"\"5\""`: "",
	} {
		if got := NumberText(raw); got != want {
			t.Errorf("NumberText(%s) = %q, want %q", raw, got, want)
		}
	}
}

// referenceNumber returns the JSON number raw holds, directly or inside a
// JSON string, false when it holds none.
func referenceNumber(raw json.RawMessage) (string, bool) {
	text := string(raw)
	if raw[0] == '"' && json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	valid := text != "" && strings.TrimSpace(text) == text && json.Valid([]byte(text)) &&
		strings.IndexByte("-0123456789", text[0]) >= 0
	return text, valid
}

// referenceExpiresIn reads expires_in with math/big as a lifetime from a
// nanosecond to 1 year; false when it is not a positive number.
func referenceExpiresIn(raw json.RawMessage) (time.Duration, bool) {
	const year = 365 * 24 * time.Hour
	text, ok := referenceNumber(raw)
	if !ok {
		return 0, false
	}
	secs, _, err := big.ParseFloat(text, decimalBase, floatPrecision, big.ToNearestEven)
	if err != nil {
		mantissa, exponent, _ := strings.Cut(strings.ToLower(text), "e")
		if strings.Trim(mantissa, "-0.") == "" || mantissa[0] == '-' {
			return 0, false
		}
		if strings.HasPrefix(exponent, "-") {
			return time.Nanosecond, true
		}
		return year, true
	}
	switch {
	case secs.Sign() <= 0:
		return 0, false
	case secs.Cmp(big.NewFloat(year.Seconds())) >= 0:
		return year, true
	}
	ns, _ := secs.Mul(secs, big.NewFloat(float64(time.Second))).Int64()
	return max(time.Duration(ns), time.Nanosecond), true
}

// referenceTokenResponse decodes the members of the valid JSON object body
// with encoding/json, false when one of them does not have its type.
func referenceTokenResponse(body string) (TokenResponse, bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &members) != nil {
		return TokenResponse{}, false
	}
	var r TokenResponse
	for name, dst := range map[string]*string{
		"access_token": &r.AccessToken, "token_type": &r.TokenType, "refresh_token": &r.RefreshToken,
	} {
		if raw, ok := members[name]; ok && string(raw) != jsonNull && json.Unmarshal(raw, dst) != nil {
			return TokenResponse{}, false
		}
	}
	if raw, ok := members["expires_in"]; ok && string(raw) != jsonNull {
		d, valid := referenceExpiresIn(raw)
		if !valid {
			return TokenResponse{}, false
		}
		r.ExpiresIn = d
	}
	return r, r.AccessToken != ""
}

func FuzzParseTokenResponse(f *testing.F) {
	for _, s := range []string{
		`{"access_token":"at","token_type":"Bearer","expires_in":3600,"scope":"a b"}`,
		`{"access_token":"at","expires_in":"1e3"}`, `{"access_token":"at","expires_in":-1e400}`,
		`{"access_token":"at","expires_in":1e999999999999}`, `{"access_token":"at","expires_in":0.1}`,
		`{"access_token":"at","expires_in":"86400.000244140625"}`,
		`{"access_token":"at","expires_in":" 5"}`, `{"access_token":"a\u0074","id_token":null}`,
		`{"access_token":""}`, `{"access_token":"a","access_token":"b"}`, `{"scope":7}`, `[]`,
		`{"access_token":"at","x":{"k":1,"k":2}}`, `{"access_token":"at","x":[{"k":{}},{"k":{"k":1}}]}`,
	} {
		f.Add(s)
	}
	f.Fuzz(checkParseTokenResponse)
}

// checkParseTokenResponse fails unless ParseTokenResponse agrees with the
// reference on body.
func checkParseTokenResponse(t *testing.T, body string) {
	var extra []string
	got, err := ParseTokenResponse(body, errInvalid, func(name, _ string) error {
		extra = append(extra, name)
		return nil
	})
	want, ok := TokenResponse{}, false
	if strictObject(body) {
		want, ok = referenceTokenResponse(body)
	}
	if err != nil {
		if !errors.Is(err, errInvalid) || got != (TokenResponse{}) || ok {
			t.Fatalf("ParseTokenResponse(%q) = %+v, %v; want %+v", body, got, err, want)
		}
		return
	}
	// float64 carries the seconds to within a few nanoseconds.
	drift := (got.ExpiresIn - want.ExpiresIn).Abs()
	want.ExpiresIn = got.ExpiresIn
	if !ok || got != want || drift > driftNanos {
		t.Fatalf("ParseTokenResponse(%q) = %+v, want %+v (%v, drift %v)", body, got, want, ok, drift)
	}
	checkExtra(t, body, extra)
}

// checkExtra fails unless extra, sorted in place, lists the members of body
// that a token response does not define.
func checkExtra(t *testing.T, body string, extra []string) {
	t.Helper()
	slices.Sort(extra)
	if want := referenceExtra(body); !slices.Equal(extra, want) {
		t.Fatalf("ParseTokenResponse(%q) handed %q to extra, want %q", body, extra, want)
	}
}

// referenceExtra lists, sorted, the member names of the valid JSON object
// body that a token response does not define.
func referenceExtra(body string) []string {
	var members map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &members) != nil {
		return nil
	}
	var names []string
	for name := range members {
		switch name {
		case "access_token", "token_type", "refresh_token", "expires_in":
		default:
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func TestNewTokenRequest(t *testing.T) {
	t.Parallel()
	endpoint := tokenURL()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := NewTokenRequest(ctx, endpoint, url.Values{})
	if req.Method != http.MethodPost || req.URL.String() != endpoint.String() || req.Context() != ctx ||
		req.Header.Get("Authorization") != "" ||
		req.Header.Get(headerContentType) != "application/x-www-form-urlencoded" ||
		req.Header.Get("Accept") != "application/json" {
		t.Fatalf("NewTokenRequest = %s %v %+v, want a form POST to %v without credentials", req.Method, req.URL,
			req.Header, endpoint)
	}
	req.URL.Path = "/elsewhere"
	if endpoint.Path != tokenPath {
		t.Fatalf("endpoint path after request rewrite = %q, want %s", endpoint.Path, tokenPath)
	}
}

func TestNewTokenRequestReplayableBody(t *testing.T) {
	t.Parallel()
	endpoint := tokenURL()
	form := url.Values{ParamGrantType: {GrantRefreshToken}, ParamClientID: {"app"}}
	req := NewTokenRequest(t.Context(), endpoint, form)
	first, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll = %v, want the body", err)
	}
	again, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody = %v, want a copy", err)
	}
	second, err := io.ReadAll(again)
	if err != nil {
		t.Fatalf("ReadAll = %v, want the copy", err)
	}
	want := "client_id=app&grant_type=refresh_token"
	if string(first) != want || string(second) != want || req.ContentLength != int64(len(want)) {
		t.Fatalf("bodies %q and %q with length %d, want %q twice with its length", first, second, req.ContentLength,
			want)
	}
}

// TestNewTokenRequestEncodesForm sends the form as it is and leaves the
// caller's form unchanged.
func TestNewTokenRequestEncodesForm(t *testing.T) {
	t.Parallel()
	form := url.Values{ParamGrantType: {"client_credentials"}, ParamScope: {"a b"}}
	req := NewTokenRequest(t.Context(), tokenURL(), form)
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll = %v, want the body", err)
	}
	if want := "grant_type=client_credentials&scope=a+b"; string(got) != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if len(form) != 2 {
		t.Fatalf("caller form = %v, want it unchanged", form)
	}
}
