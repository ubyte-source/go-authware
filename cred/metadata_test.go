package cred

import (
	"encoding/json"
	"errors"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/secret"
)

func TestCheckMetadataURL(t *testing.T) {
	accept := []string{
		"http://169.254.169.254/metadata/identity/oauth2/token",
		"http://metadata.google.internal",
		"http://[fe80::1]/token",
		"http://127.0.0.1:8080/token",
		"https://metadata.example/token",
	}
	for _, raw := range accept {
		if u, err := checkMetadataURL(raw); err != nil || u.String() != raw {
			t.Errorf("checkMetadataURL(%q) = %v, %v, want it back", raw, u, err)
		}
	}
	reject := []string{
		"http://metadata.example/token",
		"http://user:pw@169.254.169.254/token",
		"ftp://169.254.169.254/token",
		"http://10.0.0.1/token",
		"://",
	}
	for _, raw := range reject {
		u, err := checkMetadataURL(raw)
		if u != (url.URL{}) || !errors.Is(err, ErrInsecureTokenURL) || !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%q: %v, %v, want the zero URL and ErrInsecureTokenURL", raw, u, err)
		}
	}
}

// TestMetadataURL returns a metadata URL with its query parsed.
func TestMetadataURL(t *testing.T) {
	p := problems.New(ErrInvalidConfig)
	u, q := metadataURL(p, "http://169.254.169.254/token?b=%41&a=x&a=y")
	want := url.Values{"a": {"x", "y"}, "b": {"A"}}
	if err := p.Err(); err != nil || u.Path != "/token" || !maps.EqualFunc(q, want, slices.Equal) {
		t.Fatalf("metadataURL = %v, %v, %v, want /token with a=x, a=y and b=A", u, q, err)
	}
}

// TestMetadataURLRefused records why url.ParseQuery refuses the query, and
// returns no query for an insecure URL.
func TestMetadataURLRefused(t *testing.T) {
	const prefix = "cred: invalid config: metadata URL query: "
	for raw, want := range map[string]string{
		"http://169.254.169.254/?a=%zz":   prefix + `invalid URL escape "%zz"`,
		"http://169.254.169.254/?a=1;b=2": prefix + "invalid semicolon separator in query",
	} {
		p := problems.New(ErrInvalidConfig)
		metadataURL(p, raw)
		err := p.Err()
		if !errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrInsecureTokenURL) || err.Error() != want {
			t.Errorf("metadataURL(%q) recorded %v, want %q", raw, err, want)
		}
	}
	p := problems.New(ErrInvalidConfig)
	if u, q := metadataURL(p, "http://metadata.example/?a=1"); u != (url.URL{}) || len(q) != 0 ||
		!errors.Is(p.Err(), ErrInsecureTokenURL) {
		t.Fatalf("metadataURL(insecure) = %v, %v, %v, want the zero URL, no query and ErrInsecureTokenURL", u, q,
			p.Err())
	}
}

func TestMetadataURLMatchesParseQuery(t *testing.T) {
	const prefix = "cred: invalid config: metadata URL query: "
	for _, query := range []string{
		"", "a", "a=1&a=2&b", "+=%41+b", "a=b=c", "&&a=&=b", "a=%zz", "a=%4", "%zz=1&b=2", "a=1;b=2",
	} {
		raw := "http://169.254.169.254/?" + query
		want, wantErr := url.ParseQuery(query)
		p := problems.New(ErrInvalidConfig)
		u, got := metadataURL(p, raw)
		if wantURL, err := url.Parse(raw); err != nil || u != *wantURL {
			t.Errorf("metadataURL(%q) URL = %v, want %v", raw, &u, wantURL)
		}
		if !maps.EqualFunc(got, want, slices.Equal) {
			t.Errorf("metadataURL(%q) query = %v, want %v", raw, got, want)
		}
		err := p.Err()
		if wantErr == nil && err != nil {
			t.Errorf("metadataURL(%q) recorded %v, want nothing", raw, err)
		}
		if wantErr != nil && (!errors.Is(err, ErrInvalidConfig) || err.Error() != prefix+wantErr.Error()) {
			t.Errorf("metadataURL(%q) recorded %v, want %q", raw, err, prefix+wantErr.Error())
		}
	}
}

func TestIsMetadataHost(t *testing.T) {
	for host, want := range map[string]bool{
		"169.254.169.254": true, "METADATA.google.internal": true, "fe80::1": true,
		"metadata.google.internal.evil": false, "10.0.0.1": false, "": false,
	} {
		if got := isMetadataHost(host); got != want {
			t.Errorf("isMetadataHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// newMetadata returns a source for target whose token is the answer body.
func newMetadata(tb testing.TB, target string) *metadataSource {
	tb.Helper()
	u, err := url.Parse(target)
	if err != nil {
		tb.Fatalf("Parse(%q) = %v, want a URL", target, err)
	}
	return &metadataSource{
		client:  netguard.Client(nil, time.Second),
		parse:   func(body string) (*Token, error) { return &Token{Value: secret.New(body)}, nil },
		service: "probe",
		target:  u,
		header:  "X-Probe",
		value:   "1",
	}
}

func TestMetadataSourceToken(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK, `{"ok":true}`))
	if got := mustToken(t, newMetadata(t, rec.srv.URL+"/x")); got != `{"ok":true}` {
		t.Fatalf("token = %q, want the answer body", got)
	}
	if got := rec.requests()[0]; got.requestHeader.Get("X-Probe") != "1" || got.method != http.MethodGet ||
		got.path != "/x" {
		t.Fatalf("request = %+v, want GET /x with X-Probe: 1", got)
	}
}

// TestMetadataSourceTokenPassesTheContext sends the request under the context
// Token gets.
func TestMetadataSourceTokenPassesTheContext(t *testing.T) {
	m := newMetadata(t, idpEndpoint)
	transport := &markedTransport{}
	m.client = &http.Client{Transport: transport}
	if _, err := m.Token(marked(t)); err != nil || transport.marked.Load() != 1 {
		t.Fatalf("Token = %v after %d marked requests, want nil after 1", err, transport.marked.Load())
	}
}

func TestMetadataSourceTokenStatus(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusMultipleChoices} {
		rec := newRecording(t, answer(status, "no identity assigned"))
		_, err := newMetadata(t, rec.srv.URL).Token(t.Context())
		var oe *OAuth2Error
		if !errors.As(err, &oe) || oe.Status != status || oe.Description != "no identity assigned" ||
			!strings.HasPrefix(err.Error(), "cred: probe: ") {
			t.Errorf("%d: err = %v, want *OAuth2Error with that status", status, err)
		}
	}
}

// TestMetadataSourceTokenOversized reads a success answer of 1 MiB, refuses one
// a byte longer as an invalid response, and keeps the status of an error answer
// over 1 MiB.
func TestMetadataSourceTokenOversized(t *testing.T) {
	exact := newRecording(t, answer(http.StatusOK, strings.Repeat("x", mib)))
	if tok, err := newMetadata(t, exact.srv.URL).Token(t.Context()); err != nil || tok.Value.Len() != mib {
		t.Fatalf("1 MiB success = %v, want its body as the token", err)
	}
	huge := newRecording(t, answer(http.StatusOK, strings.Repeat("x", mib+1)))
	_, err := newMetadata(t, huge.srv.URL).Token(t.Context())
	if !errors.Is(err, ErrInvalidTokenResponse) || errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversized success err = %v, want ErrInvalidTokenResponse alone", err)
	}
	_, err = newMetadata(t, hugeAnswer(t, http.StatusServiceUnavailable).URL).Token(t.Context())
	var refused *OAuth2Error
	if !errors.As(err, &refused) || refused.Status != http.StatusServiceUnavailable || !refused.Transient() {
		t.Fatalf("oversized 503 err = %v, want a transient *OAuth2Error of status 503", err)
	}
}

func TestMetadataSourceTokenErrors(t *testing.T) {
	sink := newRecording(t, answer(http.StatusOK, "{}"))
	redirect := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.srv.URL, http.StatusFound)
	})
	var oe *OAuth2Error
	if _, err := newMetadata(t, redirect.URL).Token(t.Context()); !errors.As(err, &oe) || len(sink.requests()) != 0 {
		t.Fatalf("Token(redirect) = %v after %d requests to the target, want an *OAuth2Error after 0", err,
			len(sink.requests()))
	}
	_, err := newMetadata(t, "http://127.0.0.1:1/x").Token(t.Context())
	if !errors.As(err, new(*url.Error)) || !strings.HasPrefix(err.Error(), "cred: probe: ") {
		t.Errorf("refused connection err = %v, want *url.Error named after the service", err)
	}
	ok := newRecording(t, answer(http.StatusOK, "{}"))
	failing := newMetadata(t, ok.srv.URL)
	failing.parse = func(string) (*Token, error) { return nil, errSource }
	_, err = failing.Token(t.Context())
	if !errors.Is(err, errSource) || !strings.HasPrefix(err.Error(), "cred: probe: ") {
		t.Fatalf("parse err = %v, want errSource named after the service", err)
	}
}

func TestParseEpoch(t *testing.T) {
	for raw, want := range map[string]time.Time{
		`1700000000`:   time.Unix(expiresOn, 0),
		`"1700000000"`: time.Unix(expiresOn, 0),
		`1`:            time.Unix(1, 0),
	} {
		if got, err := parseEpoch(raw, errExpNotPositive); err != nil || !got.Equal(want) {
			t.Errorf("%s: %v, %v, want %v", raw, got, err, want)
		}
	}
	if got, err := parseEpoch(`null`, errExpNotPositive); err != nil || !got.IsZero() {
		t.Errorf("parseEpoch(null) = %v, %v, want the zero time", got, err)
	}
	for _, raw := range []string{`0`, `-5`, `"x"`, `1.5`, `1.0`, `1e3`, `"null"`, `"1e3"`, `"0"`,
		`-99999999999999999999`, `"-9223372036854775809"`, `99999999999999999999.5`} {
		if got, err := parseEpoch(raw, errExpNotPositive); !got.IsZero() || !errors.Is(err, errExpNotPositive) {
			t.Errorf("%s: %v, %v, want the refusal of a non-positive exp", raw, got, err)
		}
	}
}

func TestParseEpochCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// a fractional now tells the cap from its whole second
		time.Sleep(time.Second / 2)
		limit := time.Now().Add(maxLifetime)
		for raw, want := range map[string]time.Time{
			strconv.FormatInt(limit.Unix(), decimalBase):   time.Unix(limit.Unix(), 0),
			strconv.FormatInt(limit.Unix()+1, decimalBase): limit,
			`9223372036854775807`:                          limit,
			`9223372036854775808`:                          limit,
			`"99999999999999999999"`:                       limit,
		} {
			if got, err := parseEpoch(raw, errExpNotPositive); err != nil || !got.Equal(want) {
				t.Errorf("%s: %v, %v, want %v", raw, got, err, want)
			}
		}
	})
}

func FuzzParseEpoch(f *testing.F) {
	for _, seed := range []string{`1700000000`, `"1700000000"`, `null`, `0`, `-5`, `1.5`, `"1e3"`,
		`9223372036854775807`, `9223372036854775808`, `"99999999999999999999"`, `-99999999999999999999`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// parseEpoch reads member values of validated documents only.
		if !json.Valid([]byte(raw)) || !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw {
			return
		}
		before := time.Now()
		got, err := parseEpoch(raw, errExpNotPositive)
		checkEpoch(t, raw, got, err, before)
	})
}

// checkEpoch fails unless parseEpoch, called with raw at before, answered
// got and err as the grammar of positive Unix seconds demands.
func checkEpoch(t *testing.T, raw string, got time.Time, err error, before time.Time) {
	t.Helper()
	if err != nil {
		checkEpochRefused(t, raw, got, err)
		return
	}
	if raw != jsonNull {
		checkExpiry(t, raw, got, before)
		return
	}
	if !got.IsZero() {
		t.Fatalf("null: %v, want the zero time", got)
	}
}

// checkEpochRefused fails unless raw is not canonical and parseEpoch refused
// it with the zero time and ErrInvalidTokenResponse.
func checkEpochRefused(t *testing.T, raw string, got time.Time, err error) {
	t.Helper()
	if _, canonical := canonicalEpoch(raw); canonical || !got.IsZero() || !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("%s: %v, %v, want a refusal wrapping ErrInvalidTokenResponse", raw, got, err)
	}
}

// TestPositiveSeconds reads positive JSON integers, one beyond int64 as its
// largest value, and refuses every other number with zero.
func TestPositiveSeconds(t *testing.T) {
	for _, tc := range []struct {
		text string
		n    int64
		ok   bool
	}{
		{"1", 1, true}, {"9223372036854775807", math.MaxInt64, true}, {"9223372036854775808", math.MaxInt64, true},
		{"0", 0, false}, {"-1", 0, false}, {"-9223372036854775809", 0, false}, {"1.5", 0, false}, {"1e3", 0, false},
		{"", 0, false},
	} {
		if n, ok := positiveSeconds(tc.text); n != tc.n || ok != tc.ok {
			t.Errorf("positiveSeconds(%q) = %d, %t; want %d, %t", tc.text, n, ok, tc.n, tc.ok)
		}
	}
}

// TestEpochMember reads the named epoch member and skips the others.
func TestEpochMember(t *testing.T) {
	var at time.Time
	walk := epochMember(msiExpiresOn, errExpiresOnNotPositive, &at)
	if err := walk("expires_in", `"x"`); err != nil || !at.IsZero() {
		t.Fatalf("walk(other member) = %v, set %v; want it skipped", err, at)
	}
	if err := walk(msiExpiresOn, `"1700000000"`); err != nil || !at.Equal(time.Unix(expiresOn, 0)) {
		t.Fatalf("walk(expires_on) = %v, set %v; want %v", err, at, time.Unix(expiresOn, 0))
	}
	if err := walk(msiExpiresOn, "-1"); !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("walk(expires_on -1) = %v, want ErrInvalidTokenResponse", err)
	}
}
