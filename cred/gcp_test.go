package cred

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

// The problems NewGCPMetadata joins for a bad config, an expiry an ID token
// carries, and the failure of a refused config.
const (
	gcpProblems   = 4
	smallExp      = 42
	wantGCPSource = "NewGCPMetadata = %v, want a source"
)

func fakeJWT(payload string) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString([]byte(payload)) + ".c2ln"
}

func TestNewGCPMetadata(t *testing.T) {
	if _, err := NewGCPMetadata(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewGCPMetadata(nil) = %v, want ErrInvalidConfig", err)
	}
	_, err := NewGCPMetadata(&GCPMetadataConfig{BaseURL: "http://meta.example"})
	if !errors.Is(err, ErrInsecureTokenURL) || !errors.Is(err, ErrInvalidConfig) ||
		strings.Contains(err.Error(), "\n") {
		t.Fatalf("err = %v, want ErrInsecureTokenURL alone", err)
	}
	_, err = NewGCPMetadata(&GCPMetadataConfig{BaseURL: "http://meta.example", Scopes: []string{""}})
	if !errors.Is(err, ErrInsecureTokenURL) || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want insecure URL and bad scope", err)
	}
	for name, cfg := range map[string]*GCPMetadataConfig{
		"empty scope":         {Scopes: []string{""}},
		"comma in scope":      {Scopes: []string{"a,b"}},
		"space in scope":      {Scopes: []string{"x y"}},
		"repeated scope":      {Scopes: []string{"a", "a"}},
		"scopes and audience": {Scopes: []string{"a"}, Audience: "https://svc"},
		"negative timeout":    {Timeout: -time.Second},
	} {
		if _, err := NewGCPMetadata(cfg); !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: err = %v, want one ErrInvalidConfig", name, err)
		}
	}
}

func TestNewGCPMetadataToken(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK, `{"access_token":"at","expires_in":"3599","token_type":"Bearer"}`))
	src, err := NewGCPMetadata(&GCPMetadataConfig{BaseURL: rec.srv.URL + "/?x=1", Scopes: []string{"a", "b"}})
	if err != nil {
		t.Fatalf(wantGCPSource, err)
	}
	before := time.Now()
	tok := nextToken(t, src)
	if tok.Value.Reveal() != wantAccess || tok.Expires.Before(before.Add(3599*time.Second)) {
		t.Fatalf("token = %q expiring %v, want %s expiring in 3599s", tok.Value.Reveal(), tok.Expires, wantAccess)
	}
	got := rec.requests()[0]
	if got.path != gcpAccountPath+"token" || got.query.Encode() != "scopes=a%2Cb&x=1" ||
		got.requestHeader.Get("Metadata-Flavor") != "Google" {
		t.Fatalf("request = %+v, want the token path with scopes a,b and x=1", got)
	}
}

func TestGCPMetadataConfigValidate(t *testing.T) {
	if err := (*GCPMetadataConfig)(nil).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Validate() = %v, want ErrInvalidConfig", err)
	}
	if err := (&GCPMetadataConfig{Scopes: []string{"a"}}).Validate(); err != nil {
		t.Fatalf("valid Validate() = %v, want nil", err)
	}
	cfg := &GCPMetadataConfig{BaseURL: "http://meta.example", Audience: "x", Scopes: []string{"a,b"}, Timeout: -1}
	if err := cfg.Validate(); !errors.Is(err, ErrInsecureTokenURL) || !errors.Is(err, ErrInvalidConfig) ||
		strings.Count(err.Error(), newline) != gcpProblems-1 {
		t.Fatalf("Validate() = %v, want four joined problems", err)
	}
}

// TestNewGCPMetadataBaseURL appends the service account path to the path of
// BaseURL and keeps its query.
func TestNewGCPMetadataBaseURL(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK, okToken))
	src, err := NewGCPMetadata(&GCPMetadataConfig{BaseURL: rec.srv.URL + "/proxy/?x=1"})
	if err != nil {
		t.Fatalf(wantGCPSource, err)
	}
	mustToken(t, src)
	if got := rec.requests()[0]; got.path != "/proxy"+gcpAccountPath+"token" || got.query.Get("x") != "1" {
		t.Fatalf("request = %+v, want the account path below /proxy and x=1 kept", got)
	}
}

// TestNewGCPMetadataBaseURLQuery keeps the query of BaseURL with the parameters
// the source sets overriding it, and refuses a query url.ParseQuery refuses.
func TestNewGCPMetadataBaseURLQuery(t *testing.T) {
	src, err := NewGCPMetadata(&GCPMetadataConfig{BaseURL: "http://metadata.google.internal/?x=1&scopes=old"})
	const want = "scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform&x=1"
	if m, ok := src.(*metadataSource); err != nil || !ok || m.target.RawQuery != want {
		t.Fatalf("NewGCPMetadata = %+v, %v, want the query %s", src, err, want)
	}
	cfg := &GCPMetadataConfig{BaseURL: "http://metadata.google.internal/?a=1;b=2"}
	const refused = "cred: invalid config: metadata URL query: invalid semicolon separator in query"
	if _, err := NewGCPMetadata(cfg); !errors.Is(err, ErrInvalidConfig) || err.Error() != refused {
		t.Fatalf("NewGCPMetadata(a=1;b=2) = %v, want %q", err, refused)
	}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) || err.Error() != refused {
		t.Fatalf("Validate(a=1;b=2) = %v, want %q", err, refused)
	}
}

func TestNewGCPMetadataTokenIDToken(t *testing.T) {
	jwt := fakeJWT(`{"aud":"https://svc","exp":1700000000}`)
	rec := newRecording(t, answer(http.StatusOK, jwt+"\n"))
	src, err := NewGCPMetadata(&GCPMetadataConfig{BaseURL: rec.srv.URL, Audience: "https://svc"})
	if err != nil {
		t.Fatalf(wantGCPSource, err)
	}
	tok := nextToken(t, src)
	if tok.Value.Reveal() != jwt || !tok.Expires.Equal(time.Unix(expiresOn, 0)) {
		t.Fatalf("token = %q expiring %v, want the ID token expiring at 1700000000", tok.Value.Reveal(), tok.Expires)
	}
	got := rec.requests()[0]
	want := url.Values{"audience": {"https://svc"}, "format": {"full"}}
	if got.path != gcpAccountPath+"identity" || got.query.Encode() != want.Encode() {
		t.Fatalf("request = %+v, want the identity path with %s", got, want.Encode())
	}
}

func TestNewGCPMetadataTokenErrors(t *testing.T) {
	for _, tt := range []struct {
		body     string
		audience string
	}{
		{`{"expires_in":10}`, ""},
		{fakeJWT(`{"aud":"x"}`), "x"},
	} {
		rec := newRecording(t, answer(http.StatusOK, tt.body))
		src, err := NewGCPMetadata(&GCPMetadataConfig{BaseURL: rec.srv.URL, Audience: tt.audience})
		if err != nil {
			t.Fatalf(wantGCPSource, err)
		}
		_, err = src.Token(t.Context())
		if !errors.Is(err, ErrInvalidTokenResponse) || !strings.HasPrefix(err.Error(), "cred: gcp metadata: ") {
			t.Errorf("%s: err = %v, want ErrInvalidTokenResponse named after the service", tt.body, err)
		}
	}
	rec := newRecording(t, answer(http.StatusNotFound, "not found"))
	src, err := NewGCPMetadata(&GCPMetadataConfig{BaseURL: rec.srv.URL})
	if err != nil {
		t.Fatalf(wantGCPSource, err)
	}
	var oe *OAuth2Error
	if _, err := src.Token(t.Context()); !errors.As(err, &oe) || oe.Status != http.StatusNotFound {
		t.Fatalf("Token = %v, want an *OAuth2Error of status 404", err)
	}
}

// TestParseIDTokenNotAJWT names a body that is no compact JWT, with a refusal
// built once.
func TestParseIDTokenNotAJWT(t *testing.T) {
	tok, err := parseIDToken("a.b")
	if want := "invalid token response: ID token is not a JWT"; tok != nil || !errors.Is(err,
		ErrInvalidTokenResponse) || !errors.Is(err, errIDTokenNotJWT) || err.Error() != want {
		t.Fatalf("parseIDToken(a.b) = %v, %v, want errIDTokenNotJWT reading %q", tok, err, want)
	}
	assertAllocs(t, 0, func() {
		if _, err := parseIDToken("a.b"); !errors.Is(err, errIDTokenNotJWT) {
			t.Fatalf("parseIDToken(a.b) error = %v, want errIDTokenNotJWT", err)
		}
	})
}

func TestParseIDToken(t *testing.T) {
	jwt := fakeJWT(`{"exp":42}`)
	if tok, err := parseIDToken(" " + jwt + "\n"); err != nil || tok.Value.Reveal() != jwt ||
		!tok.Expires.Equal(time.Unix(smallExp, 0)) {
		t.Fatalf("parseIDToken = %v, %v, want the trimmed JWT expiring at 42", tok, err)
	}
	tok, err := parseIDToken(fakeJWT(`{"exp":99999999999}`))
	if err != nil || tok.Expires.After(time.Now().Add(maxLifetime)) {
		t.Fatalf("parseIDToken(far exp) = %v, %v, want an expiry within MaxLifetime", tok, err)
	}
	for _, jwt := range []string{
		"", "a.b", "a.b.c.d", jwt + ".extra", jwt + "\x01",
		fakeJWT(`{"sub":"x"}`), fakeJWT(`{"exp":null}`), fakeJWT(`{"exp":0}`), fakeJWT(`{"exp":1,"exp":2}`),
		fakeJWT(`[1]`),
	} {
		if _, err := parseIDToken(jwt); !errors.Is(err, ErrInvalidTokenResponse) {
			t.Errorf("parseIDToken(%q) = %v, want ErrInvalidTokenResponse", jwt, err)
		}
	}
	if _, err := parseIDToken(fakeJWT(`{"sub":"x"}`)); !errors.Is(err, errIDTokenNoExp) {
		t.Errorf("parseIDToken(no exp) = %v, want errIDTokenNoExp", err)
	}
}

func FuzzParseIDToken(f *testing.F) {
	for _, seed := range []string{
		fakeJWT(`{"exp":42}`), " " + fakeJWT(`{"exp":"42"}`) + "\n", fakeJWT(`{"exp":null}`),
		fakeJWT(`{"exp":1,"exp":2}`),
		fakeJWT(`{"exp":99999999999}`) + "\x01", "a.b.c", "", fakeJWT(`{"exp":99999999999999999999}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		before := time.Now()
		tok, err := parseIDToken(body)
		checkIDToken(t, body, tok, err, before)
	})
}

// checkIDToken fails unless parseIDToken, called at before on body, answered
// tok and err as the reference reads body: the token of the trimmed compact
// JWS, expiring at the exp of its payload, or a refusal.
func checkIDToken(t *testing.T, body string, tok *Token, err error, before time.Time) {
	t.Helper()
	want, exp := referenceIDToken(body)
	if want == nil || err != nil {
		checkRefusal(t, body, tok, err, want)
		return
	}
	checkToken(t, body, tok, want)
	checkExpiry(t, exp, tok.Expires, before)
}

// jwsParts counts the segments of a compact JWS.
const jwsParts = 3

// referenceIDToken returns the token of the trimmed body and the exp of its
// payload, nil unless body is a header value and a compact JWS whose payload,
// unpadded base64url, is a strict JSON object with a canonical Unix exp.
func referenceIDToken(body string) (tok *referenceAnswer, exp string) {
	jwt := strings.TrimSpace(body)
	parts := strings.Split(jwt, ".")
	if len(parts) != jwsParts || strings.ContainsAny(parts[1], "\r\n") || !syntax.IsFieldValue(jwt) {
		return nil, ""
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, ""
	}
	exp, dated := jsonMember(string(payload), "exp")
	if _, strict := strictMembers(string(payload)); !strict || !dated {
		return nil, ""
	}
	if _, canonical := canonicalEpoch(exp); !canonical {
		return nil, ""
	}
	return &referenceAnswer{access: jwt}, exp
}

func TestParseIDTokenPayload(t *testing.T) {
	valid := strings.Split(fakeJWT(`{"exp":42}`), ".")[1]
	trailingBitSet := valid[:len(valid)-1] + string(valid[len(valid)-1]+1)
	for _, payload := range []string{"%%%", trailingBitSet} {
		_, err := parseIDToken("a." + payload + ".c")
		if !errors.Is(err, ErrInvalidTokenResponse) || !errors.Is(err, errIDTokenPayload) ||
			!strings.HasSuffix(err.Error(), "payload is not base64url") {
			t.Errorf("payload %q: err = %v, want errIDTokenPayload", payload, err)
		}
	}
}

func TestParseAccessToken(t *testing.T) {
	tok, err := parseAccessToken(`{"access_token":"at","token_type":"MAC"}`)
	if err != nil || tok.Value.Reveal() != wantAccess || tok.Type != "MAC" || !tok.Expires.IsZero() {
		t.Fatalf("parseAccessToken = %+v, %v, want MAC at without expiry", tok, err)
	}
	for _, body := range []string{`{"token_type":"Bearer"}`, `{"access_token":"a\r\nb"}`} {
		if tok, err := parseAccessToken(body); tok != nil || !errors.Is(err, ErrInvalidTokenResponse) {
			t.Errorf("%s: %v, %v, want ErrInvalidTokenResponse", body, tok, err)
		}
	}
	_, zeroErr := parseAccessToken(`{"access_token":"at","expires_in":0}`)
	if want := "invalid token response: expires_in is not a positive number"; !errors.Is(zeroErr,
		ErrInvalidTokenResponse) || zeroErr.Error() != want {
		t.Fatalf("parseAccessToken(zero expires_in) = %v, want %q", zeroErr, want)
	}
}

// checkAnswer fails unless parseAccessToken, called at before on body,
// answered tok and err as the reference reads body: its token, expiring its
// lifetime after the parse, or a refusal wrapping ErrInvalidTokenResponse.
func checkAnswer(t *testing.T, body string, tok *Token, err error, before time.Time) {
	t.Helper()
	want := readAnswer(body)
	if want == nil || err != nil {
		checkRefusal(t, body, tok, err, want)
		return
	}
	checkToken(t, body, tok, want)
	checkLifetime(t, body, tok.Expires, want.lifetime, before)
}

func FuzzParseAccessToken(f *testing.F) {
	for _, seed := range []string{
		okToken, `{"access_token":"at","token_type":"MAC","expires_in":"60"}`,
		`{"access_token":"at","expires_in":null}`, `{"token_type":"Bearer"}`, `{"access_token":"a\r\nb"}`,
		`{"access_token":"at","expires_in":0}`,
		`{"access_token":"at","expires_on":"1700000000"}`, `{"access_token":"at","access_token":"bt"}`, `[]`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		before := time.Now()
		tok, err := parseAccessToken(body)
		checkAnswer(t, body, tok, err, before)
	})
}
