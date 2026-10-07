package cred

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAzureMSIConfigValidate(t *testing.T) {
	if err := (*AzureMSIConfig)(nil).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Validate() = %v, want ErrInvalidConfig", err)
	}
	if err := (&AzureMSIConfig{Resource: "r"}).Validate(); err != nil {
		t.Fatalf("valid Validate() = %v, want nil", err)
	}
	err := (&AzureMSIConfig{Endpoint: "http://imds.example/token", Timeout: -time.Second}).Validate()
	if !errors.Is(err, ErrInsecureTokenURL) || !errors.Is(err, ErrInvalidConfig) || strings.Count(err.Error(),
		"\n") != 2 {
		t.Fatalf("Validate() = %v, want the insecure URL, the missing resource and the negative timeout", err)
	}
}

func TestNewAzureMSI(t *testing.T) {
	if _, err := NewAzureMSI(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewAzureMSI(nil) = %v, want ErrInvalidConfig", err)
	}
	_, err := NewAzureMSI(&AzureMSIConfig{Endpoint: "http://imds.example/token"})
	if !errors.Is(err, ErrInsecureTokenURL) || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want insecure URL and missing resource", err)
	}
	_, err = NewAzureMSI(&AzureMSIConfig{Endpoint: "http://imds.example/token", Resource: "r"})
	if !errors.Is(err, ErrInsecureTokenURL) || !errors.Is(err, ErrInvalidConfig) ||
		strings.Contains(err.Error(), "\n") {
		t.Fatalf("err = %v, want insecure URL alone", err)
	}
	_, err = NewAzureMSI(&AzureMSIConfig{Timeout: -time.Second})
	if !errors.Is(err, ErrInvalidConfig) || strings.Count(err.Error(), "\n") != 1 {
		t.Fatalf("err = %v, want missing resource and negative timeout", err)
	}
}

// TestNewAzureMSIEndpointQuery keeps the query of Endpoint with the parameters
// the source sets overriding it, and refuses a query url.ParseQuery refuses.
func TestNewAzureMSIEndpointQuery(t *testing.T) {
	const endpoint = "http://169.254.169.254/token?x=1&resource=old&api-version=1"
	src, err := NewAzureMSI(&AzureMSIConfig{Endpoint: endpoint, Resource: "r", ClientID: "c"})
	if err != nil {
		t.Fatalf("NewAzureMSI = %v, want a source", err)
	}
	const want = "api-version=2018-02-01&client_id=c&resource=r&x=1"
	if m, ok := src.(*metadataSource); !ok || m.target.RawQuery != want {
		t.Fatalf("NewAzureMSI = %+v, want the query %s", src, want)
	}
	cfg := &AzureMSIConfig{Endpoint: "http://169.254.169.254/token?a=%zz", Resource: "r"}
	const refused = `cred: invalid config: metadata URL query: invalid URL escape "%zz"`
	if _, err := NewAzureMSI(cfg); !errors.Is(err, ErrInvalidConfig) || err.Error() != refused {
		t.Fatalf("NewAzureMSI(a=%%zz) = %v, want %q", err, refused)
	}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) || err.Error() != refused {
		t.Fatalf("Validate(a=%%zz) = %v, want %q", err, refused)
	}
}

func TestNewAzureMSIToken(t *testing.T) {
	rec := newRecording(t, answer(http.StatusOK,
		`{"access_token":"at","token_type":"Bearer","expires_in":"86399","expires_on":"1700000000"}`))
	src, err := NewAzureMSI(&AzureMSIConfig{
		Endpoint: rec.srv.URL + "/token?x=1", Resource: "https://vault", ClientID: "uai",
	})
	if err != nil {
		t.Fatalf("NewAzureMSI = %v, want a source", err)
	}
	tok := nextToken(t, src)
	if tok.Value.Reveal() != wantAccess || !tok.Expires.Equal(time.Unix(expiresOn, 0)) {
		t.Fatalf("token = %q expiring %v, want %s expiring at 1700000000", tok.Value.Reveal(), tok.Expires, wantAccess)
	}
	got := rec.requests()[0]
	want := "api-version=2018-02-01&client_id=uai&resource=https%3A%2F%2Fvault&x=1"
	if got.query.Encode() != want || got.requestHeader.Get("Metadata") != "true" || got.path != "/token" {
		t.Fatalf("request = %+v, want %s on /token with Metadata: true", got, want)
	}
}

// newMSIFor returns an Azure managed identity source whose metadata service
// answers status and body.
func newMSIFor(t *testing.T, status int, body string) TokenSource {
	t.Helper()
	rec := newRecording(t, answer(status, body))
	src, err := NewAzureMSI(&AzureMSIConfig{Endpoint: rec.srv.URL, Resource: "r"})
	if err != nil {
		t.Fatalf("NewAzureMSI = %v, want a source", err)
	}
	return src
}

func TestNewAzureMSITokenErrors(t *testing.T) {
	for _, body := range []string{
		`{"access_token":"at","expires_on":"soon"}`, `{"expires_on":"1700000000"}`, `{"access_token":"a\nb"}`,
	} {
		_, err := newMSIFor(t, http.StatusOK, body).Token(t.Context())
		if !errors.Is(err, ErrInvalidTokenResponse) || !strings.HasPrefix(err.Error(),
			"cred: azure managed identity: ") {
			t.Errorf("%s: err = %v, want ErrInvalidTokenResponse named after the service", body, err)
		}
	}
	_, err := newMSIFor(t, http.StatusBadRequest, `{"error":"invalid_resource"}`).Token(t.Context())
	var oe *OAuth2Error
	if !errors.As(err, &oe) || oe.Status != http.StatusBadRequest || oe.Code != "invalid_resource" ||
		!strings.HasPrefix(err.Error(), "cred: azure managed identity: ") {
		t.Fatalf("err = %v, want the 400 invalid_resource answer named after the service", err)
	}
}

func TestParseMSIResponse(t *testing.T) {
	before := time.Now()
	tok, err := parseMSIResponse(`{"access_token":"at","expires_in":"3600"}`)
	after := time.Now()
	if err != nil {
		t.Fatalf("parseMSIResponse = %v, want a token", err)
	}
	if tok.Expires.Before(before.Add(time.Hour)) || tok.Expires.After(after.Add(time.Hour)) {
		t.Fatalf("Expires = %v, want an hour from the parse", tok.Expires)
	}
	tok, err = parseMSIResponse(`{"access_token":"at","expires_in":3600,"expires_on":null}`)
	if err != nil || tok.Expires.Before(before.Add(time.Hour)) {
		t.Fatalf("parseMSIResponse(null expires_on) = %v, %v, want expires_in to count", tok, err)
	}
	_, err = parseMSIResponse(`{"access_token":"at"} trailing`)
	if !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("parseMSIResponse(trailing data) = %v, want ErrInvalidTokenResponse", err)
	}
}

// TestParseMSIResponseNamesTheFault reports why an answer was refused.
func TestParseMSIResponseNamesTheFault(t *testing.T) {
	tok, err := parseMSIResponse(`{"access_token":"at","expires_in":"soon"}`)
	if want := "invalid token response: expires_in is not a positive number"; tok != nil || !errors.Is(err,
		ErrInvalidTokenResponse) || err.Error() != want {
		t.Fatalf("parseMSIResponse(bad expires_in) = %v, %v, want %q", tok, err, want)
	}
}

// TestParseMSIResponseFarExpiresOn caps at a year an expires_on beyond it, and
// one beyond int64 too.
func TestParseMSIResponseFarExpiresOn(t *testing.T) {
	for _, far := range []string{`99999999999`, `"99999999999999999999"`} {
		before := time.Now()
		tok, err := parseMSIResponse(`{"access_token":"at","expires_on":` + far + `}`)
		if err != nil || tok.Expires.Before(before.Add(maxLifetime)) || tok.Expires.After(time.Now().Add(maxLifetime)) {
			t.Errorf("parseMSIResponse(expires_on %s) = %v, %v, want the expiry capped at a year", far, tok, err)
		}
	}
}

func TestParseMSIResponseExpiresOn(t *testing.T) {
	on := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	epoch := strconv.FormatInt(on.Unix(), decimalBase)
	for _, body := range []string{
		`{"access_token":"at","client_id":"c","expires_in":"60","expires_on":"` + epoch +
			`","ext_expires_in":"60","not_before":"1","resource":"https://vault.azure.net","token_type":"Bearer"}`,
		`{"expires_on":` + epoch + `,"expires_in":"60","access_token":"at"}`,
	} {
		if tok, err := parseMSIResponse(body); err != nil || !tok.Expires.Equal(on) {
			t.Errorf("parseMSIResponse(%s) = %v, %v; want the expiry of expires_on", body, tok, err)
		}
	}
	for _, body := range []string{
		`{"access_token":"at","expires_on":"soon"}`,
		`{"access_token":"at","expires_on":0}`,
		`{"access_token":"at","expires_on":"1","expires_on":"2"}`,
	} {
		if tok, err := parseMSIResponse(body); tok != nil || !errors.Is(err, ErrInvalidTokenResponse) {
			t.Errorf("parseMSIResponse(%s) = %v, %v; want ErrInvalidTokenResponse", body, tok, err)
		}
	}
}

func FuzzParseMSIResponse(f *testing.F) {
	for _, seed := range []string{
		`{"access_token":"at","expires_in":"3600","expires_on":"1700000000"}`,
		`{"access_token":"at","expires_on":null}`,
		`{"access_token":"a\nb"}`, `{"access_token":"at","token_type":"Be arer"}`, `{"access_token":"at"} x`, `[]`,
		`{"access_token":"at","ACCESS_TOKEN":"zz"}`, `{"access_token":"at","expires_on":"99999999999999999999"}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		before := time.Now()
		tok, err := parseMSIResponse(body)
		checkMSIToken(t, body, tok, err, before)
	})
}

// checkMSIToken fails unless parseMSIResponse, called at before on body,
// answered tok and err as the reference reads body: an expires_on, canonical
// Unix seconds, wins over expires_in.
func checkMSIToken(t *testing.T, body string, tok *Token, err error, before time.Time) {
	t.Helper()
	want := readAnswer(body)
	on, dated := jsonMember(body, "expires_on")
	if _, canonical := canonicalEpoch(on); dated && !canonical {
		want = nil
	}
	if want == nil || err != nil {
		checkRefusal(t, body, tok, err, want)
		return
	}
	checkToken(t, body, tok, want)
	if dated {
		checkExpiry(t, on, tok.Expires, before)
		return
	}
	checkLifetime(t, body, tok.Expires, want.lifetime, before)
}
