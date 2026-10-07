package cred

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

// Reference SigV4 credentials and fixtures.
const (
	awsExampleID  = "AKIDEXAMPLE"
	awsExampleKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	awsExampleSTS = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIe" +
		"oIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0" +
		"wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDr" +
		"ypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// vanillaSig is the signature of get-vanilla and of every request that shares
	// its canonical request.
	vanillaSig = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"

	exampleURL        = "https://example.amazonaws.com/"
	myHeader          = "My-Header1"
	signedMyHeader    = "host;my-header1;x-amz-date"
	signedContentType = "content-type;host;x-amz-date"
	signedS3          = "host;x-amz-content-sha256;x-amz-date"
	unreservedChars   = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	lambdaInvokePath  = "2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:f/invocations"

	iamCanonical = "GET\n/\nAction=ListUsers&Version=2010-05-08\n" +
		"content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\n" +
		"x-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\n" + emptySHA256
)

func newTestSigV4(tb testing.TB, service, sessionToken string) *sigV4 {
	tb.Helper()
	signer, err := NewSigV4(&SigV4Config{
		AccessKey: awsExampleID, SecretKey: secret.New(awsExampleKey), SessionToken: secret.New(sessionToken),
		Region: testRegion, Service: service,
	})
	if err != nil {
		tb.Fatalf("NewSigV4 = %v, want a signer", err)
	}
	s, ok := signer.(*sigV4)
	if !ok {
		tb.Fatalf("NewSigV4 = %T, want a *sigV4", signer)
	}
	return s
}

// awsExampleTime is the signing instant of the reference vectors, given in a
// zone other than UTC.
func awsExampleTime(tb testing.TB) time.Time {
	tb.Helper()
	at, err := time.Parse(time.RFC3339, "2015-08-30T13:36:00+01:00")
	if err != nil {
		tb.Fatalf("Parse(signing instant) = %v, want a time", err)
	}
	return at
}

// Literals of the SigV4 tests.
const (
	testLetter        = "a"
	testData          = "data"
	testService       = "service"
	testRegion        = "us-east-1"
	serviceIAM        = "iam"
	serviceS3         = "s3"
	pairSep           = "="
	iamExampleDate    = "20120215"
	iamNextDate       = "20120216"
	awsExampleStamp   = "20150830T123600Z"
	headerAmzDate     = "X-Amz-Date"
	headerContentType = "Content-Type"
	headerContentSHA  = "X-Amz-Content-Sha256"
	connectionHeader  = "Connection"
	unreservedSample  = "AZaz09-_.~"
	wantSigned        = "Sign = %v, want nil"
	// The problems Validate of an empty config with a session token reports,
	// and those NewSigV4 of an empty config reports.
	sigV4ConfigProblems = 5
	newSigV4Problems    = 4
	// mapWalks is how many times a header map is walked, in a new order each.
	mapWalks = 32
	// longHeaderValue sizes the canonical headers at the edge of a size class;
	// canonicalHeaders then allocates canonicalAllocs times: the host value,
	// the lowered names and the two lists, each sized once.
	longHeaderValue = 27
	canonicalAllocs = 4
)

func TestSigV4ConfigValidate(t *testing.T) {
	if err := (*SigV4Config)(nil).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Validate() = %v, want ErrInvalidConfig", err)
	}
	valid := &SigV4Config{AccessKey: testLetter, SecretKey: secret.New("k"), Region: "r", Service: "s"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid Validate() = %v, want nil", err)
	}
	err := (&SigV4Config{SessionToken: secret.New(" t")}).Validate()
	if !errors.Is(err, ErrInvalidConfig) || strings.Count(err.Error(), newline) != sigV4ConfigProblems-1 {
		t.Fatalf("Validate() = %v, want five joined problems", err)
	}
}

func TestNewSigV4(t *testing.T) {
	if _, err := NewSigV4(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewSigV4(nil) = %v, want ErrInvalidConfig", err)
	}
	_, err := NewSigV4(&SigV4Config{})
	if !errors.Is(err, ErrInvalidConfig) || strings.Count(err.Error(), newline) != newSigV4Problems-1 {
		t.Fatalf("err = %v, want four joined problems", err)
	}
	for _, service := range []string{serviceS3, "s3-object-lambda", "s3-outposts", "s3express"} {
		signer, err := NewSigV4(&SigV4Config{AccessKey: testLetter, SecretKey: secret.New("k"), Region: "r",
			Service: service, UnsignedPayload: true})
		if s, ok := signer.(*sigV4); err != nil || !ok || !s.s3Paths {
			t.Fatalf("NewSigV4(%s) = %+v, %v, want a signer of S3 paths", service, signer, err)
		}
	}
}

func TestNewSigV4Rejects(t *testing.T) {
	for name, mutate := range map[string]func(*SigV4Config){
		"access key with newline": func(c *SigV4Config) { c.AccessKey = "AKID\n" },
		"access key with slash":   func(c *SigV4Config) { c.AccessKey = "AK/ID" },
		"session token with CRLF": func(c *SigV4Config) { c.SessionToken = secret.New("tok\r\nX-Evil: 1") },
		"session token spaced":    func(c *SigV4Config) { c.SessionToken = secret.New(" tok") },
		"region with slash":       func(c *SigV4Config) { c.Region = "us/east" },
		"service with space":      func(c *SigV4Config) { c.Service = "s 3" },
		"iam unsigned payload":    func(c *SigV4Config) { c.Service, c.UnsignedPayload = serviceIAM, true },
	} {
		cfg := &SigV4Config{
			AccessKey: awsExampleID, SecretKey: secret.New(awsExampleKey), SessionToken: secret.New(awsExampleSTS),
			Region: testRegion, Service: serviceS3,
		}
		mutate(cfg)
		if _, err := NewSigV4(cfg); !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: err = %v, want one ErrInvalidConfig", name, err)
		}
	}
}

type sigV4Case struct {
	name         string
	method       string
	rawURL       string
	headers      [][2]string
	body         string
	service      string
	sessionToken string
	signed       string
	sig          string
}

// sigV4GetCases returns reference SigV4 vectors of GET requests, signed at
// awsExampleTime.
func sigV4GetCases() []sigV4Case {
	return []sigV4Case{
		{name: "get-vanilla", rawURL: exampleURL, sig: vanillaSig},
		{name: "get-vanilla-empty-path", rawURL: "https://example.amazonaws.com", sig: vanillaSig},
		{name: "get-vanilla-query", rawURL: exampleURL + "?Param1=value1",
			sig: "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"},
		{name: "get-vanilla-query-order-key-case", rawURL: exampleURL + "?Param2=value2&Param1=value1",
			sig: "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"},
		{name: "get-vanilla-query-order-key", rawURL: exampleURL + "?Param1=value2&Param1=value1",
			sig: "5772eed61e12b33fae39ee5e7012498b51d56abc0abb7c60486157bd471c4694"},
		{name: "get-vanilla-query-order-value", rawURL: exampleURL + "?Param1=value2&Param1=Value1",
			sig: "eedbc4e291e521cf13422ffca22be7d2eb8146eecf653089df300a15b2382bd1"},
		{name: "get-vanilla-query-unreserved", rawURL: exampleURL + "?" + unreservedChars + pairSep + unreservedChars,
			sig: "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197"},
		{name: "get-vanilla-utf8-query", rawURL: exampleURL + "?%E1%88%B4=bar",
			sig: "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04"},
		{name: "get-unreserved", rawURL: exampleURL + unreservedChars,
			sig: "07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f"},
		{name: "get-relative", rawURL: exampleURL + "example/..", sig: vanillaSig},
		{name: "get-relative-relative", rawURL: exampleURL + "example1/example2/../..", sig: vanillaSig},
		{name: "get-slash", rawURL: exampleURL + slash, sig: vanillaSig},
		{name: "get-slash-dot-slash", rawURL: exampleURL + "./", sig: vanillaSig},
		{name: "get-slash-pointless-dot", rawURL: exampleURL + "./example",
			sig: "ef75d96142cf21edca26f06005da7988e4f8dc83a165a80865db7089db637ec5"},
		{name: "get-slashes", rawURL: exampleURL + "/example//",
			sig: "9a624bd73a37c9a373b5312afbebe7a714a789de108f0bdfe846570885f57e84"},
		{name: "get-header-value-trim", rawURL: exampleURL,
			headers: [][2]string{{myHeader, " value1"}, {"My-Header2", ` "a   b   c"`}},
			signed:  "host;my-header1;my-header2;x-amz-date",
			sig:     "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736"},
		{name: "get-header-key-duplicate", rawURL: exampleURL,
			headers: [][2]string{{myHeader, "value2"}, {myHeader, "value2"}, {myHeader, "value1"}},
			signed:  signedMyHeader,
			sig:     "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"},
		{name: "get-header-value-order", rawURL: exampleURL,
			headers: [][2]string{
				{myHeader, "value4"}, {myHeader, "value1"}, {myHeader, "value3"}, {myHeader, "value2"},
			},
			signed: signedMyHeader,
			sig:    "08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01"},
	}
}

// sigV4OtherCases returns reference SigV4 vectors of other methods and
// services, signed at awsExampleTime.
func sigV4OtherCases() []sigV4Case {
	return []sigV4Case{
		{name: "post-vanilla", method: http.MethodPost, rawURL: exampleURL,
			sig: "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"},
		{name: "post-vanilla-query", method: http.MethodPost, rawURL: exampleURL + "?Param1=value1",
			sig: "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11"},
		{name: "post-header-key-sort", method: http.MethodPost, rawURL: exampleURL,
			headers: [][2]string{{myHeader, "value1"}}, signed: signedMyHeader,
			sig: "c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c"},
		{name: "post-header-value-case", method: http.MethodPost, rawURL: exampleURL,
			headers: [][2]string{{myHeader, "VALUE1"}}, signed: signedMyHeader,
			sig: "cdbc9802e29d2942e5e10b5bccfdd67c5f22c7c4e8ae67b53629efa58b974b7d"},
		{name: "post-x-www-form-urlencoded", method: http.MethodPost, rawURL: exampleURL,
			headers: [][2]string{{headerContentType, "application/x-www-form-urlencoded"}}, body: "Param1=value1",
			signed: signedContentType,
			sig:    "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"},
		{name: "post-x-www-form-urlencoded-parameters", method: http.MethodPost, rawURL: exampleURL,
			headers: [][2]string{{headerContentType, "application/x-www-form-urlencoded; charset=utf8"}},
			body:    "Param1=value1",
			signed:  signedContentType,
			sig:     "1a72ec8f64bd914b0e42e42607c7fbce7fb2c7465f63e3092b3b0d39fa77a6fe"},
		{name: "post-sts-header-before", method: http.MethodPost, rawURL: exampleURL, sessionToken: awsExampleSTS,
			signed: "host;x-amz-date;x-amz-security-token",
			sig:    "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead"},
		{name: "iam-list-users", rawURL: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			service: serviceIAM,
			headers: [][2]string{{headerContentType, "application/x-www-form-urlencoded; charset=utf-8"}},
			signed:  signedContentType,
			sig:     "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"},
		{name: "default-port-and-ignored-headers", rawURL: "https://example.amazonaws.com:443/",
			headers: [][2]string{
				{authorization, "Basic x"}, {"User-Agent", "ua"}, {"Content-Length", "0"}, {"Expect",
					"100-continue"},
			},
			sig: vanillaSig},
		{name: "ec2-indexed-members", service: "ec2",
			rawURL: "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances&" +
				"InstanceId.1=i-1&InstanceId.2=i-2&InstanceId.3=i-3&" +
				"InstanceId.4=i-4&InstanceId.5=i-5&InstanceId.6=i-6&" +
				"InstanceId.7=i-7&InstanceId.8=i-8&InstanceId.9=i-9&InstanceId.10=i-10&Version=2016-11-15",
			sig: "055c311cb5f9464f3398f26eb28e7f8221f4ee4cfbc727e9a7b74b7bb215891d"},
		{name: "lambda-arn-path", method: http.MethodPost, service: "lambda",
			rawURL: "https://lambda.us-east-1.amazonaws.com/" + lambdaInvokePath,
			sig:    "dcb90e24318f4151cd76c9afae465398a2219074a2962069becf2e5baa71b665"},
		{name: "path-encoded-twice", rawURL: exampleURL + "example%20space/",
			sig: "446b817944c553435b35e813c261ff4e161fff982d1bacdef1c87f6785dd1662"},
		{name: "s3-path-encoded-once", service: serviceS3, rawURL: "https://bucket.s3.amazonaws.com/my%20photo.jpg",
			signed: signedS3,
			sig:    "1ef4294c35418ffc209b84510f8d99b77eb6f9b2bc88064f48e518ab55ea9067"},
		{name: "s3-path-not-normalized", service: serviceS3, rawURL: "https://bucket.s3.amazonaws.com//k//",
			signed: signedS3,
			sig:    "15a67f8a1d28753df1281d30ee4f8f61caf195586d3520c5ca234a2e9163e454"},
		{name: "plus-in-query", rawURL: exampleURL + "?a=b+c&a=b",
			sig: "67711592d9460f812f551e4afeb64da75dce55b650beb46d5b99556d2cd0c487"},
	}
}

func TestSigV4Sign(t *testing.T) {
	for _, tt := range slices.Concat(sigV4GetCases(), sigV4OtherCases()) {
		service, signed := cmp.Or(tt.service, testService), cmp.Or(tt.signed, "host;x-amz-date")
		r := newReq(t, cmp.Or(tt.method, http.MethodGet), tt.rawURL, strings.NewReader(tt.body))
		for _, h := range tt.headers {
			r.Header[h[0]] = append(r.Header[h[0]], h[1])
		}
		if err := newTestSigV4(t, service, tt.sessionToken).signAt(r, awsExampleTime(t)); err != nil {
			t.Fatalf("%s: signAt = %v, want nil", tt.name, err)
		}
		want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/" + service + "/aws4_request, " +
			"SignedHeaders=" + signed + ", Signature=" + tt.sig
		if got := r.Header.Get(authorization); got != want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, got, want)
		}
		if r.Header.Get(headerAmzDate) != awsExampleStamp {
			t.Errorf("%s: X-Amz-Date = %q, want 20150830T123600Z", tt.name, r.Header.Get(headerAmzDate))
		}
	}
	bare := &http.Request{Method: http.MethodGet, URL: newReq(t, http.MethodGet, exampleURL, http.NoBody).URL}
	if err := newTestSigV4(t, testService, "").signAt(bare, awsExampleTime(t)); err != nil ||
		bare.Header.Get(headerAmzDate) != awsExampleStamp || bare.Header.Get(authorization) == "" {
		t.Fatalf("signAt(no header map) = %v with %v, want a signed request", err, bare.Header)
	}
}

func TestSigV4SignCurrentTime(t *testing.T) {
	r := newReq(t, http.MethodGet, exampleURL, http.NoBody)
	before := time.Now().UTC().Truncate(time.Second)
	if err := newTestSigV4(t, testService, "").Sign(t.Context(), r); err != nil {
		t.Fatalf(wantSigned, err)
	}
	after := time.Now().UTC()
	at, err := time.Parse(awsTimeFormat, r.Header.Get(headerAmzDate))
	if err != nil || at.Before(before) || at.After(after) {
		t.Fatalf("X-Amz-Date = %v, %v, want within [%v, %v]", at, err, before, after)
	}
	scope := "Credential=AKIDEXAMPLE/" + at.Format(awsDateFormat) + "/us-east-1/service/aws4_request,"
	if got := r.Header.Get(authorization); !strings.Contains(got, scope) {
		t.Fatalf("Authorization = %q, want scope %q", got, scope)
	}
}

func TestSigV4SignSideEffects(t *testing.T) {
	r := newReq(t, http.MethodPut, "https://bucket.s3.amazonaws.com:8443/k?b=2&a=1", strings.NewReader(testData))
	if err := newTestSigV4(t, serviceS3, awsExampleSTS).Sign(t.Context(), r); err != nil {
		t.Fatalf(wantSigned, err)
	}
	if r.URL.RawQuery != "a=1&b=2" || r.Host != "bucket.s3.amazonaws.com:8443" {
		t.Fatalf("query %q, host %q, want a=1&b=2 and bucket.s3.amazonaws.com:8443", r.URL.RawQuery, r.Host)
	}
	if r.Header.Get(headerContentSHA) != sha256Hex([]byte(testData)) ||
		r.Header.Get("X-Amz-Security-Token") != awsExampleSTS {
		t.Fatalf("headers = %v, want the body hash and the session token", r.Header)
	}
}

func TestSigV4SignUnsignedPayload(t *testing.T) {
	s := newTestSigV4(t, serviceS3, "")
	s.cfg.UnsignedPayload = true
	body := &closeTracker{Reader: strings.NewReader("stream")}
	r := newReq(t, http.MethodPut, "https://bucket.s3.amazonaws.com/k", body)
	if err := s.Sign(t.Context(), r); err != nil {
		t.Fatalf(wantSigned, err)
	}
	if r.Header.Get(headerContentSHA) != "UNSIGNED-PAYLOAD" || body.closed.Load() || r.Body != body {
		t.Fatalf("headers %v, body closed %t, want UNSIGNED-PAYLOAD with the body untouched", r.Header,
			body.closed.Load())
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestSigV4SignErrors(t *testing.T) {
	s := newTestSigV4(t, testService, "")
	noHost := newReq(t, http.MethodGet, exampleURL, http.NoBody)
	noHost.Host, noHost.URL.Host = "", ""
	if err := s.Sign(t.Context(), noHost); !errors.Is(err, ErrMissingHost) {
		t.Fatalf("Sign(no host) = %v, want ErrMissingHost", err)
	}
	broken := newReq(t, http.MethodPost, exampleURL, failingReader{})
	if err := s.Sign(t.Context(), broken); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Sign(failing body) = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestSigV4CanonicalRequest(t *testing.T) {
	r := newReq(t, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", http.NoBody)
	r.Method = ""
	r.Header.Set(headerContentType, "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set(headerAmzDate, awsExampleStamp)
	canonical, signed := newTestSigV4(t, serviceIAM, "").canonicalRequest(r, emptySHA256)
	if string(canonical) != iamCanonical || signed != "content-type;host;x-amz-date" {
		t.Fatalf("canonical request:\n%s\nwant:\n%s", canonical, iamCanonical)
	}
	const wantHash = "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
	if got := sha256Hex(canonical); got != wantHash {
		t.Fatalf("canonical request hash = %s, want %s", got, wantHash)
	}
}

// TestSigV4CanonicalRequestURI checks the path line of canonical requests: the
// reference normalize-path URIs, S3 paths as sent, and the path of an Opaque URL.
func TestSigV4CanonicalRequestURI(t *testing.T) {
	const bucketURL = "https://bucket.s3.amazonaws.com/"
	for _, tc := range []struct{ service, rawURL, opaque, uri string }{
		{testService, exampleURL + "example/..", "", slash},
		{testService, exampleURL + "example1/example2/../..", "", slash},
		{testService, exampleURL + slash, "", slash},
		{testService, exampleURL + "./", "", slash},
		{testService, exampleURL + "./example", "", "/example"},
		{testService, exampleURL + "/example//", "", "/example/"},
		{testService, exampleURL + ".well-known/a%20b", "", "/.well-known/a%2520b"},
		{testService, exampleURL, "//example.amazonaws.com/a%2Fb/../c", "/c"},
		{testService, exampleURL + "p", "//example.amazonaws.com", slash},
		{testService, exampleURL, "///p", "/p"},
		{testService, exampleURL, "/a%2Fb//", "/a%252Fb/"},
		{testService, exampleURL, "a/./b", "/a/b"},
		{serviceS3, bucketURL + "/a/../k//", "", "//a/../k//"},
		{serviceS3, bucketURL, "//bucket.s3.amazonaws.com/my%20photo.jpg", "/my%20photo.jpg"},
		{serviceS3, bucketURL, "/a%zz", "/a%25zz"},
	} {
		r := newReq(t, http.MethodGet, tc.rawURL, http.NoBody)
		r.URL.Opaque = tc.opaque
		canonical, _ := newTestSigV4(t, tc.service, "").canonicalRequest(r, emptySHA256)
		if got := strings.Split(string(canonical), "\n")[1]; got != tc.uri {
			t.Errorf("%s canonical URI of %s with Opaque %q = %q, want %q", tc.service, tc.rawURL, tc.opaque, got,
				tc.uri)
		}
	}
}

// TestWirePath checks wirePath against EscapedPath, and for an Opaque URL against
// the path of the request target that url.URL.RequestURI returns.
func TestWirePath(t *testing.T) {
	for _, u := range []*url.URL{
		{Path: ""}, {Path: "/a b/./c"}, {Path: "/a/b", RawPath: "/a%2Fb"},
		{Opaque: "//h"}, {Opaque: "//h/a%2Fb/../c"}, {Opaque: "///p"}, {Opaque: "//u@h:443/x"},
		{Opaque: "/a%2Fb//"}, {Opaque: "a/./b"},
	} {
		u.Scheme = "https"
		want := u.EscapedPath()
		if u.Opaque != "" {
			want = u.RequestURI()
			if target, err := url.Parse(want); err == nil && target.IsAbs() {
				want = target.EscapedPath()
			}
		}
		if got := wirePath(u); got != want {
			t.Errorf("wirePath(%s) = %q, want %q", u, got, want)
		}
	}
}

// TestNormalizedPath resolves paths from the root, at the edges: no segment
// left, a trailing /. and .. past the root.
func TestNormalizedPath(t *testing.T) {
	for want, paths := range map[string][]string{
		"":            {""},
		slash:         {slash, "//", "/./", "/..", "/a/../..", ".."},
		"/a":          {"/a", "/a/.", "/a/b/..", "/../a", testLetter, "./a"},
		"/a/":         {"/a/", "/a/./", "/a/b/../", "a/"},
		"/a/b":        {"/a//b"},
		"/.a/..b/...": {"/.a/..b/..."},
	} {
		for _, in := range paths {
			if got := normalizedPath(in); got != want {
				t.Errorf("normalizedPath(%q) = %q, want %q", in, got, want)
			}
		}
	}
}

const (
	shortPathLen    = 7
	shortEscapedLen = 4
)

// stringsOver returns every string of at most n bytes of alphabet.
func stringsOver(alphabet string, n int) []string {
	total, level := 1, 1
	for range n {
		level *= len(alphabet)
		total += level
	}
	all := make([]string, 1, total)
	for prefix := 0; len(all) < total; prefix++ {
		for i := range len(alphabet) {
			all = append(all, all[prefix]+alphabet[i:i+1])
		}
	}
	return all
}

func TestNormalizedPathMatchesClean(t *testing.T) {
	for _, p := range stringsOver("/.a", shortPathLen) {
		want := ""
		if p != "" {
			want = path.Clean(slash + p)
			if want != slash && strings.HasSuffix(p, slash) {
				want += slash
			}
		}
		if got := normalizedPath(p); got != want {
			t.Fatalf("normalizedPath(%q) = %q, want %q", p, got, want)
		}
	}
}

// referencePlainSegments reports, with two strings.Contains, whether no slash of
// p is followed by a slash or a dot.
func referencePlainSegments(p string) bool {
	return !strings.Contains(p, "//") && !strings.Contains(p, "/.")
}

func TestPlainSegments(t *testing.T) {
	for _, p := range stringsOver("/.a", shortPathLen) {
		if got, want := plainSegments(p), referencePlainSegments(p); got != want {
			t.Fatalf("plainSegments(%q) = %t, want %t", p, got, want)
		}
	}
}

func TestUnescapedPath(t *testing.T) {
	for _, p := range stringsOver("/%2Fz", shortEscapedLen) {
		want := p
		if decoded, err := url.PathUnescape(p); err == nil {
			want = decoded
		}
		if got := unescapedPath(p); got != want {
			t.Fatalf("unescapedPath(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestJoinLines(t *testing.T) {
	for _, lines := range [][]string{{""}, {testLetter}, {testLetter, "", "bc"}, {"", ""}} {
		want := strings.Join(lines, "\n")
		if got := joinLines(lines...); string(got) != want || cap(got) != len(want) {
			t.Errorf("joinLines(%q) = %q with capacity %d, want %q with capacity %d", lines, got, cap(got), want,
				len(want))
		}
	}
}

func TestStringToSign(t *testing.T) {
	const want = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\n" +
		"f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
	got := stringToSign(awsExampleStamp, "20150830/us-east-1/iam/aws4_request", []byte(iamCanonical))
	if string(got) != want || cap(got) != len(want)+sha256.Size {
		t.Fatalf("stringToSign = %q with capacity %d, want %q with room for its MAC, capacity %d", got, cap(got), want,
			len(want)+sha256.Size)
	}
}

func TestSigV4PayloadHash(t *testing.T) {
	s := newTestSigV4(t, testService, "")
	for _, body := range []io.Reader{nil, http.NoBody, strings.NewReader("")} {
		r := newReq(t, http.MethodGet, exampleURL, body)
		if h, err := s.payloadHash(r); err != nil || h != emptySHA256 {
			t.Fatalf("payloadHash(empty body) = %s, %v, want %s", h, err, emptySHA256)
		}
	}
	// Without a body the hash is a constant, built once.
	for _, r := range []*http.Request{{}, {Body: http.NoBody}} {
		assertAllocs(t, 0, func() {
			if _, err := s.payloadHash(r); err != nil {
				t.Fatalf("payloadHash(no body) = %v, want the hash", err)
			}
		})
	}
}

func TestSigV4PayloadHashKeepsGetBody(t *testing.T) {
	s := newTestSigV4(t, testService, "")
	r := newReq(t, http.MethodPut, exampleURL, strings.NewReader("sent"))
	sent := r.Body
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("fresh")), nil }
	if h, err := s.payloadHash(r); err != nil || h != sha256Hex([]byte("fresh")) || r.Body != sent {
		t.Fatalf("hash = %s, %v, want the hash of the GetBody copy with r.Body untouched", h, err)
	}
}

func TestSigV4PayloadHashLimit(t *testing.T) {
	s := newTestSigV4(t, testService, "")
	for _, size := range []int{mib, mib + 1} {
		body := strings.Repeat(testLetter, size)
		h, err := s.payloadHash(newReq(t, http.MethodPut, exampleURL, strings.NewReader(body)))
		if size == mib && (err != nil || h != sha256Hex([]byte(body))) {
			t.Errorf("1 MiB body: hash = %s, %v, want its hash", h, err)
		}
		if size > mib && (h != "" || !errors.Is(err, ErrBodyTooLarge)) {
			t.Errorf("body over 1 MiB: hash = %q, %v, want ErrBodyTooLarge", h, err)
		}
	}
	// The refusal of a copy over 1 MiB is built once.
	var copied strings.Reader
	over, rc := strings.Repeat(testLetter, mib+1), io.NopCloser(&copied)
	r := newReq(t, http.MethodPut, exampleURL, strings.NewReader(over))
	r.GetBody = func() (io.ReadCloser, error) { copied.Reset(over); return rc, nil }
	assertAllocs(t, 0, func() {
		if h, err := s.payloadHash(r); h != "" || !errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("copy over 1 MiB: hash = %q, %v, want no hash and ErrBodyTooLarge", h, err)
		}
	})
}

func TestSigV4PayloadHashBuffersBody(t *testing.T) {
	s := newTestSigV4(t, testService, "")
	r := newReq(t, http.MethodPut, exampleURL, strings.NewReader(testData))
	r.GetBody, r.ContentLength = nil, -1
	if h, err := s.payloadHash(r); err != nil || h != sha256Hex([]byte(testData)) {
		t.Fatalf("payloadHash = %s, %v, want the hash of data", h, err)
	}
	replay, err := r.GetBody()
	if err != nil {
		t.Fatalf("GetBody = %v, want the buffered body", err)
	}
	for _, rc := range []io.ReadCloser{r.Body, replay} {
		if b, err := io.ReadAll(rc); err != nil || string(b) != testData || r.ContentLength != int64(len(testData)) {
			t.Fatalf("body = %q, %v with length %d, want data with length 4", b, err, r.ContentLength)
		}
	}
}

func TestSigningHost(t *testing.T) {
	for raw, want := range map[string]string{
		"https://a.example:443/": "a.example", "http://a.example:80/": "a.example",
		"https://a.example:80/": "a.example:80", "http://a.example:443/": "a.example:443",
		"https://[::1]:443/": "[::1]", "https://a.example/": "a.example",
		"https://[2001:db8:0:0:0:0:0:1]:443/": "[2001:db8:0:0:0:0:0:1]", "ftp://a.example:443/": "a.example:443",
	} {
		r := newReq(t, http.MethodGet, raw, http.NoBody)
		if got := signingHost(r); got != want {
			t.Errorf("signingHost(%s) = %q, want %q", raw, got, want)
		}
		r.Host = ""
		if got := signingHost(r); got != want {
			t.Errorf("signingHost(%s) via URL = %q, want %q", raw, got, want)
		}
	}
	r := newReq(t, http.MethodGet, "https://a.example/", http.NoBody)
	assertAllocs(t, 0, func() { signingHost(r) })
}

// FuzzSigningHost checks signingHost against net.SplitHostPort applied to
// every host, so skipping a host without the default port changes no answer.
func FuzzSigningHost(f *testing.F) {
	for _, host := range []string{"host.example", "host.example:443", "host.example:80", "[::1]", "[::1]:443", "[::1]x",
		"x]:80", "::1", "a:b:443", ":443", ""} {
		f.Add(host, true)
	}
	f.Fuzz(func(t *testing.T, host string, https bool) {
		scheme, port := "http", "80"
		if https {
			scheme, port = "https", "443"
		}
		want := host
		if h, p, err := net.SplitHostPort(host); err == nil && p == port {
			want = h
			if strings.Contains(h, ":") {
				want = "[" + h + "]"
			}
		}
		if got := signingHost(&http.Request{Host: host, URL: &url.URL{Scheme: scheme}}); got != want {
			t.Fatalf("signingHost(%s://%s) = %q, want %q", scheme, host, got, want)
		}
	})
}

func TestCanonicalQuery(t *testing.T) {
	for raw, want := range map[string]string{
		"":                                 "",
		"&b=2&&a=1":                        "a=1&b=2",
		"b=2&a=1":                          "a=1&b=2",
		"InstanceId.10=b&InstanceId.1=a":   "InstanceId.1=a&InstanceId.10=b",
		"a-b=2&a=1":                        "a=1&a-b=2",
		"k=v2&k=v1&k":                      "k=&k=v1&k=v2",
		"a=b+c&%7E=%2f&x=%zz&&":            "a=b%20c&x=%25zz&~=%2F",
		"space=a%20b%2Bc%3D&%E1%88%B4=bar": "%E1%88%B4=bar&space=a%20b%2Bc%3D",
		"a/b=c/d":                          "a%2Fb=c%2Fd",
		"k=%41+%zz&k=a%4&t=%2":             "k=%2541%2B%25zz&k=a%254&t=%252",
		"+=:&%41=%2b":                      "%20=%3A&A=%2B",
	} {
		if got := canonicalQuery(raw); got != want {
			t.Errorf("canonicalQuery(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestCanonicalQueryAllocs encodes an empty query without allocating, a
// reserved name that fills the encoding buffer into it and the query, and the
// twelve pairs of a query that the stack cannot sort into a third allocation.
func TestCanonicalQueryAllocs(t *testing.T) {
	ec2 := "Action=DescribeInstances&InstanceId.1=i-1&InstanceId.2=i-2&InstanceId.3=i-3&InstanceId.4=i-4&" +
		"InstanceId.5=i-5&InstanceId.6=i-6&InstanceId.7=i-7&InstanceId.8=i-8&InstanceId.9=i-9&InstanceId.10=i-10&" +
		"Version=2016-11-15"
	// The encoding buffer and the query, and with them the slice of the pairs
	// past the eight the stack sorts.
	const encoded, sorted = 2, 3
	eight := "a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8"
	for _, tc := range []struct {
		raw, want string
		allocs    float64
	}{
		{"", "", 0},
		{":", "%3A=", encoded},
		{eight, eight, encoded},
		{eight + "&i=9", eight + "&i=9", sorted},
		{ec2, "Action=DescribeInstances&InstanceId.1=i-1&InstanceId.10=i-10&InstanceId.2=i-2&InstanceId.3=i-3&" +
			"InstanceId.4=i-4&InstanceId.5=i-5&InstanceId.6=i-6&InstanceId.7=i-7&InstanceId.8=i-8&InstanceId.9=i-9&" +
			"Version=2016-11-15", sorted},
	} {
		assertAllocs(t, tc.allocs, func() {
			if got := canonicalQuery(tc.raw); got != tc.want {
				t.Fatalf("canonicalQuery(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func FuzzCanonicalQuery(f *testing.F) {
	for _, seed := range []string{"", "&b=2&&a=1", "k=v2&k=v1&k", "a=b+c&%7E=%2f&x=%zz&&", pairSep, "a/b=c/d"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if got, want := canonicalQuery(raw), referenceCanonicalQuery(raw); got != want {
			t.Fatalf("canonicalQuery(%q) = %q, want %q", raw, got, want)
		}
	})
}

// referenceCanonicalQuery decodes each name and value of raw as a form does,
// a malformed escape kept as text, escapes them with awsEscape and sorts the
// pairs by name, then by value.
func referenceCanonicalQuery(raw string) string {
	var pairs [][2]string
	for part := range strings.SplitSeq(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, pairSep)
		pairs = append(pairs, [2]string{awsEscape(formDecoded(k)), awsEscape(formDecoded(v))})
	}
	slices.SortFunc(pairs, func(a, b [2]string) int {
		return cmp.Or(strings.Compare(a[0], b[0]), strings.Compare(a[1], b[1]))
	})
	joined := make([]string, 0, len(pairs))
	for _, p := range pairs {
		joined = append(joined, p[0]+pairSep+p[1])
	}
	return strings.Join(joined, "&")
}

// formDecoded returns s decoded as a form value, or s when it is malformed.
func formDecoded(s string) string {
	if dec, err := url.QueryUnescape(s); err == nil {
		return dec
	}
	return s
}

// awsEscape is the reference AWS encoding of s: every byte but A-Z a-z 0-9 - _
// . ~ as upper-case %HH, which url.QueryEscape writes but for a space.
func awsEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// TestFormByte reads the first byte of each string as a form decodes it, and
// refuses a '%' without two hex digits after it.
func TestFormByte(t *testing.T) {
	const escaped, lastByte = 3, 0xff
	for _, tc := range []struct {
		in    string
		c     byte
		width int
		ok    bool
	}{
		{"a+", 'a', 1, true}, {"+a", ' ', 1, true}, {"%41", 'A', escaped, true}, {"%2fx", '/', escaped, true},
		{"%ff", lastByte, escaped, true}, {"%zz", 0, 0, false}, {"%4", 0, 0, false}, {"%", 0, 0, false},
		{"%4g", 0, 0, false}, {"%g4", 0, 0, false},
	} {
		if c, width, ok := formByte(tc.in); c != tc.c || width != tc.width || ok != tc.ok {
			t.Errorf("formByte(%q) = %q, %d, %t; want %q, %d, %t", tc.in, c, width, ok, tc.c, tc.width, tc.ok)
		}
	}
}

func TestCanonicalHeaders(t *testing.T) {
	r := newReq(t, http.MethodGet, "https://h.example/", http.NoBody)
	r.Host = "h.example"
	r.Header["X-B"] = []string{" 1  2 ", "3"}
	r.Header["x-b"] = []string{"4"}
	r.Header["A-Empty"] = []string{}
	r.Header.Set(authorization, "secret")
	r.Header.Set("Host", "other.example")
	r.Header.Set("Z", "z")
	for _, hop := range hopByHop() {
		r.Header.Set(hop, "1")
	}
	r.Header["connection"] = []string{" X-Hop ,, close", "x-gone"}
	r.Header.Set("X-Hop", "dropped")
	r.Header["X-GONE"] = []string{"dropped"}
	const want = "host:h.example\nx-b:1 2,3,4\nz:z\n"
	for range mapWalks { // the header map is walked in a new order every time
		if canonical, signed := canonicalHeaders(r); canonical != want || signed != "host;x-b;z" {
			t.Fatalf("canonicalHeaders = %q, %q, want %q, %q", canonical, signed, want, "host;x-b;z")
		}
	}
}

// hopByHop returns the headers that a proxy or the transport may drop or
// rewrite, in the case a request map holds them.
func hopByHop() []string {
	return []string{
		"Authorization", "Content-Length", "Cookie", "Expect", "User-Agent", "X-Amzn-Trace-Id", connectionHeader,
		"Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "Te", "Trailer",
		"Transfer-Encoding", "Upgrade",
	}
}

// TestCanonicalHeadersJoinsTheFirstName joins the values of a name written in
// two cases that sorts before host.
func TestCanonicalHeadersJoinsTheFirstName(t *testing.T) {
	r := &http.Request{Host: "h.example", Header: http.Header{"A": {"1"}, "a": {"2"}}}
	if canonical, signed := canonicalHeaders(r); canonical != "a:1,2\nhost:h.example\n" || signed != "a;host" {
		t.Fatalf("canonicalHeaders = %q, %q, want the values of a joined", canonical, signed)
	}
}

// FuzzCanonicalHeaders checks canonicalHeaders against a reference over the
// "name:value" lines of block: host and the signable headers by sorted
// lower-case name, the trimmed values of one name joined by commas.
func FuzzCanonicalHeaders(f *testing.F) {
	f.Add("h.example", "X-B: 1  2 \nx-b:4\nZ:z\nAuthorization:secret\nHost:other\nuser-agent:u")
	f.Add(" ", "a:\n:b\nA:c\nB: \t x  y \u00a0")
	f.Add("", "connect\u0130on:x-a\nX-A:a\nConnectiox:x-b\nX-B:b\nconnection:x-c\nX-C:c")
	f.Fuzz(func(t *testing.T, host, block string) {
		r := &http.Request{Host: host, Header: http.Header{}}
		for line := range strings.SplitSeq(block, "\n") {
			name, value, _ := strings.Cut(line, ":")
			r.Header[name] = append(r.Header[name], value)
		}
		wantCanonical, wantSignedHeaders := referenceCanonicalHeaders(host, r.Header)
		if canonical, signed := canonicalHeaders(r); canonical != wantCanonical || signed != wantSignedHeaders {
			t.Fatalf("canonicalHeaders(%q, %q) = %q, %q, want %q, %q", host, block, canonical, signed, wantCanonical,
				wantSignedHeaders)
		}
	})
}

// referenceCanonicalHeaders builds the canonical headers of a request to
// host carrying h, one name at a time in byte order: host and every header
// but those of hopByHop and those a Connection header names.
func referenceCanonicalHeaders(host string, h http.Header) (canonical, signed string) {
	values := map[string][]string{}
	add := func(lower, v string) {
		words := strings.FieldsFunc(strings.TrimSpace(v), func(r rune) bool { return r == ' ' })
		values[lower] = append(values[lower], strings.Join(words, " "))
	}
	add("host", host)
	unsigned := connectionOptions(h)
	for _, hop := range append(hopByHop(), "Host") {
		unsigned = append(unsigned, strings.ToLower(hop))
	}
	for _, name := range slices.Sorted(maps.Keys(h)) {
		lower := strings.ToLower(name)
		if slices.ContainsFunc(unsigned, func(u string) bool { return strings.EqualFold(u, lower) }) {
			continue
		}
		for _, v := range h[name] {
			add(lower, v)
		}
	}
	var b strings.Builder
	names := slices.Sorted(maps.Keys(values))
	for _, lower := range names {
		b.WriteString(lower + ":" + strings.Join(values[lower], ",") + "\n")
	}
	return b.String(), strings.Join(names, ";")
}

// connectionOptions returns the non-empty comma-separated options of every
// header of h whose name folds to Connection, trimmed of blanks.
func connectionOptions(h http.Header) []string {
	var options []string
	for name, vals := range h {
		if !strings.EqualFold(name, connectionHeader) {
			continue
		}
		for _, v := range vals {
			for option := range strings.SplitSeq(v, ",") {
				if option = strings.Trim(option, " \t\r\n"); option != "" {
					options = append(options, option)
				}
			}
		}
	}
	return options
}

func TestSignableHeader(t *testing.T) {
	for _, h := range append(hopByHop(), "Host") {
		if signableHeader(strings.ToLower(h)) {
			t.Errorf("signableHeader(%s) = true, want false", strings.ToLower(h))
		}
	}
	if !signableHeader("content-type") || !signableHeader("x-amz-date") || !signableHeader("x-amz-security-token") {
		t.Fatal("signableHeader(content-type, x-amz-date or x-amz-security-token) = false, want true")
	}
}

// TestWriteLowerName lower-cases an ASCII name into the buffer after what it
// holds, and maps any other name as strings.ToLower does.
func TestWriteLowerName(t *testing.T) {
	for _, name := range []string{"", "x-amz-date", "X-Amz-Date", "AZ@[`az{", "\u212Aeep-Alive", "\xffA", "\x80B"} {
		var names strings.Builder
		names.WriteString(pairSep)
		if got, want := writeLowerName(&names, name), strings.ToLower(name); got != want {
			t.Errorf("writeLowerName(%q) = %q, want %q", name, got, want)
		}
	}
	var names strings.Builder
	names.WriteString("x;")
	if got := writeLowerName(&names, "A-B\x7f"); got != "a-b\x7f" || names.String() != "x;a-b\x7f" {
		t.Fatalf("writeLowerName(A-B DEL) = %q leaving %q, want a-b DEL written after x;", got, names.String())
	}
}

// TestWithoutOptions drops the fields that the options of every Connection
// header name, whatever their case or blanks, and keeps the others.
func TestWithoutOptions(t *testing.T) {
	fields := []headerField{{lower: "a"}, {lower: "b"}, {lower: "c"}, {lower: "close"}, {lower: ""}}
	kept := make([]string, 0, len(fields))
	for _, f := range withoutOptions(fields, [][]string{{" A ,, \tclose"}, {"c"}}) {
		kept = append(kept, f.lower)
	}
	if want := []string{"b", ""}; !slices.Equal(kept, want) {
		t.Fatalf("withoutOptions kept %q, want %q", kept, want)
	}
}

// TestSignedFieldsDropsConnectionOptions drops the headers that the Connection
// headers of every case name, and keeps a header with another name.
func TestSignedFieldsDropsConnectionOptions(t *testing.T) {
	h := http.Header{
		connectionHeader: {"x-a"}, "CONNECTION": {"X-B"}, "Connectio": {"x-c"},
		"X-A": {"a"}, "X-B": {"b"}, "X-C": {"c"}, "X-D": {"d"},
	}
	kept := make([]string, 0, len(h))
	for _, f := range signedFields(h, nil) {
		kept = append(kept, f.lower)
	}
	slices.Sort(kept)
	if want := []string{"connectio", "x-c", "x-d"}; !slices.Equal(kept, want) {
		t.Fatalf("signedFields kept %q, want %q", kept, want)
	}
}

// TestNameBytes counts the bytes of every header name.
func TestNameBytes(t *testing.T) {
	if got := nameBytes(http.Header{"A": nil, "Bc": {"x"}, "": {"y"}}); got != len("ABc") {
		t.Fatalf("nameBytes = %d, want 3", got)
	}
}

func TestWriteTrimmed(t *testing.T) {
	for in, want := range map[string]string{
		"": "", " a ": testLetter, `"a   b   c"`: `"a b c"`, "a \t b": "a \t b", "a  b    c ": "a b c",
		"\ta  \t  b": "a \t b",
	} {
		var b strings.Builder
		b.WriteString("x:")
		writeTrimmed(&b, in)
		if b.String() != "x:"+want {
			t.Errorf("writeTrimmed(%q) wrote %q, want %q", in, b.String(), "x:"+want)
		}
	}
}

// TestAppendQueryComponent appends each component decoded as a form value, or
// literal when an escape is malformed, after what the buffer holds.
func TestAppendQueryComponent(t *testing.T) {
	for in, want := range map[string]string{
		"": "", unreservedSample: unreservedSample, "a/b": "a%2Fb", "x y": "x%20y", "=*:é": "%3D%2A%3A%C3%A9",
		"a+b%2B%41%e1%88%b4": "a%20b%2BA%E1%88%B4", "%41+%zz": "%2541%2B%25zz", "a%4": "a%254",
	} {
		if got := appendQueryComponent([]byte(pairSep), in); string(got) != pairSep+want {
			t.Errorf("appendQueryComponent(=, %q) = %q, want %q", in, got, pairSep+want)
		}
	}
}

func TestAWSEncodePath(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "/": "/", "a b/c": "a%20b/c", "//x//": "//x//", "/=+*%:é": "/%3D%2B%2A%25%3A%C3%A9",
	} {
		if got := awsEncodePath(in); got != want {
			t.Errorf("awsEncodePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAppendAWSEncoded(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "\x00\xff~": "%00%FF~", unreservedSample: unreservedSample, "a/b": "a%2Fb", "x y": "x%20y",
		"=+*%:é": "%3D%2B%2A%25%3A%C3%A9",
	} {
		if got := appendAWSEncoded([]byte(pairSep), in); string(got) != pairSep+want {
			t.Errorf("appendAWSEncoded(=, %q) = %q, want %q", in, got, pairSep+want)
		}
	}
}

// FuzzAppendQueryComponent checks appendQueryComponent, after a prefix,
// against url.QueryUnescape and url.QueryEscape.
func FuzzAppendQueryComponent(f *testing.F) {
	for _, seed := range []string{"", "a/b", "=+*%:é ", unreservedChars, "%41+%zz", "a%4", "%e1%88%b4"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, want := appendQueryComponent([]byte(pairSep), in), pairSep+awsEscape(formDecoded(in))
		if string(got) != want {
			t.Fatalf("appendQueryComponent(=, %q) = %q, want %q", in, got, want)
		}
	})
}

func FuzzAWSEncodePath(f *testing.F) {
	for _, seed := range []string{"", "/", "a b/c", "//x//", lambdaInvokePath} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		segments := strings.Split(in, slash)
		for i, segment := range segments {
			segments[i] = awsEscape(segment)
		}
		if got, want := awsEncodePath(in), strings.Join(segments, slash); got != want {
			t.Fatalf("awsEncodePath(%q) = %q, want %q", in, got, want)
		}
	})
}

// sha256Hex is the reference lower-case hex SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestHexString(t *testing.T) {
	var sum [sha256.Size]byte
	for i := range sum {
		sum[i] = byte(i * 8)
	}
	const want = "0008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f8"
	if got := hexString(sum[:]); got != want {
		t.Fatalf("hexString = %s, want %s", got, want)
	}
	// One allocation: the string, encoded on the stack.
	assertAllocs(t, 1, func() { hexString(sum[:]) })
}

func TestDeriveSigningKey(t *testing.T) {
	const wantKey = "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
	if key := deriveSigningKey(awsExampleKey, iamExampleDate, testRegion, serviceIAM); hexString(key[:]) != wantKey {
		t.Fatalf("deriveSigningKey = %x, want %s", key, wantKey)
	}
	const wantMAC = "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"
	if mac := hmacSHA256([]byte("key"), []byte(testData)); hexString(mac[:]) != wantMAC {
		t.Fatalf("hmacSHA256 = %x, want %s", mac, wantMAC)
	}
}

// keyedWith reports whether k is the iam key of date: its scope, its
// Authorization prefix and the MAC of the key derived for date, the HMAC-SHA256
// chain over date, region, service and aws4_request.
func keyedWith(k *datedKey, date string) bool {
	key := []byte("AWS4" + awsExampleKey)
	for _, part := range []string{date, testRegion, serviceIAM, "aws4_request", testData} {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(part))
		key = mac.Sum(nil)
	}
	scope := date + "/us-east-1/iam/aws4_request"
	return k.date == date && k.scope == scope &&
		k.authPrefix == "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"+scope+", SignedHeaders=" &&
		bytes.Equal(k.mac.Sum(nil, []byte(testData)), key)
}

func TestSigV4SigningKey(t *testing.T) {
	s := newTestSigV4(t, serviceIAM, "")
	first := s.signingKey(iamExampleDate)
	if !keyedWith(first, iamExampleDate) {
		t.Fatalf("signingKey = %+v, want the MAC of the 20120215 key", first)
	}
	if again := s.signingKey(iamExampleDate); again != first {
		t.Fatalf("signingKey(same date) = %p, want %p: the key derived once", again, first)
	}
	if next := s.signingKey(iamNextDate); !keyedWith(next, iamNextDate) {
		t.Fatalf("next day signingKey = %+v, want the MAC of the 20120216 key", next)
	}
}

// TestSigV4KeyAfterInterleaved pauses a signer of one day after its load while
// a signer of the next day publishes its key: each gets the key of its own day,
// the paused one publishes nothing and the next signer shares the published key.
func TestSigV4KeyAfterInterleaved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestSigV4(t, serviceIAM, "")
		resume := pauseAfter(s.key.Load, func(k *datedKey) *datedKey { return s.keyAfter(k, iamExampleDate) })
		other := s.signingKey(iamNextDate)
		paused := resume()
		if !keyedWith(paused, iamExampleDate) || !keyedWith(other, iamNextDate) || s.key.Load() != other {
			t.Fatalf("paused signer got %+v, the other %+v, %+v published; want the keys of their days and the "+
				"other one published", paused, other, s.key.Load())
		}
		if again := s.signingKey(iamNextDate); again != other {
			t.Fatalf("next signer got %+v, want the published key of %s, %+v", again, iamNextDate, other)
		}
	})
}

// TestSigV4KeyAfterFoundInterleaved pauses a signer that found the key of its
// day while a signer of the next day publishes its key: the paused one returns
// the key it found and publishes nothing.
func TestSigV4KeyAfterFoundInterleaved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestSigV4(t, serviceIAM, "")
		found := s.signingKey(iamExampleDate)
		resume := pauseAfter(s.key.Load, func(k *datedKey) *datedKey { return s.keyAfter(k, iamExampleDate) })
		other := s.signingKey(iamNextDate)
		if paused := resume(); paused != found || !keyedWith(other, iamNextDate) || s.key.Load() != other ||
			s.signingKey(iamNextDate) != other {
			t.Fatalf("paused signer got %p, %+v published; want %p and the key of %s kept", paused, s.key.Load(),
				found, iamNextDate)
		}
	})
}

// TestDatedKeyAuthorization appends the signed list and the signature in hex to
// the Authorization prefix in one allocation.
func TestDatedKeyAuthorization(t *testing.T) {
	k := &datedKey{authPrefix: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders="}
	signature := make([]byte, sha256.Size)
	for i := range signature {
		signature[i] = byte(i * 8)
	}
	const want = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=0008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f8"
	if got := k.authorization("host;x-amz-date", signature); got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
	assertAllocs(t, 1, func() { k.authorization("host;x-amz-date", signature) })
}

// signAllocs is what the signer of TestSigV4SignAllocs spends, after the day's
// signing key is derived, on each request of that test with at most signedPairs
// query pairs and, once signed, signedNames header names.
const signAllocs = 13

// The most query pairs and header names signAllocs covers.
const (
	signedPairs = 8
	signedNames = 15
)

// TestSigV4SignAllocs signs at signAllocs one pair, five escaped pairs with five
// headers, Connection included, and eight pairs with 15 header names; a ninth
// pair or a sixteenth name costs one more.
func TestSigV4SignAllocs(t *testing.T) {
	s := newTestSigV4(t, testService, "")
	// request returns a bodiless GET of n query pairs whose header map, once
	// signed, holds names names: X-Amz-Date, Authorization and X-<i> headers.
	request := func(n, names int) *http.Request {
		pairs := make([]string, n)
		for i := range pairs {
			pairs[i] = "p" + strconv.Itoa(i) + "=v"
		}
		r := newReq(t, http.MethodGet, "https://example.amazonaws.com/p?"+strings.Join(pairs, "&"), http.NoBody)
		for i := range names - 2 {
			r.Header.Set("X-"+strconv.Itoa(i), "v")
		}
		return r
	}
	five := newReq(t, http.MethodGet, "https://example.amazonaws.com/p?e=::&d=a+b&c=%2F%2f&b=%E1%88%B4&a=%zz",
		http.NoBody)
	for _, name := range []string{"X-One", "X-Two", "Content-Type", "x-lower"} {
		five.Header.Set(name, "v  v")
	}
	five.Header.Set(connectionHeader, "X-Two")
	for _, tc := range []struct {
		r      *http.Request
		allocs float64
	}{
		{request(1, 2), signAllocs}, {five, signAllocs}, {request(signedPairs, signedNames), signAllocs},
		{request(signedPairs+1, signedNames), signAllocs + 1}, {request(signedPairs, signedNames+1), signAllocs + 1},
	} {
		assertAllocs(t, tc.allocs, func() {
			if err := s.Sign(t.Context(), tc.r); err != nil {
				t.Fatalf(wantSigned, err)
			}
		})
	}
	if want := "a=%25zz&b=%E1%88%B4&c=%2F%2F&d=a%20b&e=%3A%3A"; five.URL.RawQuery != want {
		t.Fatalf("signed query = %q, want %q", five.URL.RawQuery, want)
	}
}

// TestSigV4SignSignsWhatArrives sends signed requests that carry every header
// a proxy or the transport may drop or rewrite, over HTTP/2 and through a
// reverse proxy: each header the signature lists arrives as it was sent.
func TestSigV4SignSignsWhatArrives(t *testing.T) {
	arrived := make(chan http.Header, 1)
	record := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	})
	h2 := httptest.NewUnstartedServer(record)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	t.Cleanup(h2.Close)
	backend := serve(t, record)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("Parse(%q) = %v, want a URL", backend.URL, err)
	}
	proxy := serve(t, httputil.NewSingleHostReverseProxy(target).ServeHTTP)
	for _, tc := range []struct {
		via, rawURL, connection string
		base                    http.RoundTripper
	}{
		{"HTTP/2", h2.URL, "keep-alive", h2.Client().Transport},
		{"a proxy", proxy.URL, "close, X-Hop", proxy.Client().Transport},
	} {
		r := newReq(t, http.MethodGet, tc.rawURL+"/p?a=1", http.NoBody)
		for name, value := range map[string]string{
			connectionHeader: tc.connection, "Keep-Alive": "timeout=5", "Proxy-Connection": "keep-alive",
			"Te": "trailers", "Proxy-Authorization": "Basic eDp5", "Trailer": "X-T", "Cookie": "a=1;b=2", "X-Hop": "1",
			"X-Kept": "k",
		} {
			r.Header.Set(name, value)
		}
		resp, err := NewTransport(tc.base, newTestSigV4(t, testService, "")).RoundTrip(r)
		if err != nil {
			t.Fatalf("via %s: RoundTrip = %v, want an answer", tc.via, err)
		}
		closeResponse(t, resp)
		checkArrived(t, tc.via, r.Header, <-arrived)
	}
}

// checkArrived fails unless every header but host that the signature of got
// lists arrived with the values sent carried, x-amz-date set by the signer,
// and x-kept is among them.
func checkArrived(t *testing.T, via string, sent, got http.Header) {
	t.Helper()
	_, list, _ := strings.Cut(got.Get(authorization), "SignedHeaders=")
	list, _, _ = strings.Cut(list, ",")
	for name := range strings.SplitSeq(list, ";") {
		want := sent.Values(name)
		switch name {
		case "host":
			continue
		case "x-amz-date":
			want = got.Values(name)
		}
		if !slices.Equal(got.Values(name), want) || len(want) == 0 {
			t.Errorf("via %s: signed %s arrived as %q, sent as %q", via, name, got.Values(name), want)
		}
	}
	if !strings.Contains(list, "x-kept") {
		t.Errorf("via %s: SignedHeaders=%s, want x-kept signed", via, list)
	}
}

func TestCanonicalHeadersAllocs(t *testing.T) {
	r := newReq(t, http.MethodGet, "https://h.example/", http.NoBody)
	// 81 bytes of canonical headers and 25 of signed ones: bounds one byte
	// short would fall into the 80- and 24-byte size classes and grow a list.
	r.Header.Set(headerAmzDate, awsExampleStamp)
	r.Header.Set(customHeader, strings.Repeat("k", longHeaderValue))
	assertAllocs(t, canonicalAllocs, func() { canonicalHeaders(r) })
	// The stack sorts 15 headers and host, one slice holds more: 37 headers and
	// host fill 38 slots, where a slice sized two short holds 36 and grows.
	const stackFields, extraFields = 15, 35
	for n, allocs := range map[int]float64{stackFields: canonicalAllocs, stackFields + 1: canonicalAllocs + 1,
		extraFields + 2: canonicalAllocs + 1} {
		h := http.Header{}
		for i := range n {
			h.Set("X-Field-"+strconv.Itoa(i), testLetter)
		}
		assertAllocs(t, allocs, func() { canonicalHeaders(&http.Request{Host: "h.example", Header: h}) })
	}
}

// BenchmarkWriteLowerName lowers the header names of a signed request into one
// buffer, against strings.ToLower, which allocates each name.
func BenchmarkWriteLowerName(b *testing.B) {
	names := []string{headerContentType, headerAmzDate, "X-Amz-Security-Token", headerContentSHA}
	size := 0
	for _, name := range names {
		size += len(name)
	}
	lowerAll := func() []string {
		var arena strings.Builder
		arena.Grow(size)
		lowered := make([]string, 0, len(names))
		for _, name := range names {
			lowered = append(lowered, writeLowerName(&arena, name))
		}
		return lowered
	}
	toLowerAll := func() []string {
		lowered := make([]string, 0, len(names))
		for _, name := range names {
			lowered = append(lowered, strings.ToLower(name))
		}
		return lowered
	}
	if got, want := lowerAll(), toLowerAll(); !slices.Equal(got, want) {
		b.Fatalf("writeLowerName = %q, want %q", got, want)
	}
	for name, lower := range map[string]func() []string{"writeLowerName": lowerAll, "strings.ToLower": toLowerAll} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				lower()
			}
		})
	}
}

func BenchmarkHexString(b *testing.B) {
	sum := sha256.Sum256([]byte(testData))
	if got, want := hexString(sum[:]), hex.EncodeToString(sum[:]); got != want {
		b.Fatalf("hexString = %s, want %s", got, want)
	}
	for name, encode := range map[string]func([]byte) string{
		"hexString": hexString, "hex.EncodeToString": hex.EncodeToString,
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				encode(sum[:])
			}
		})
	}
}

func BenchmarkJoinLines(b *testing.B) {
	lines := strings.Split(iamCanonical, newline)
	if got := joinLines(lines...); string(got) != iamCanonical {
		b.Fatalf("joinLines = %q, want %q", got, iamCanonical)
	}
	for name, join := range map[string]func() []byte{
		"joinLines":    func() []byte { return joinLines(lines...) },
		"strings.Join": func() []byte { return []byte(strings.Join(lines, newline)) },
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var joined []byte
			for b.Loop() {
				joined = join()
			}
			if string(joined) != iamCanonical {
				b.Fatalf("%s = %q, want %q", name, joined, iamCanonical)
			}
		})
	}
}

// BenchmarkAppendQueryComponent encodes an escaped query value into a reused
// buffer, against url.QueryUnescape and url.QueryEscape.
func BenchmarkAppendQueryComponent(b *testing.B) {
	const component = "arn%3Aaws%3As3%3A%3A%3Abucket%2Fkey+name~1"
	buf := make([]byte, 0, encodedWidth*len(component))
	if got, want := string(appendQueryComponent(buf, component)), awsEscape(formDecoded(component)); got != want {
		b.Fatalf("appendQueryComponent = %q, want %q", got, want)
	}
	b.Run("appendQueryComponent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			buf = appendQueryComponent(buf[:0], component)
		}
	})
	b.Run("url", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			awsEscape(formDecoded(component))
		}
	})
}

// BenchmarkPlainSegments scans a Lambda invoke path once, against two
// strings.Contains.
func BenchmarkPlainSegments(b *testing.B) {
	const p = slash + lambdaInvokePath
	for name, plain := range map[string]func(string) bool{
		"plainSegments": plainSegments, "strings.Contains": referencePlainSegments,
	} {
		if !plain(p) {
			b.Fatalf("%s(%q) = false, want true", name, p)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				plain(p)
			}
		})
	}
}

func BenchmarkSigV4Sign(b *testing.B) {
	s := newTestSigV4(b, testService, "")
	r := newReq(b, http.MethodGet, "https://example.amazonaws.com/p?x=1", http.NoBody)
	if err := s.Sign(b.Context(), r); err != nil {
		b.Fatalf(wantSigned, err)
	}
	auth := r.Header.Get(authorization)
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") ||
		!strings.Contains(auth, "/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=") {
		b.Fatalf("Authorization = %q, want a SigV4 signature of host and x-amz-date", auth)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		own := r.Clone(r.Context())
		for pb.Next() {
			if err := s.Sign(own.Context(), own); err != nil {
				b.Errorf(wantSigned, err)
				return
			}
		}
	})
}

func BenchmarkSigV4SignBody(b *testing.B) {
	s := newTestSigV4(b, serviceS3, awsExampleSTS)
	body := strings.Repeat(testLetter, 4<<10)
	r := newReq(b, http.MethodPut, "https://bucket.s3.amazonaws.com/k?b=2&a=1", strings.NewReader(body))
	if err := s.Sign(b.Context(), r); err != nil {
		b.Fatalf(wantSigned, err)
	}
	if got, want := r.Header.Get(headerContentSHA), sha256Hex([]byte(body)); got != want {
		b.Fatalf("X-Amz-Content-Sha256 = %q, want %q", got, want)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		own := r.Clone(r.Context())
		for pb.Next() {
			if err := s.Sign(own.Context(), own); err != nil {
				b.Errorf(wantSigned, err)
				return
			}
		}
	})
}

// ExampleNewSigV4 signs every request of an http.Client for API Gateway.
func ExampleNewSigV4() {
	api := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		fmt.Println(strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"))
	}))
	accessKeyID, secretKey := "AKIDEXAMPLE", secret.New("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	signer, err := NewSigV4(&SigV4Config{
		AccessKey: accessKeyID,
		SecretKey: secretKey,
		Region:    "us-east-1",
		Service:   "execute-api",
	})
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: NewTransport(nil, signer)}
	defer api.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, api.URL, http.NoBody)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := resp.Body.Close(); err != nil {
		fmt.Println(err)
	}
	// Output: true
}
