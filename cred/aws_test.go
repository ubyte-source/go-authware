package cred

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// AWS-published test credentials used by the official sigv4 test suite.
//
//nolint:gosec // G101: AWS-published fixture credentials, not real secrets.
const (
	testAccessKey = "AKIDEXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	testRegion    = "us-east-1"
	testService   = "service"
)

func fixedTime(t *testing.T) func() time.Time {
	t.Helper()
	tt, err := time.Parse(awsTimeFormat, "20150830T123600Z")
	if err != nil {
		t.Fatalf("parse fixture time: %v", err)
	}
	return func() time.Time { return tt }
}

func newSigV4(t *testing.T) *SigV4 {
	t.Helper()
	return &SigV4{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Region:    testRegion,
		Service:   testService,
		Now:       fixedTime(t),
	}
}

// TestSigV4_GetVanilla matches the AWS sigv4 test-suite "get-vanilla"
// fixture: GET / on example.amazonaws.com with the X-Amz-Date supplied.
func TestSigV4_GetVanilla(t *testing.T) {
	s := newSigV4(t)
	req := newHTTPReq(t, http.MethodGet, "https://example.amazonaws.com/", http.NoBody)
	if err := s.Sign(context.Background(), req); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	const wantAuthSig = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "Signature="+wantAuthSig) {
		t.Fatalf("Authorization mismatch:\n got: %s\nwant signature: %s", auth, wantAuthSig)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Fatalf("X-Amz-Date = %q", got)
	}
	if !strings.Contains(auth, "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request") {
		t.Fatalf("Credential field missing/mismatch: %s", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-date") {
		t.Fatalf("SignedHeaders mismatch: %s", auth)
	}
}

// TestSigV4_GetVanillaQuery uses the "get-vanilla-query" fixture (a single
// query parameter) to verify canonical-query-string encoding and ordering.
func TestSigV4_GetVanillaQuery(t *testing.T) {
	s := newSigV4(t)
	req := newHTTPReq(t, http.MethodGet,
		"https://example.amazonaws.com/?Param1=value1", http.NoBody)
	if err := s.Sign(context.Background(), req); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	const wantSig = "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"
	if got := req.Header.Get("Authorization"); !strings.Contains(got, "Signature="+wantSig) {
		t.Fatalf("Authorization mismatch:\n got: %s\nwant signature: %s", got, wantSig)
	}
}

// TestSigV4_PostBody verifies that a non-empty body is hashed and that the
// body is restored before delegating downstream.
func TestSigV4_PostBody(t *testing.T) {
	body := strings.NewReader("Param1=value1")
	req := newHTTPReq(t, http.MethodPost,
		"https://example.amazonaws.com/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s := newSigV4(t)
	if signErr := s.Sign(context.Background(), req); signErr != nil {
		t.Fatalf("Sign: %v", signErr)
	}

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("Param1=value1")) {
		t.Fatalf("body not restored: %q", got)
	}
	if req.ContentLength != int64(len("Param1=value1")) {
		t.Fatalf("ContentLength = %d", req.ContentLength)
	}
	// Two requests differing only by body must produce different signatures.
	other := newHTTPReq(t, http.MethodPost,
		"https://example.amazonaws.com/", strings.NewReader("Param1=value2"))
	other.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if signErr := s.Sign(context.Background(), other); signErr != nil {
		t.Fatal(signErr)
	}
	if req.Header.Get("Authorization") == other.Header.Get("Authorization") {
		t.Fatal("body change did not change signature")
	}
}

// TestSigV4_S3StylePreSetContentHash verifies that when the caller
// pre-populates X-Amz-Content-Sha256 (as required for S3), the header is
// covered by the signature.
func TestSigV4_S3StylePreSetContentHash(t *testing.T) {
	s := newSigV4(t)
	body := []byte("payload")
	req := newHTTPReq(t, http.MethodPut,
		"https://example.s3.amazonaws.com/key", bytes.NewReader(body))
	req.Header.Set("X-Amz-Content-Sha256", hexSHA256(body))
	if err := s.Sign(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-content-sha256") {
		t.Fatalf("x-amz-content-sha256 not signed: %s", auth)
	}
}

func TestSigV4_UnsignedPayload(t *testing.T) {
	s := newSigV4(t)
	s.UnsignedPayload = true
	req := newHTTPReq(t, http.MethodPut,
		"https://example.amazonaws.com/object",
		strings.NewReader("very-large-stream"))
	// Caller sets the magic placeholder for S3 streaming uploads.
	req.Header.Set("X-Amz-Content-Sha256", awsUnsignedBody)
	if err := s.Sign(context.Background(), req); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != awsUnsignedBody {
		t.Fatalf("X-Amz-Content-Sha256 = %q", got)
	}
}

func TestSigV4_SessionToken(t *testing.T) {
	s := newSigV4(t)
	s.SessionToken = "FQoGZXIvYX..."
	req := newHTTPReq(t, http.MethodGet, "https://example.amazonaws.com/", http.NoBody)
	if err := s.Sign(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != s.SessionToken {
		t.Fatalf("X-Amz-Security-Token = %q", got)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-security-token") {
		t.Fatalf("session token not in SignedHeaders: %s", auth)
	}
}

func TestSigV4_PathSpecialChars(t *testing.T) {
	s := newSigV4(t)
	// Spaces and reserved chars exercise the canonical URI encoder.
	req := newHTTPReq(t, http.MethodGet,
		"https://example.amazonaws.com/path%20with%20spaces/and+plus", http.NoBody)
	if err := s.Sign(context.Background(), req); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Different paths must yield different signatures.
	other := newHTTPReq(t, http.MethodGet, "https://example.amazonaws.com/different", http.NoBody)
	if err := s.Sign(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") == other.Header.Get("Authorization") {
		t.Fatal("two different paths produced identical signatures")
	}
}

func TestSigV4_QueryReordered(t *testing.T) {
	s := newSigV4(t)
	a := newHTTPReq(t, http.MethodGet, "https://example.amazonaws.com/?b=2&a=1", http.NoBody)
	b := newHTTPReq(t, http.MethodGet, "https://example.amazonaws.com/?a=1&b=2", http.NoBody)
	if err := s.Sign(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err := s.Sign(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if a.Header.Get("Authorization") != b.Header.Get("Authorization") {
		t.Fatalf("query reorder changed signature:\n a: %s\n b: %s",
			a.Header.Get("Authorization"), b.Header.Get("Authorization"))
	}
}

func TestSigV4_RejectsNoHost(t *testing.T) {
	s := newSigV4(t)
	req := &http.Request{Method: http.MethodGet, Header: http.Header{}}
	if err := s.Sign(context.Background(), req); !errors.Is(err, ErrSigV4MissingHost) {
		t.Fatalf("err = %v, want ErrSigV4MissingHost", err)
	}
}

func TestSigV4_AsRoundTripper(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := newSigV4(t)
	client := &http.Client{Transport: RoundTripper(srv.Client().Transport, s)}
	req := newHTTPReq(t, http.MethodGet, srv.URL, http.NoBody).WithContext(context.Background())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestAWSURIEncode(t *testing.T) {
	cases := []struct {
		in          string
		want        string
		encodeSlash bool
	}{
		{"abc-_.~", "abc-_.~", false},
		{"a b", "a%20b", false},
		{"a/b", "a/b", false},
		{"a/b", "a%2Fb", true},
		{"=", "%3D", false},
		{"é", "%C3%A9", false},
	}
	for _, tc := range cases {
		if got := awsURIEncode(tc.in, tc.encodeSlash); got != tc.want {
			t.Errorf("awsURIEncode(%q, %v) = %q, want %q", tc.in, tc.encodeSlash, got, tc.want)
		}
	}
}

func TestHexSHA256_EmptyShortcut(t *testing.T) {
	if hexSHA256(nil) != awsHashEmpty {
		t.Fatal("empty hash mismatch")
	}
	if hexSHA256([]byte("")) != awsHashEmpty {
		t.Fatal("zero-len hash mismatch")
	}
}

func TestDeriveSigningKey_Stable(t *testing.T) {
	a := deriveSigningKey(testSecretKey, "20150830", testRegion, testService)
	b := deriveSigningKey(testSecretKey, "20150830", testRegion, testService)
	if !bytes.Equal(a, b) {
		t.Fatal("signing key not deterministic")
	}
	c := deriveSigningKey(testSecretKey, "20150831", testRegion, testService)
	if bytes.Equal(a, c) {
		t.Fatal("date change should change signing key")
	}
}

// BenchmarkSigV4_Sign measures signing throughput on a small GET request.
func BenchmarkSigV4_Sign(b *testing.B) {
	tt, err := time.Parse(awsTimeFormat, "20150830T123600Z")
	if err != nil {
		b.Fatalf("parse fixture time: %v", err)
	}
	s := &SigV4{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Region:    testRegion,
		Service:   testService,
		Now:       func() time.Time { return tt },
	}
	b.ReportAllocs()

	for b.Loop() {
		req := newHTTPReq(b, http.MethodGet, "https://example.amazonaws.com/path?x=1", http.NoBody)
		if err := s.Sign(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}
