package cred

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	awsAlgorithm    = "AWS4-HMAC-SHA256"
	awsRequestTerm  = "aws4_request"
	awsTimeFormat   = "20060102T150405Z"
	awsDateFormat   = "20060102"
	awsHashEmpty    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	awsUnsignedBody = "UNSIGNED-PAYLOAD"
)

// ErrSigV4MissingHost is returned when the request has no Host: the
// canonical request always includes a host header so signing without
// one is refused.
var ErrSigV4MissingHost = errors.New("cred/aws: request has no Host")

// SigV4 is an outbound Signer implementing AWS Signature Version 4. It
// adds X-Amz-Date and Authorization (and X-Amz-Security-Token when
// SessionToken is set) and consumes the body to compute its SHA-256
// hash, restoring a fresh body before delegating.
type SigV4 struct {
	// Now overrides the signing clock; nil uses time.Now. UTC is
	// enforced regardless of the source location.
	Now func() time.Time
	// AccessKey is the AWS access key id (AKID...).
	AccessKey string
	// SecretKey is the AWS secret access key.
	SecretKey string
	// SessionToken is the optional STS session token.
	SessionToken string
	// Region is the target region (e.g. "us-east-1").
	Region string
	// Service is the target service identifier (e.g. "s3").
	Service string
	// UnsignedPayload skips body hashing and uses the literal
	// "UNSIGNED-PAYLOAD" placeholder.
	UnsignedPayload bool
}

var _ Signer = (*SigV4)(nil)

// Sign attaches an AWS SigV4 Authorization header to r.
func (s *SigV4) Sign(_ context.Context, r *http.Request) error {
	host := requestHost(r)
	if host == "" {
		return ErrSigV4MissingHost
	}
	r.Host = host

	now := s.now()
	amzDate := now.Format(awsTimeFormat)
	dateStamp := now.Format(awsDateFormat)

	r.Header.Set("X-Amz-Date", amzDate)
	if s.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", s.SessionToken)
	}

	payloadHash, err := s.payloadHash(r)
	if err != nil {
		return err
	}
	canonical, signedHeaders := buildCanonicalRequest(r, payloadHash)
	credentialScope := dateStamp + "/" + s.Region + "/" + s.Service + "/" + awsRequestTerm

	stringToSign := awsAlgorithm + "\n" +
		amzDate + "\n" +
		credentialScope + "\n" +
		hexSHA256([]byte(canonical))

	signingKey := deriveSigningKey(s.SecretKey, dateStamp, s.Region, s.Service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	r.Header.Set("Authorization",
		awsAlgorithm+" Credential="+s.AccessKey+"/"+credentialScope+
			", SignedHeaders="+signedHeaders+
			", Signature="+signature)
	return nil
}

func (s *SigV4) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *SigV4) payloadHash(r *http.Request) (string, error) {
	if s.UnsignedPayload {
		return awsUnsignedBody, nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return awsHashEmpty, nil
	}
	buf, err := io.ReadAll(r.Body)
	if closeErr := r.Body.Close(); closeErr != nil {
		return "", closeErr
	}
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	return hexSHA256(buf), nil
}

// requestHost returns r.Host, falling back to URL.Host then the Host
// header. A non-empty result is required because "host" is always a
// signed header.
func requestHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Header.Get("Host")
}

// buildCanonicalRequest constructs the SigV4 canonical request and the
// semicolon-separated list of signed header names.
func buildCanonicalRequest(r *http.Request, payloadHash string) (canonical, signedHeaders string) {
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = http.MethodGet
	}
	canonURI := canonicalURI(r.URL)
	canonQS := canonicalQueryString(r.URL)
	canonHeaders, signed := canonicalHeaders(r)

	var b strings.Builder
	b.Grow(256)
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(canonURI)
	b.WriteByte('\n')
	b.WriteString(canonQS)
	b.WriteByte('\n')
	b.WriteString(canonHeaders)
	b.WriteByte('\n')
	b.WriteString(signed)
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String(), signed
}

// canonicalURI percent-encodes each path segment; an empty path becomes "/".
func canonicalURI(u *url.URL) string {
	if u == nil || u.Path == "" {
		return "/"
	}
	segments := strings.Split(u.EscapedPath(), "/")
	for i, seg := range segments {
		segments[i] = awsURIEncode(uriDecode(seg), false)
	}
	return strings.Join(segments, "/")
}

// canonicalQueryString sorts and re-encodes the query string per SigV4.
func canonicalQueryString(u *url.URL) string {
	if u == nil || u.RawQuery == "" {
		return ""
	}
	pairs := make([]string, 0, 8)
	for raw := range strings.SplitSeq(u.RawQuery, "&") {
		if raw == "" {
			continue
		}
		k, v, _ := strings.Cut(raw, "=")
		pairs = append(pairs, awsURIEncode(uriDecode(k), true)+"="+awsURIEncode(uriDecode(v), true))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// canonicalHeaders returns the canonical headers block and the
// semicolon-separated list of signed header names. The host header is
// always included; r.Header is not mutated.
func canonicalHeaders(r *http.Request) (canonical, signedHeaders string) {
	names := make([]string, 0, len(r.Header)+1)
	values := make(map[string]string, len(r.Header)+1)
	values["host"] = strings.TrimSpace(r.Host)
	names = append(names, "host")
	for k, vv := range r.Header {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "authorization" {
			continue
		}
		values[lk] = strings.TrimSpace(strings.Join(vv, ","))
		names = append(names, lk)
	}
	sort.Strings(names)

	var canon strings.Builder
	canon.Grow(64)
	for _, n := range names {
		canon.WriteString(n)
		canon.WriteByte(':')
		canon.WriteString(values[n])
		canon.WriteByte('\n')
	}
	return canon.String(), strings.Join(names, ";")
}

// awsURIEncode percent-encodes outside the SigV4 unreserved set
// (A-Z a-z 0-9 - _ . ~). Slashes are preserved when encodeSlash is false.
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if isAWSUnreserved(c) || (c == '/' && !encodeSlash) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUpper(c >> 4))
		b.WriteByte(hexUpper(c & 0x0F))
	}
	return b.String()
}

func isAWSUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-', c == '_', c == '.', c == '~':
		return true
	default:
		return false
	}
}

// uriDecode percent-decodes s, leaving malformed sequences unchanged.
func uriDecode(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	dec, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return dec
}

func hexUpper(nibble byte) byte {
	if nibble < 10 {
		return '0' + nibble
	}
	return 'A' + (nibble - 10)
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func hexSHA256(data []byte) string {
	if len(data) == 0 {
		return awsHashEmpty
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// deriveSigningKey computes the per-request signing key.
func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte(awsRequestTerm))
}
