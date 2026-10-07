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
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ubyte-source/go-authware/v2/internal/keyedmac"
	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/problems"
	"github.com/ubyte-source/go-authware/v2/internal/syntax"
	"github.com/ubyte-source/go-authware/v2/secret"
)

const (
	awsAlgorithm    = "AWS4-HMAC-SHA256"
	awsRequestTerm  = "aws4_request"
	awsTimeFormat   = "20060102T150405Z"
	awsDateFormat   = "20060102"
	awsUnsignedBody = "UNSIGNED-PAYLOAD"
	awsEmptyBody    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	awsServiceS3    = "s3"

	// maxSignedBody bounds the body a signature hashes.
	maxSignedBody = 1 << 20

	// slash separates the parts of a credential scope and the segments of a
	// path.
	slash = "/"
)

// SigV4Config configures NewSigV4.
type SigV4Config struct {
	// AccessKey is the access key ID; required.
	AccessKey string
	// SecretKey is the secret access key; required.
	SecretKey secret.Value
	// SessionToken is the optional temporary session token.
	SessionToken secret.Value
	// Region is the signing region, such as us-east-1; required.
	Region string
	// Service is the signing name, such as s3 or execute-api; required.
	Service string
	// UnsignedPayload signs UNSIGNED-PAYLOAD instead of the body hash; a body
	// over 1 MiB needs it, and NewSigV4 refuses it unless Service is one of S3's.
	UnsignedPayload bool
}

// Validate reports every problem NewSigV4 refuses c for, joined, each
// wrapping ErrInvalidConfig.
func (c *SigV4Config) Validate() error {
	if c == nil {
		return errNilConfig
	}
	return c.check()
}

// check reports the problems Validate reports for c, which is not nil.
func (c *SigV4Config) check() error {
	p := problems.New(ErrInvalidConfig)
	if !syntax.IsToken(c.AccessKey) {
		p.Addf("SigV4 access key is empty or not a token")
	}
	if c.SecretKey.IsZero() {
		p.Addf("missing SigV4 secret key")
	}
	if !c.SessionToken.IsZero() && !syntax.IsFieldValue(c.SessionToken.Reveal()) {
		p.Addf("SigV4 session token is not a valid header value")
	}
	if !syntax.IsToken(c.Region) {
		p.Addf("SigV4 region %q is empty or not a token", c.Region)
	}
	if !syntax.IsToken(c.Service) {
		p.Addf("SigV4 service %q is empty or not a token", c.Service)
	}
	if c.UnsignedPayload && !s3Service(c.Service) {
		p.Addf("SigV4 unsigned payload needs an S3 service, not %q", c.Service)
	}
	return p.Err()
}

// s3Service reports whether service is a signing name of S3, whose paths are
// encoded once and not normalized and which takes UNSIGNED-PAYLOAD.
func s3Service(service string) bool {
	switch service {
	case awsServiceS3, "s3-object-lambda", "s3-outposts", "s3express":
		return true
	}
	return false
}

// datedKey is the HMAC-SHA256 of a signing key, the UTC date the key is valid
// for, its credential scope and the Authorization header up to the signed list.
type datedKey struct {
	date       string
	scope      string
	authPrefix string
	mac        *keyedmac.MAC
}

// sigV4 signs requests with AWS Signature Version 4.
type sigV4 struct {
	cfg     SigV4Config
	key     atomic.Pointer[datedKey]
	bodies  netguard.Digester
	s3Paths bool
}

// NewSigV4 returns a SigV4 signer, or an error wrapping ErrInvalidConfig. Paths
// follow the S3 rules, encoded once, when Service is s3, s3-object-lambda,
// s3-outposts or s3express, and are normalized and encoded twice otherwise.
func NewSigV4(cfg *SigV4Config) (Signer, error) {
	if cfg == nil {
		return nil, errNilConfig
	}
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &sigV4{cfg: *cfg, s3Paths: s3Service(cfg.Service)}, nil
}

// Sign signs r at the current time. It sets r.Host without a default port and
// the X-Amz-* headers, hashes a body of at most 1 MiB, from GetBody or buffered
// for replay, and puts the query in canonical form, so the wire matches.
func (s *sigV4) Sign(_ context.Context, r *http.Request) error {
	return s.signAt(r, time.Now())
}

func (s *sigV4) signAt(r *http.Request, now time.Time) error {
	host := signingHost(r)
	if host == "" {
		return ErrMissingHost
	}
	r.Host = host
	now = now.UTC()
	amzDate := now.Format(awsTimeFormat)
	if r.Header == nil {
		r.Header = http.Header{}
	}
	r.Header.Set("X-Amz-Date", amzDate)
	if !s.cfg.SessionToken.IsZero() {
		r.Header.Set("X-Amz-Security-Token", s.cfg.SessionToken.Reveal())
	}
	payload, err := s.payloadHash(r)
	if err != nil {
		return err
	}
	if s.s3Paths {
		r.Header.Set("X-Amz-Content-Sha256", payload)
	}
	r.URL.RawQuery = canonicalQuery(r.URL.RawQuery)
	canonical, signed := s.canonicalRequest(r, payload)
	key := s.signingKey(amzDate[:len(awsDateFormat)])
	toSign := stringToSign(amzDate, key.scope, canonical)
	r.Header.Set(headerAuthorization, key.authorization(signed, key.mac.Sum(toSign[len(toSign):], toSign)))
	return nil
}

// signingKey returns the key of date, which concurrent signers share once it
// is published; a signer that finds no key of date published derives it.
func (s *sigV4) signingKey(date string) *datedKey {
	return s.keyAfter(s.key.Load(), date)
}

// keyAfter returns loaded, the key signingKey found, when it is the key of
// date, and otherwise derives the key of date and publishes it unless another
// signer has replaced loaded.
func (s *sigV4) keyAfter(loaded *datedKey, date string) *datedKey {
	if loaded != nil && loaded.date == date {
		return loaded
	}
	key := deriveSigningKey(s.cfg.SecretKey.Reveal(), date, s.cfg.Region, s.cfg.Service)
	scope := date + slash + s.cfg.Region + slash + s.cfg.Service + slash + awsRequestTerm
	k := &datedKey{
		date:       date,
		scope:      scope,
		authPrefix: awsAlgorithm + " Credential=" + s.cfg.AccessKey + slash + scope + ", SignedHeaders=",
		mac:        keyedmac.New(sha256.New, key[:]),
	}
	s.key.CompareAndSwap(loaded, k)
	return k
}

// errBodyToSignTooLarge refuses a body over maxSignedBody, built once.
var errBodyToSignTooLarge = bodyToSign(ErrBodyTooLarge)

// bodyToSign wraps err, why the body of a request to sign was not hashed.
func bodyToSign(err error) error { return fmt.Errorf(errPrefix+"read body to sign: %w", err) }

// payloadHash returns UNSIGNED-PAYLOAD when the config says so, and otherwise
// the hex SHA-256 of the body of r, that of no bytes without one.
func (s *sigV4) payloadHash(r *http.Request) (string, error) {
	switch {
	case s.cfg.UnsignedPayload:
		return awsUnsignedBody, nil
	case r.Body == nil || r.Body == http.NoBody:
		return awsEmptyBody, nil
	}
	sum, err := s.bodies.Digest(r, maxSignedBody, errBodyToSignTooLarge)
	switch {
	case errors.Is(err, errBodyToSignTooLarge):
		return "", err
	case err != nil:
		return "", bodyToSign(err)
	}
	return hexString(sum[:]), nil
}

// canonicalRequest returns the canonical request and the signed header
// list.
func (s *sigV4) canonicalRequest(r *http.Request, payload string) (canonical []byte, signed string) {
	uri := r.URL.Path
	switch {
	case !s.s3Paths:
		uri = normalizedPath(wirePath(r.URL))
	case r.URL.Opaque != "":
		uri = unescapedPath(wirePath(r.URL))
	}
	headers, signed := canonicalHeaders(r)
	canonical = joinLines(
		cmp.Or(r.Method, http.MethodGet), cmp.Or(awsEncodePath(uri), slash), r.URL.RawQuery, headers, signed, payload,
	)
	return canonical, signed
}

// wirePath returns the escaped path of u: when Opaque is set, the one net/http
// sends, from the slash after the authority of an Opaque that starts with //, or
// all of Opaque; otherwise EscapedPath.
func wirePath(u *url.URL) string {
	if u.Opaque == "" {
		return u.EscapedPath()
	}
	rest, ok := strings.CutPrefix(u.Opaque, "//")
	if !ok {
		return u.Opaque
	}
	if i := strings.Index(rest, slash); i >= 0 {
		return rest[i:]
	}
	return ""
}

// normalizedPath returns p as path.Clean resolves it from the root, ending in a
// slash when p does and the result is not the root; an empty p stays empty.
func normalizedPath(p string) string {
	rooted := strings.HasPrefix(p, slash)
	if p == "" || rooted && plainSegments(p) {
		return p
	}
	if !rooted {
		p = slash + p
	}
	clean := path.Clean(p)
	if clean != slash && strings.HasSuffix(p, slash) {
		return clean + slash
	}
	return clean
}

// plainSegments reports whether no slash of p is followed by a slash or a dot.
func plainSegments(p string) bool {
	for {
		i := strings.IndexByte(p, slash[0])
		if i < 0 || i+1 == len(p) {
			return true
		}
		if c := p[i+1]; c == slash[0] || c == '.' {
			return false
		}
		p = p[i+2:]
	}
}

// unescapedPath returns p, an escaped path, decoded, or p when
// url.PathUnescape refuses it.
func unescapedPath(p string) string {
	if decoded, err := url.PathUnescape(p); err == nil {
		return decoded
	}
	return p
}

// authorization returns the Authorization header of a request whose signed
// header list is signed and whose signature, a SHA-256 MAC, is signature.
func (k *datedKey) authorization(signed string, signature []byte) string {
	const term = ", Signature="
	var buf [2 * sha256.Size]byte
	digits := hex.AppendEncode(buf[:0], signature)
	var b strings.Builder
	b.Grow(len(k.authPrefix) + len(signed) + len(term) + len(digits))
	b.WriteString(k.authPrefix)
	b.WriteString(signed)
	b.WriteString(term)
	b.Write(digits)
	return b.String()
}

// joinLines joins lines with newlines into one allocation.
func joinLines(lines ...string) []byte {
	size := len(lines) - 1
	for _, line := range lines {
		size += len(line)
	}
	b := make([]byte, 0, size)
	for i, line := range lines {
		if i > 0 {
			b = append(b, '\n')
		}
		b = append(b, line...)
	}
	return b
}

// stringToSign returns the string that the signing key signs for a canonical
// request of amzDate in scope, with room after it for its MAC.
func stringToSign(amzDate, scope string, canonical []byte) []byte {
	sum := sha256.Sum256(canonical)
	b := make([]byte, 0, len(awsAlgorithm)+len(amzDate)+len(scope)+3+hex.EncodedLen(len(sum))+sha256.Size)
	b = append(b, awsAlgorithm+"\n"...)
	b = append(b, amzDate...)
	b = append(b, '\n')
	b = append(b, scope...)
	b = append(b, '\n')
	return hex.AppendEncode(b, sum[:])
}

// signingHost returns the request host without the default port of an http or
// https request, a port clients leave out of the Host header.
func signingHost(r *http.Request) string {
	host, scheme := cmp.Or(r.Host, r.URL.Host), r.URL.Scheme
	if (scheme != netguard.SchemeHTTPS && scheme != netguard.SchemeHTTP) ||
		host[strings.LastIndexByte(host, ':')+1:] != netguard.DefaultPort(scheme) {
		return host
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

type queryPair struct{ encName, encValue []byte }

// Scratch bounds of a signature: the most bytes the AWS encoding writes for one
// byte, and how many query pairs and header fields are sorted without a heap
// slice.
const (
	encodedWidth = len("%XX")
	queryStack   = 8
	headerStack  = 16
)

// canonicalQuery encodes every name and value, decoded as a form would, into
// one buffer and sorts them by name, then by value. The buffer holds each pair
// as name=value&, so the query takes its length but the last '&'.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	var stack [queryStack]queryPair
	pairs := slices.Grow(stack[:0], strings.Count(raw, "&")+1)
	arena := make([]byte, 0, encodedWidth*len(raw)+len("=&"))
	for part := range strings.SplitSeq(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		start := len(arena)
		arena = appendQueryComponent(arena, k)
		name := arena[start:]
		arena = append(arena, '=')
		value := len(arena)
		arena = appendQueryComponent(arena, v)
		pairs = append(pairs, queryPair{name, arena[value:]})
		arena = append(arena, '&')
	}
	slices.SortFunc(pairs, func(a, b queryPair) int {
		return cmp.Or(bytes.Compare(a.encName, b.encName), bytes.Compare(a.encValue, b.encValue))
	})
	var b strings.Builder
	b.Grow(len(arena))
	for _, p := range pairs {
		b.Write(p.encName)
		b.WriteByte('=')
		b.Write(p.encValue)
		b.WriteByte('&')
	}
	return strings.TrimSuffix(b.String(), "&")
}

// appendQueryComponent appends s to dst decoded as a form value and
// AWS-encoded; a malformed escape, which url.QueryUnescape refuses, keeps s
// literal.
func appendQueryComponent(dst []byte, s string) []byte {
	start := len(dst)
	for rest := s; rest != ""; {
		c, width, ok := formByte(rest)
		if !ok {
			return appendAWSEncoded(dst[:start], s)
		}
		dst = appendAWSByte(dst, c)
		rest = rest[width:]
	}
	return dst
}

// formByte returns the byte that s, not empty, starts with as a form decodes
// it, and how many bytes of s encode it: '+' is a space and %HH the byte of its
// hex digits; ok is false for a '%' that starts no such escape.
func formByte(s string) (c byte, width int, ok bool) {
	switch s[0] {
	case '+':
		return ' ', 1, true
	case '%':
		var b [1]byte
		if len(s) < encodedWidth {
			return 0, 0, false
		}
		if _, err := hex.Decode(b[:], []byte(s[1:encodedWidth])); err != nil {
			return 0, 0, false
		}
		return b[0], encodedWidth, true
	}
	return s[0], 1, true
}

// headerField is a signable header, by lower-cased and by sent name.
type headerField struct {
	lower  string
	name   string
	values []string
}

// The request headers that canonicalHeaders names.
const (
	headerHost       = "host"
	headerConnection = "connection"
)

// canonicalHeaders lists host and every header a proxy or the transport
// cannot rewrite, lower-cased and sorted, with values trimmed, inner space
// runs collapsed and the values of one lower-cased name joined by commas.
func canonicalHeaders(r *http.Request) (canonical, signed string) {
	var stack [headerStack]headerField
	fields := slices.Grow(stack[:0], len(r.Header)+1)
	fields = append(signedFields(r.Header, fields), headerField{lower: headerHost, values: []string{r.Host}})
	slices.SortFunc(fields, func(a, b headerField) int {
		return cmp.Or(strings.Compare(a.lower, b.lower), strings.Compare(a.name, b.name))
	})
	return writeCanonical(fields)
}

// signedFields appends to fields every header of h signed under its name, the
// names lower-cased into one buffer, but those a Connection header names.
func signedFields(h http.Header, fields []headerField) []headerField {
	var names strings.Builder
	names.Grow(nameBytes(h))
	var stack [1][]string
	connection := stack[:0]
	for name, vals := range h {
		lower := writeLowerName(&names, name)
		// The length test keeps out a non-ASCII name that strings.ToLower maps to connection.
		if len(name) == len(headerConnection) && lower == headerConnection {
			connection = append(connection, vals)
		}
		if len(vals) > 0 && signableHeader(lower) {
			fields = append(fields, headerField{lower: lower, name: name, values: vals})
		}
	}
	return withoutOptions(fields, connection)
}

func nameBytes(h http.Header) int {
	n := 0
	for name := range h {
		n += len(name)
	}
	return n
}

// writeLowerName returns name as strings.ToLower maps it, written into names
// when it is ASCII.
func writeLowerName(names *strings.Builder, name string) string {
	start := names.Len()
	for i := range len(name) {
		c := name[i]
		if c >= utf8.RuneSelf {
			return strings.ToLower(name)
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		names.WriteByte(c)
	}
	return names.String()[start:]
}

// withoutOptions drops from fields the headers that the values of the
// Connection headers name, which a proxy removes before it forwards the request.
func withoutOptions(fields []headerField, connection [][]string) []headerField {
	for _, vals := range connection {
		for _, v := range vals {
			for option := range strings.SplitSeq(v, ",") {
				if option = textproto.TrimString(option); option != "" {
					fields = slices.DeleteFunc(fields, func(f headerField) bool {
						return strings.EqualFold(f.lower, option)
					})
				}
			}
		}
	}
	return fields
}

// writeCanonical returns the canonical headers and the signed list of fields,
// which are sorted by lower-cased name.
func writeCanonical(fields []headerField) (canonical, signed string) {
	// Each field adds its name and a separator to both lists, and its values,
	// each with a separator, to the canonical one.
	names, values := 0, 0
	for _, f := range fields {
		names += len(f.lower) + 1
		for _, v := range f.values {
			values += len(v) + 1
		}
	}
	var c, n strings.Builder
	c.Grow(names + values)
	n.Grow(names)
	for i, f := range fields {
		if i > 0 && f.lower == fields[i-1].lower {
			c.WriteByte(',')
			writeHeaderValues(&c, f.values)
			continue
		}
		if i > 0 {
			c.WriteByte('\n')
		}
		c.WriteString(f.lower)
		c.WriteByte(':')
		n.WriteString(f.lower)
		n.WriteByte(';')
		writeHeaderValues(&c, f.values)
	}
	c.WriteByte('\n')
	return c.String(), strings.TrimSuffix(n.String(), ";")
}

// writeHeaderValues writes values to b trimmed and joined by commas.
func writeHeaderValues(b *strings.Builder, values []string) {
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		writeTrimmed(b, v)
	}
}

// writeTrimmed writes v to b trimmed, with each inner run of spaces as one.
func writeTrimmed(b *strings.Builder, v string) {
	v = strings.TrimSpace(v)
	for {
		before, after, found := strings.Cut(v, "  ")
		b.WriteString(before)
		if !found {
			return
		}
		b.WriteByte(' ')
		v = strings.TrimLeft(after, " ")
	}
}

// signableHeader reports whether the header lower of a request map is signed
// under its name: host comes from the request, and a proxy or the transport
// may drop or rewrite the others it refuses.
func signableHeader(lower string) bool {
	switch lower {
	case headerHost, "authorization", "content-length", "cookie", "expect", "user-agent", "x-amzn-trace-id",
		headerConnection, "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
		"trailer", "transfer-encoding", "upgrade":
		return false
	}
	return true
}

// awsEncodePath percent-encodes each segment of p and keeps the slashes.
func awsEncodePath(p string) string {
	var b strings.Builder
	b.Grow(len(p))
	var escape [encodedWidth]byte
	for i := range len(p) {
		if c := p[i]; c == slash[0] {
			b.WriteByte(c)
		} else {
			b.Write(appendAWSByte(escape[:0], c))
		}
	}
	return b.String()
}

func appendAWSEncoded(dst []byte, s string) []byte {
	for i := range len(s) {
		dst = appendAWSByte(dst, s[i])
	}
	return dst
}

// appendAWSByte appends c to dst, percent-encoded in upper-case hex unless it
// is one of A-Z a-z 0-9 - _ . ~.
func appendAWSByte(dst []byte, c byte) []byte {
	const hexDigits = "0123456789ABCDEF"
	if syntax.IsUnreserved(c) {
		return append(dst, c)
	}
	return append(dst, '%', hexDigits[c>>4], hexDigits[c&0x0F])
}

func hmacSHA256(key, data []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	return sum
}

// hexString returns sum, a SHA-256 digest or MAC, in lower-case hex.
func hexString(sum []byte) string {
	var buf [2 * sha256.Size]byte
	return string(hex.AppendEncode(buf[:0], sum))
}

func deriveSigningKey(secretKey, date, region, service string) [sha256.Size]byte {
	k := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	k = hmacSHA256(k[:], []byte(region))
	k = hmacSHA256(k[:], []byte(service))
	return hmacSHA256(k[:], []byte(awsRequestTerm))
}
