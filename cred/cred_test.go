package cred

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

func TestTokenApply(t *testing.T) {
	tests := []struct {
		tok        *Token
		header     string
		wantHeader string
	}{
		{&Token{Value: secret.New(testPayload)}, authorization, "Bearer abc"},
		{&Token{Value: secret.New(testPayload), Type: dpop, Header: "X-Auth"}, "X-Auth", dpopABC},
	}
	for _, tt := range tests {
		r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
		tt.tok.Apply(r)
		bare := &http.Request{Method: http.MethodGet, URL: r.URL}
		tt.tok.Apply(bare)
		if got, gotBare := r.Header.Get(tt.header), bare.Header.Get(tt.header); got != tt.wantHeader ||
			gotBare != tt.wantHeader {
			t.Errorf("%s = %q, and %q without a header map; want %q", tt.header, got, gotBare, tt.wantHeader)
		}
	}
}

// TestTokenShared renders the header value and the canonical header name of a
// copy once.
func TestTokenShared(t *testing.T) {
	tok := &Token{Value: secret.New(testPayload), Type: dpop, Header: "x-api-key"}
	shared := tok.shared()
	if shared == tok || !tok.rendered.IsZero() || tok.canonicalHeader != "" || shared.rendered.Reveal() != dpopABC ||
		shared.canonicalHeader != "X-Api-Key" {
		t.Fatalf("shared = %p rendering %q in %q, want a copy of %p rendering DPoP abc in X-Api-Key", shared,
			shared.rendered.Reveal(), shared.canonicalHeader, tok)
	}
	if def := (&Token{Value: tok.Value}).shared(); def.canonicalHeader != authorization {
		t.Fatalf("shared without Header names %q, want Authorization", def.canonicalHeader)
	}
}

// TestTokenSharedCopy applies, from a copy of a shared token, edited or not,
// the header value and name of the copy.
func TestTokenSharedCopy(t *testing.T) {
	shared := (&Token{Value: secret.New(testPayload), Type: dpop, Header: "x-api-key"}).shared()
	for name, edit := range map[string]func(*Token){
		"none":      func(*Token) {},
		"value":     func(c *Token) { c.Value = secret.New("xyz") },
		"type":      func(c *Token) { c.Type = "Toke" },
		"separator": func(c *Token) { c.Type, c.Value = "DPo", secret.New(" abc") },
		"header":    func(c *Token) { c.Header = "x-other" },
	} {
		c := *shared
		edit(&c)
		r := &http.Request{}
		c.Apply(r)
		key, want := http.CanonicalHeaderKey(c.Header), c.Type+" "+c.Value.Reveal()
		if got := r.Header[key]; len(r.Header) != 1 || len(got) != 1 || got[0] != want {
			t.Errorf("Apply after a %s edit set %q, want %s: %q: a stale rendering is ignored", name, r.Header, key,
				want)
		}
	}
}

// TestTokenApplyAllocs renders the header value of a fixed token on each
// call and reuses the value and the canonical name of a shared token, whatever
// the case of its Header; the header slice is allocated.
func TestTokenApplyAllocs(t *testing.T) {
	plain := &Token{Value: secret.New(strings.Repeat("a", longToken))}
	lower := &Token{Value: plain.Value, Header: "x-api-key"}
	want := "Bearer " + plain.Value.Reveal()
	for _, tc := range []struct {
		tok    *Token
		header string
		allocs float64
	}{{plain, authorization, 2}, {plain.shared(), authorization, 1}, {lower.shared(), "X-Api-Key", 1}} {
		r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
		assertAllocs(t, tc.allocs, func() { tc.tok.Apply(r) })
		if got := r.Header[tc.header]; len(got) != 1 || got[0] != want {
			t.Fatalf("Apply set %s to %.20q, want Bearer and the token", tc.header, got)
		}
	}
}

func TestTokenApplyBare(t *testing.T) {
	for _, header := range []string{"", customHeader} {
		tok := &Token{Value: secret.New("k v"), Header: header, Bare: true}
		for _, apply := range []*Token{tok, tok.shared()} {
			r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
			apply.Apply(r)
			if got := r.Header.Get(cmp.Or(header, authorization)); got != "k v" {
				t.Errorf("Apply of a bare token in %q wrote %q, want the value alone", header, got)
			}
		}
	}
}

func TestTokenSign(t *testing.T) {
	var s Signer = &Token{Value: secret.New("k"), Type: "Token", Header: customHeader}
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	if err := s.Sign(t.Context(), r); err != nil || r.Header.Get(customHeader) != "Token k" {
		t.Fatalf("Sign() = %v, %s %q, want Token k", err, customHeader, r.Header.Get(customHeader))
	}
}

func TestTokenValidate(t *testing.T) {
	ok := []*Token{
		{Value: secret.New(testPayload)},
		{Value: secret.New("a b\tc"), Type: "Token", Header: customHeader},
		{Value: secret.New(testPayload), Header: customHeader, Bare: true},
	}
	for _, tok := range ok {
		if err := tok.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", tok, err)
		}
	}
	bad := []struct {
		tok  *Token
		want string
	}{
		{&Token{Value: secret.New(testPayload), Header: "X Key"}, `token header "X Key"`},
		{&Token{Value: secret.New(testPayload), Type: spacedScheme}, `token type "Be arer" is not a valid scheme`},
		{&Token{Value: secret.New(testPayload), Type: "Bearer", Bare: true},
			`token type "Bearer" is set on a bare token`},
		{&Token{}, "token value"},
		{&Token{Value: secret.New("abc\n")}, "token value"},
		{&Token{Value: secret.New("a\x00b")}, "token value"},
	}
	for _, tc := range bad {
		if err := tc.tok.Validate(); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalidConfig with %q", tc.tok, err, tc.want)
		}
	}
}

// TestTokenValidateNil reports a nil token as every sibling Validate reports a
// nil config.
func TestTokenValidateNil(t *testing.T) {
	var none *Token
	if err := none.Validate(); !errors.Is(err, ErrInvalidConfig) || err.Error() != "cred: invalid config: nil token" {
		t.Fatalf("(*Token)(nil).Validate() = %v, want ErrInvalidConfig: nil token", err)
	}
}

// TestTokenValidateJoined reports every problem of a token at once, without
// its value.
func TestTokenValidateJoined(t *testing.T) {
	err := (&Token{Value: secret.New("s3cr3t\n"), Header: "X Key", Type: spacedScheme}).Validate()
	if !errors.Is(err, ErrInvalidConfig) || strings.Count(err.Error(), newline) != 2 ||
		strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("err = %q, want three joined ErrInvalidConfig problems without the value", err)
	}
}

// TestTokenValidateBareType refuses a type on a bare token, and also as a
// scheme when it is not a token.
func TestTokenValidateBareType(t *testing.T) {
	err := (&Token{Value: secret.New(testPayload), Type: spacedScheme, Bare: true}).Validate()
	const want = `cred: invalid config: token type "Be arer" is set on a bare token` + newline +
		`cred: invalid config: token type "Be arer" is not a valid scheme`
	if !errors.Is(err, ErrInvalidConfig) || err.Error() != want {
		t.Fatalf("err = %q, want %q", err, want)
	}
}

// TestTokenSharedHidesTheCredential prints a shared token, whose header value is
// rendered, without its credential.
func TestTokenSharedHidesTheCredential(t *testing.T) {
	tok := (&Token{Value: secret.New("s3cr3t-token"), Type: dpop}).shared()
	if out := fmt.Sprintf("%v %+v %#v %v", tok, tok, tok, *tok); strings.Contains(out, "s3cr3t") {
		t.Fatalf("fmt output = %s, want no s3cr3t", out)
	}
}

func TestTokenLogValue(t *testing.T) {
	exp, err := time.Parse(time.RFC3339, "2030-01-02T03:04:05Z")
	if err != nil {
		t.Fatalf("Parse(expiry) = %v, want nil", err)
	}
	tok := &Token{Value: secret.New("s3cr3t-token"), Type: "Bearer", Expires: exp}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).LogAttrs(t.Context(), slog.LevelInfo, "m", slog.Any("tok", tok))
	fmt.Fprintf(&buf, "%v %+v %#v", tok, tok, tok)
	out := buf.String()
	if strings.Contains(out, "s3cr3t") {
		t.Fatalf("log and fmt output = %s, want no s3cr3t", out)
	}
	if !strings.Contains(out, `"tok":{"type":"Bearer","expires":"2030-01-02T03:04:05Z"}`) {
		t.Fatalf("log record = %s, want the type and expiry group", out)
	}
}

func TestTokenSourceFunc(t *testing.T) {
	want := &Token{Value: secret.New("x")}
	got, err := TokenSourceFunc(func(context.Context) (*Token, error) { return want, nil }).Token(t.Context())
	if err != nil || got != want {
		t.Fatalf("Token = %v, %v, want %v", got, err, want)
	}
}

func TestSignerFunc(t *testing.T) {
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	err := SignerFunc(func(_ context.Context, r *http.Request) error {
		r.Header.Set("X-Signed", "1")
		return nil
	}).Sign(t.Context(), r)
	if err != nil || r.Header.Get("X-Signed") != "1" {
		t.Fatalf("Sign = %v with X-Signed %q, want nil and 1", err, r.Header.Get("X-Signed"))
	}
}

// TestSignerFuncPassesTheContext calls the function with the context Sign gets.
func TestSignerFuncPassesTheContext(t *testing.T) {
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	got := false
	err := SignerFunc(func(ctx context.Context, _ *http.Request) error {
		got = isMarked(ctx)
		return nil
	}).Sign(marked(t), r)
	if err != nil || !got {
		t.Fatalf("Sign = %v with the caller's context passed %t, want nil and true", err, got)
	}
}

// TestAsSignerPassesTheContext asks the source for a token under the context
// Sign gets.
func TestAsSignerPassesTheContext(t *testing.T) {
	got := false
	src := TokenSourceFunc(func(ctx context.Context) (*Token, error) {
		got = isMarked(ctx)
		return &Token{Value: secret.New(seq1)}, nil
	})
	if err := AsSigner(src).Sign(marked(t), newReq(t, http.MethodGet, testAPIURL, http.NoBody)); err != nil || !got {
		t.Fatalf("Sign = %v with the caller's context passed %t, want nil and true", err, got)
	}
}

func TestAsSigner(t *testing.T) {
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	bare := &http.Request{Method: http.MethodGet, URL: r.URL}
	for _, req := range []*http.Request{r, bare} {
		if err := AsSigner(&sequence{}).Sign(t.Context(), req); err != nil {
			t.Fatalf("Sign = %v, want nil", err)
		}
		if got := req.Header.Get(authorization); got != bearerSeq1 {
			t.Fatalf("Authorization = %q, want %q", got, bearerSeq1)
		}
	}
}

// TestAsSignerAllocs signs with a cached token: the header value comes
// rendered from the cache, and the header slice is the one allocation.
func TestAsSignerAllocs(t *testing.T) {
	c, err := NewCachedSource(&sequence{ttl: time.Hour})
	if err != nil {
		t.Fatalf(wantCache, err)
	}
	s := AsSigner(c)
	r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
	assertAllocs(t, 1, func() {
		if err := s.Sign(t.Context(), r); err != nil || r.Header.Get(authorization) != bearerSeq1 {
			t.Fatalf("Sign = %v with %q, want nil and %s", err, r.Header.Get(authorization), bearerSeq1)
		}
	})
}

func BenchmarkAsSigner(b *testing.B) {
	c, err := NewCachedSource(&sequence{ttl: time.Hour})
	if err != nil {
		b.Fatalf(wantCache, err)
	}
	s := AsSigner(c)
	r := newReq(b, http.MethodGet, testAPIURL, http.NoBody)
	if err := s.Sign(b.Context(), r); err != nil || r.Header.Get(authorization) != bearerSeq1 {
		b.Fatalf("Sign = %v with %q, want nil and %s", err, r.Header.Get(authorization), bearerSeq1)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		own := r.Clone(r.Context())
		for pb.Next() {
			if err := s.Sign(own.Context(), own); err != nil {
				b.Errorf("Sign = %v, want nil", err)
				return
			}
		}
	})
}

func TestAsSignerErrors(t *testing.T) {
	var calls atomic.Int32
	failing := &sequence{}
	failing.fail(errSource)
	unsaved := fmt.Errorf("%w: %w", ErrRotationNotSaved, errStore)
	for _, tc := range []struct {
		name string
		src  TokenSource
		want error
	}{
		{"failure", failing, errSource},
		{"no token", nilSource{}, ErrNoToken},
		{"unsaved rotation", tokenWithError(&calls, unsaved), ErrRotationNotSaved},
	} {
		r := newReq(t, http.MethodGet, testAPIURL, http.NoBody)
		err := AsSigner(tc.src).Sign(t.Context(), r)
		if !errors.Is(err, ErrCredential) || !errors.Is(err, tc.want) || r.Header.Get(authorization) != "" {
			t.Errorf("%s: err = %v, Authorization %q; want ErrCredential wrapping %v and no header",
				tc.name, err, r.Header.Get(authorization), tc.want)
		}
	}
}

func TestFetchToken(t *testing.T) {
	tok, err := fetchToken(t.Context(), &sequence{})
	if err != nil || tok.Value.Reveal() != seq1 {
		t.Fatalf("fetchToken = %v, %v, want %s", tok, err, seq1)
	}
	if tok, err := fetchToken(t.Context(), nilSource{}); tok != nil || !errors.Is(err, ErrNoToken) {
		t.Fatalf("nil token = %v, %v, want ErrNoToken", tok, err)
	}
	var calls atomic.Int32
	if tok, err := fetchToken(t.Context(), tokenWithError(&calls, errSource)); tok != nil || !errors.Is(err,
		errSource) {
		t.Fatalf("token with an error = %v, %v, want no token and errSource", tok, err)
	}
}

func TestCredentialError(t *testing.T) {
	once := credentialError(io.EOF)
	if !errors.Is(once, ErrCredential) || !errors.Is(once, io.EOF) {
		t.Fatalf("credentialError(EOF) = %v, want ErrCredential wrapping io.EOF", once)
	}
	if twice := credentialError(once); strings.Count(twice.Error(), ErrCredential.Error()) != 1 {
		t.Fatalf("credentialError(wrapped) = %v, want ErrCredential once", twice)
	}
}

func BenchmarkTokenApply(b *testing.B) {
	jwt := strings.Repeat("a", longToken)
	tok := &Token{Value: secret.New(jwt)}
	r := newReq(b, http.MethodGet, testAPIURL, http.NoBody)
	tok.Apply(r)
	if got := r.Header.Get(authorization); got != "Bearer "+jwt {
		b.Fatalf("Authorization = %.20q, want Bearer and the 1.5 KiB token", got)
	}
	b.ReportAllocs()
	for b.Loop() {
		tok.Apply(r)
	}
}
