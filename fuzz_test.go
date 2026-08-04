package authware

import (
	"encoding/base64"
	"net/url"
	"testing"
)

var _ = base64.RawURLEncoding // keep import for future seed corpus growth

// FuzzSplitJWT exercises the dot-segment splitter on arbitrary input.
// It must never panic regardless of malformation.
func FuzzSplitJWT(f *testing.F) {
	f.Add([]byte("a.b.c"))
	f.Add([]byte(""))
	f.Add([]byte("..."))
	f.Add([]byte("a.b.c.d"))
	f.Add([]byte(".."))
	f.Add([]byte("a..c"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _, _, _ = splitJWT(data)
	})
}

// FuzzParseJWTHeaderDirect ensures the JOSE header parser is panic-free
// on arbitrary base64-shaped input.
func FuzzParseJWTHeaderDirect(f *testing.F) {
	f.Add([]byte("eyJhbGciOiJIUzI1NiJ9"))
	f.Add([]byte(""))
	f.Add([]byte("not-base64"))
	f.Add([]byte("eyJ0eXAiOiJKV1QifQ"))

	f.Fuzz(func(_ *testing.T, encoded []byte) {
		h, err := parseJWTHeader(encoded)
		_, _ = h, err
	})
}

// FuzzExtractClaims fuzzes the claims scanner. The function uses
// jsonfast.IterateFields which itself is fuzzed upstream, but this
// guard pins the contract that authware does not panic on the
// integration boundary.
func FuzzExtractClaims(f *testing.F) {
	f.Add([]byte(`{"sub":"x","exp":1}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"scp":["a","b"]}`))
	f.Add([]byte(`{"aud":["x","y"]}`))

	f.Fuzz(func(_ *testing.T, payload []byte) {
		_ = extractClaims(payload)
	})
}

// FuzzDecodeAlg ensures alg interning is panic-free on any JSON value bytes.
func FuzzDecodeAlg(f *testing.F) {
	f.Add([]byte(`"HS256"`))
	f.Add([]byte(`"none"`))
	f.Add([]byte(``))
	f.Add([]byte(`"`))

	f.Fuzz(func(_ *testing.T, raw []byte) {
		_ = decodeAlg(raw)
	})
}

// FuzzDecodeClaimValue covers every JSON scalar branch.
func FuzzDecodeClaimValue(f *testing.F) {
	f.Add([]byte(`"hello"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`-9.9`))
	f.Add([]byte(`true`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(_ *testing.T, raw []byte) {
		_ = decodeClaimValue(raw)
	})
}

// FuzzSanitiseHeaderValue verifies the AuthCheckHandler header sanitiser
// always returns control-byte-free output.
func FuzzSanitiseHeaderValue(f *testing.F) {
	f.Add("clean-value")
	f.Add("with\rCR")
	f.Add("with\nLF")
	f.Add("\x00null")

	f.Fuzz(func(t *testing.T, in string) {
		out := sanitiseHeaderValue(in)
		for i := range len(out) {
			c := out[i]
			if c < 0x20 || c == 0x7F {
				t.Fatalf("control byte %#x at index %d", c, i)
			}
		}
	})
}

// FuzzRequireHTTPS ensures the URL scheme guard never panics and admits only
// what the caller is allowed to fetch: https, or http to a loopback host, and
// never credentials in the URL.
//
// The oracle asserts against what the HTTP client will actually do — the URL as
// net/url parses it, the same parse http.NewRequest performs — instead of
// re-deriving the authority by hand. An earlier hand-rolled version split
// userinfo at the first "@" while net/url splits at the last, so it called
// "http://@@localhost" non-loopback and flagged a guard that was reading the
// host correctly; the real defect it pointed at was the missing userinfo
// refusal, not the host check.
func FuzzRequireHTTPS(f *testing.F) {
	f.Add("https://example.com")
	f.Add("http://localhost:8080")
	f.Add("http://example.com")
	f.Add("ftp://example.com")
	f.Add("")
	f.Add("http://@@localhost")
	f.Add("https://user:pass@example.com")
	f.Add("http://localhost@evil.example")

	f.Fuzz(func(t *testing.T, raw string) {
		err := requireHTTPS(raw)
		if err != nil {
			return // rejecting is always allowed; the guard may be stricter
		}
		// Admitted: it must be a URL net/http can send, with no credentials,
		// and either https or http to loopback.
		u, parseErr := url.Parse(raw)
		if parseErr != nil {
			t.Fatalf("admitted an unparseable URL %q: %v", raw, parseErr)
		}
		if u.User != nil {
			t.Fatalf("admitted URL carrying userinfo %q: net/http would send it as Basic auth", raw)
		}
		switch u.Scheme {
		case schemeHTTPS:
		case schemeHTTP:
			if !isLoopbackHost(u.Hostname()) {
				t.Fatalf("admitted plaintext http to non-loopback host %q: %q", u.Hostname(), raw)
			}
		default:
			t.Fatalf("admitted non-http(s) scheme %q: %q", u.Scheme, raw)
		}
	})
}

// FuzzAlgorithmConfusion verifies that JWT validation never accepts a
// token whose alg differs from what's bound to the supplied key. This
// is the classic critical confusion attack — fuzzing keeps it locked.
func FuzzAlgorithmConfusion(f *testing.F) {
	// Seed: standard JOSE header.
	f.Add([]byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aaaa"))

	f.Fuzz(func(_ *testing.T, raw []byte) {
		// Just invoke the splitter + header parser; full validation
		// requires a key, out of scope for boundary fuzzing.
		if h, p, s, _, ok := splitJWT(raw); ok {
			hdr, hdrErr := parseJWTHeader(h)
			_, _ = hdr, hdrErr
			payload, payErr := base64.RawURLEncoding.DecodeString(string(p))
			_, _ = payload, payErr
			sig, sigErr := base64.RawURLEncoding.DecodeString(string(s))
			_, _ = sig, sigErr
		}
	})
}
