package oauthwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/ubyte-source/go-jsonfast"
)

func TestWriteError(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "invalid_request", `bad "redirect_uri"`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	for k, v := range map[string]string{
		headerContentType: "application/json",
		"Cache-Control":   "no-store",
		"Pragma":          "no-cache",
	} {
		if got := rec.Header().Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 2 ||
		got["error"] != "invalid_request" || got["error_description"] != `bad "redirect_uri"` {
		t.Fatalf("body = %s (%v), want the code and the quoted description", rec.Body, err)
	}
}

func TestWriteErrorOmitsEmptyDescription(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusUnauthorized, "invalid_client", "")
	if got := rec.Body.String(); got != `{"error":"invalid_client"}` {
		t.Fatalf("body = %s, want %s", got, `{"error":"invalid_client"}`)
	}
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, []byte(`{"a":1}`))
	hd := rec.Header()
	if rec.Code != http.StatusCreated || rec.Body.String() != `{"a":1}` ||
		hd.Get(headerContentType) != "application/json" ||
		hd.Get("Cache-Control") != "no-store" || hd.Get("Pragma") != "" {
		t.Fatalf("WriteJSON = %d %v %s, want 201 JSON no-store without Pragma", rec.Code, hd, rec.Body)
	}
}

func TestWriteBody(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	rec.Header().Set(headerContentType, "text/plain")
	WriteBody(rec, http.StatusAccepted, []byte("done"))
	if rec.Code != http.StatusAccepted || rec.Body.String() != "done" ||
		rec.Header().Get(headerContentType) != "text/plain" {
		t.Fatalf("WriteBody = %d %v %q, want 202 done with the headers set before", rec.Code, rec.Header(), rec.Body)
	}
}

// readBack fails tb unless out is a UTF-8 JSON object that the strict readers of
// go-jsonfast accept, and returns its tokens as encoding/json reads them.
func readBack(tb testing.TB, out []byte) []json.Token {
	tb.Helper()
	number := func(raw []byte) any { return string(raw) }
	if _, err := jsonfast.DecodeValue(out, jsonfast.MaxDepth, number); err != nil || !utf8.Valid(out) {
		tb.Fatalf("DecodeValue(%q) = %v, want nil for UTF-8", out, err)
	}
	if !jsonfast.ValidUTF8(out, jsonfast.MaxDepth) {
		tb.Fatalf("ValidUTF8(%q) = false, want true", out)
	}
	if err := jsonfast.IterateMembers(out, func(_, _ []byte) error { return nil }); err != nil {
		tb.Fatalf("IterateMembers(%q) = %v, want nil", out, err)
	}
	var tokens []json.Token
	for dec := json.NewDecoder(bytes.NewReader(out)); ; {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return tokens
		}
		if err != nil {
			tb.Fatalf("encoding/json reading %q = %v, want its tokens", out, err)
		}
		tokens = append(tokens, token)
	}
}

// textMember returns the tokens of the member name with the string value s as a
// JSON writer encodes it: each byte of invalid UTF-8 is the replacement character.
func textMember(name, s string) []json.Token {
	return []json.Token{name, string([]rune(s))}
}

// object returns the tokens of a JSON object of the members.
func object(members ...[]json.Token) []json.Token {
	return slices.Concat([]json.Token{json.Delim('{')}, slices.Concat(members...), []json.Token{json.Delim('}')})
}

// FuzzWriteError checks that a strict reader reads back any code and description:
// one object of the error and, unless it is empty, the description, as written.
func FuzzWriteError(f *testing.F) {
	for _, seed := range [][2]string{
		{"invalid_request", `bad "redirect_uri"`}, {"invalid_client", ""}, {"", ""}, {"a\xffb", "\xed\xa0\x80"},
		{"\x00\x1f\x7f", "\u2028\u2029<>&"}, {`\ud800`, "\\"}, {"error", "error_description"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, code, description string) {
		rec := httptest.NewRecorder()
		WriteError(rec, http.StatusBadRequest, code, description)
		want := object(textMember(ParamError, code))
		if description != "" {
			want = object(textMember(ParamError, code), textMember(ParamErrorDescription, description))
		}
		if got := readBack(t, rec.Body.Bytes()); !slices.Equal(got, want) {
			t.Fatalf("WriteError(%q, %q) = %s, read back as %q, want %q", code, description, rec.Body, got, want)
		}
	})
}
