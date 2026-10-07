package authware

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

// The start of a registration naming its redirect URIs, and a nesting deeper
// than the parser takes.
const (
	urisOpen  = `{"redirect_uris":[`
	nestDepth = 40
)

// register posts body to the registration endpoint of a facade.
func register(t *testing.T, body string) (code int, reply, errorCode string) {
	t.Helper()
	f := testFacade(t, facadeConfig(newFakeIDP(t)))
	r := newReq(t, http.MethodPost, testMCPOrigin+pathRegister, strings.NewReader(body))
	r.Header.Set("Content-Type", testTypeJSON)
	w := serve(http.HandlerFunc(f.serveRegister), r)
	if w.Code != http.StatusCreated {
		errorCode = oauthErrorCode(t, w)
	}
	return w.Code, w.Body.String(), errorCode
}

func TestFacadeServeRegister(t *testing.T) {
	for _, c := range claudeClients() {
		code, reply, _ := register(t, c.registration)
		want := `{"client_id":"` + testFacadeClient + `","token_endpoint_auth_method":"none",` +
			`"grant_types":["authorization_code","refresh_token"],"response_types":["code"],` +
			`"redirect_uris":["` + c.redirectURI + `"]}`
		if code != http.StatusCreated || reply != want {
			t.Errorf("%s: register = %d %s, want 201 %s", c.name, code, reply, want)
		}
	}
	f := testFacade(t, facadeConfig(newFakeIDP(t)))
	body := `{"redirect_uris":["https://claude.ai/cb","http://127.0.0.1:9/cb"]}`
	w := serve(http.HandlerFunc(f.serveRegister), newReq(t, http.MethodPost, pathRegister, strings.NewReader(body)))
	const uris = `"redirect_uris":["https://claude.ai/cb","http://127.0.0.1:9/cb"]`
	if w.Header().Get("Cache-Control") != oauthwire.CacheNoStore || w.Header().Get("Content-Type") != testTypeJSON ||
		!strings.Contains(w.Body.String(), uris) {
		t.Fatalf("register = %v %s, want no-store JSON with %s", w.Header(), w.Body, uris)
	}
}

// TestFacadeServeRegisterBodyLimit pins the 64 KiB body bound: a valid body
// padded to exactly the limit registers, one byte more is refused.
func TestFacadeServeRegisterBodyLimit(t *testing.T) {
	const limit = 64 << 10
	valid := `{"redirect_uris":["https://claude.ai/cb"]}`
	for size, want := range map[int]int{limit: http.StatusCreated, limit + 1: http.StatusBadRequest} {
		code, reply, errorCode := register(t, valid+strings.Repeat(" ", size-len(valid)))
		if code != want || code == http.StatusBadRequest && errorCode != codeInvalidClientMetadata {
			t.Errorf("register of %d bytes = %d %.80s, want %d (%s when refused)",
				size, code, reply, want, codeInvalidClientMetadata)
		}
	}
}

func TestFacadeServeRegisterRejects(t *testing.T) {
	const cb = `"https://claude.ai/cb"`
	nested := strings.Repeat("[", nestDepth) + strings.Repeat("]", nestDepth)
	for body, want := range map[string]string{
		``:                        codeInvalidClientMetadata,
		jsonEmptyArray:            codeInvalidClientMetadata,
		urisOpen + cb + `]`:       codeInvalidClientMetadata,
		urisOpen + cb + `]} true`: codeInvalidClientMetadata,
		urisOpen + cb + `],"redirect_uris":["http://evil.example/cb"]}`: codeInvalidClientMetadata,
		urisOpen + cb + `],"x":` + nested + `}`:                         codeInvalidClientMetadata,
		`{"client_name":"x"}`:                                           codeInvalidRedirectURI,
		`{"redirect_uris":[]}`:                                          codeInvalidRedirectURI,
		`{"redirect_uris":"javascript:alert(1)"}`:                       codeInvalidRedirectURI,
		`{"redirect_uris":{"a":1}}`:                                     codeInvalidRedirectURI,
		`{"redirect_uris":[1]}`:                                         codeInvalidRedirectURI,
		urisOpen + cb + `,null]}`:                                       codeInvalidRedirectURI,
		`{"redirect_uris":["javascript:alert(1)"]}`:                     codeInvalidRedirectURI,
		`{"redirect_uris":["http://evil.example/cb"]}`:                  codeInvalidRedirectURI,
		`{"redirect_uris":["https://claude.ai/cb#x"]}`:                  codeInvalidRedirectURI,
		urisOpen + cb + `,"ftp://x"]}`:                                  codeInvalidRedirectURI,
	} {
		if code, reply, got := register(t, body); code != http.StatusBadRequest || got != want {
			t.Errorf("register(%.60s) = %d %s, want 400 %s", body, code, reply, want)
		}
	}
}

func TestRedirectURIs(t *testing.T) {
	uris, err := redirectURIs([]byte(`{"redirect_uris":["https://claude.ai/a` + escape('b') + `"]}`))
	if want := []string{"https://claude.ai/ab"}; err != nil || !slices.Equal(uris, want) {
		t.Fatalf("redirectURIs = %q, %v; want %q, nil", uris, err, want)
	}
	if uris, err := redirectURIs([]byte(`{}`)); uris != nil || !errors.Is(err, errRedirectURIs) {
		t.Fatalf("redirectURIs without redirect_uris = %q, %v, want nil, errRedirectURIs", uris, err)
	}
	for _, body := range []string{`{`, `{"redirect_uris":["https://` + "\x9f" + `"]}`} {
		if uris, err := redirectURIs([]byte(body)); uris != nil || !errors.Is(err, errClientMetadata) {
			t.Fatalf("redirectURIs(%q) = %q, %v, want nil, errClientMetadata", body, uris, err)
		}
	}
}

// FuzzRedirectURIs checks every body against a reference built on
// encoding/json: the redirect URIs of a strict object whose redirect_uris is a
// non-empty array of valid URIs, else the class of the refusal.
func FuzzRedirectURIs(f *testing.F) {
	for _, c := range claudeClients() {
		f.Add([]byte(c.registration))
	}
	f.Add([]byte(`{"redirect_uris":["https://a.example/cb","http://[::1]:1/x"],"x":{"y":[1]}}`))
	f.Add([]byte(`{"redirect_uris":["https://a.example/c` + escape('b') + `"]}`))
	f.Add([]byte(`{"redirect_uris":["https://a.example/cb"],"REDIRECT_URIS":["https://b.example/cb"]}`))
	f.Add([]byte(`{"redirect_uris":["http://evil.example/cb"],"x":` + "\xff}"))
	f.Add([]byte(`{"x":` + "\"\\ud800\"" + `,"redirect_uris":[]}`))
	f.Add([]byte(`{"redirect_uris":["https://a.example/cb"],"x":{"y":1,"y":1}}`))
	f.Add([]byte(`{"redirect_uris":["https://a.example/cb"],"x":1e400,"y":[{"a":-1E+999}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		uris, err := redirectURIs(body)
		want, wantErr := referenceRedirectURIs(string(body))
		if !errors.Is(err, wantErr) || (wantErr == nil) != (err == nil) || !slices.Equal(uris, want) {
			t.Fatalf("redirectURIs(%q) = %q, %v; want %q, %v", body, uris, err, want, wantErr)
		}
	})
}

// referenceRedirectURIs returns the redirect URIs that the registration body
// names, or errClientMetadata for what is no strict JSON object and
// errRedirectURIs for a missing, empty or invalid redirect_uris.
func referenceRedirectURIs(body string) ([]string, error) {
	var uris []string
	err := strictMembers(body, func(name string, value json.RawMessage) error {
		if name != "redirect_uris" {
			return nil
		}
		list, ok := stringValues(value)
		if !ok || slices.ContainsFunc(list, func(u string) bool { return !referenceRedirectURI(u) }) {
			return errRedirectURIs
		}
		uris = list
		return nil
	})
	switch {
	case errors.Is(err, errNotStrict):
		return nil, errClientMetadata
	case err != nil:
		return nil, err
	case len(uris) == 0:
		return nil, errRedirectURIs
	}
	return uris, nil
}
