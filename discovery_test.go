package authware

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

// metadataLimit is the largest discovery document accepted, 256 KiB.
const metadataLimit = 256 << 10

// sizedDoc pads a metadata document for base to exactly size bytes.
func sizedDoc(base string, size int) string {
	doc := metadataDoc(base, base)
	return strings.Repeat(" ", size-len(doc)) + doc
}

func discoverWith(tb testing.TB, client *http.Client, raw string) (*serverMetadata, error) {
	tb.Helper()
	return (&issuer{client: client, url: raw}).discover(tb.Context())
}

func TestIssuerDiscover(t *testing.T) {
	const path = "/tenant/v2.0"
	openID := []string{testOpenIDConfiguration}
	tests := []struct {
		name     string
		suffix   string
		docs     map[string]func(string) string
		paths    []string
		jwksOnly bool
	}{
		{"openid", "", openIDDoc(func(b string) string { return metadataDoc(b, b) }), openID, false},
		{"trailing slash", "/", openIDDoc(func(b string) string { return metadataDoc(b+"/", b) }), openID, false},
		{"openid with path", path, map[string]func(string) string{
			path + testOpenIDConfiguration: func(b string) string { return metadataDoc(b+path, b) },
		}, []string{path + testOpenIDConfiguration}, false},
		{"authorization server", path, map[string]func(string) string{
			testServerMetadata + path: func(b string) string { return metadataDoc(b+path, b) },
		}, []string{path + testOpenIDConfiguration, testServerMetadata + path}, false},
		{"authorization server after another issuer", path, map[string]func(string) string{
			path + testOpenIDConfiguration: func(b string) string { return metadataDoc(testIssuerURL, b) },
			testServerMetadata + path:      func(b string) string { return metadataDoc(b+path, b) },
		}, []string{path + testOpenIDConfiguration, testServerMetadata + path}, false},
		{"jwks only", "", openIDDoc(func(b string) string {
			return `{"issuer":"` + b + `","jwks_uri":"` + b + `/jwks"}`
		}), openID, true},
		{"size limit", "", openIDDoc(func(b string) string { return sizedDoc(b, metadataLimit) }), openID, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newMetadataServer(t, tc.docs)
			md, err := discoverWith(t, srv.Client(), srv.URL+tc.suffix)
			if err != nil {
				t.Fatalf("discover = %v, want the metadata", err)
			}
			want := serverMetadata{
				iss:                   srv.URL + tc.suffix,
				jwksURI:               srv.URL + testJWKSPath,
				authorizationEndpoint: srv.URL + "/authorize",
				tokenEndpoint:         srv.URL + "/token",
			}
			if tc.jwksOnly {
				want.authorizationEndpoint, want.tokenEndpoint = "", ""
			}
			if *md != want || strings.Join(srv.paths, " ") != strings.Join(tc.paths, " ") {
				t.Fatalf("discover = %+v after %v; want %+v after %v", md, srv.paths, &want, tc.paths)
			}
		})
	}
}

func TestIssuerDiscoverRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  func(base string) string
		want error
	}{
		{"over size limit", func(b string) string { return sizedDoc(b, metadataLimit+1) }, errBodyTooLarge},
		{"issuer slash mismatch", func(b string) string { return metadataDoc(b+"/", b) }, errIssuerMismatch},
		{"other issuer", func(b string) string { return metadataDoc(testIssuerURL, b) }, errIssuerMismatch},
		{"issuer case", func(b string) string { return metadataDoc(strings.ToUpper(b), b) }, errIssuerMismatch},
		{"endpoints elsewhere", func(b string) string { return metadataDoc(b, testIssuerURL) }, errCrossOrigin},
		{"jwks_uri number", func(b string) string { return `{"issuer":"` + b + `","jwks_uri":7}` }, errMetadata},
		{"truncated", func(b string) string { return `{"issuer":"` + b + `"` }, errMetadata},
		{"latin1", func(b string) string { return `{"issuer":"` + b + `","x":"caf\xe9"}` }, errMetadata},
		{"not found", nil, statusError(http.StatusNotFound)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docs := openIDDoc(tc.doc)
			if tc.doc == nil {
				docs = nil
			}
			srv := newMetadataServer(t, docs)
			md, err := discoverWith(t, srv.Client(), srv.URL)
			if md != nil || !errorMatches(err, tc.want) || !errors.Is(err, errDiscovery) {
				t.Fatalf("discover = %+v, %v; want nil, %v", md, err, tc.want)
			}
		})
	}
}

func TestFetchMetadata(t *testing.T) {
	origins := map[string]func(base string) string{
		"host":   func(string) string { return testIssuerURL },
		"port":   func(b string) string { return b[:strings.LastIndexByte(b, ':')] + ":1" },
		"scheme": func(b string) string { return strings.Replace(b, netguard.SchemeHTTP+"://", "https://", 1) },
	}
	for _, suffix := range []string{testJWKSPath, "/authorize", "/token"} {
		for name, origin := range origins {
			srv := newMetadataServer(t, map[string]func(string) string{testOpenIDConfiguration: func(b string) string {
				return strings.Replace(metadataDoc(b, b), `"`+b+suffix+`"`, `"`+origin(b)+suffix+`"`, 1)
			}})
			base, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatalf("Parse(%s) = %v, want the URL", srv.URL, err)
			}
			md, err := fetchMetadata(t.Context(), srv.Client(), srv.URL+testOpenIDConfiguration, base)
			if md != nil || !errors.Is(err, errCrossOrigin) {
				t.Errorf("fetchMetadata(%s on another %s) = %+v, %v, want nil, errCrossOrigin", suffix, name, md, err)
			}
		}
	}
}

func TestFetchMetadataRejects(t *testing.T) {
	srv := newMetadataServer(t, openIDDoc(func(string) string { return jsonEmptyArray }))
	base := &url.URL{Scheme: netguard.SchemeHTTP, Host: srv.Listener.Addr().String()}
	for path, want := range map[string]error{
		"/missing": statusError(http.StatusNotFound), testOpenIDConfiguration: errMetadata,
	} {
		if md, err := fetchMetadata(t.Context(), srv.Client(), srv.URL+path, base); md != nil ||
			!errorMatches(err, want) {
			t.Errorf("fetchMetadata(%s) = %+v, %v, want nil, %v", path, md, err, want)
		}
	}
}

func TestIssuerDiscoverInsecure(t *testing.T) {
	for _, raw := range []string{"http://issuer.example", "https://user:pw@issuer.example", "::"} {
		if md, err := discoverWith(t, http.DefaultClient, raw); md != nil || !errors.Is(err, ErrInsecureURL) ||
			!errors.Is(err, errDiscovery) || strings.Contains(err.Error(), "pw") {
			t.Errorf("discover(%q) = %+v, %v, want nil, errDiscovery wrapping ErrInsecureURL without userinfo", raw, md,
				err)
		}
	}
}

func TestServerMetadataSet(t *testing.T) {
	var md serverMetadata
	for name, value := range map[string]string{
		"issuer": `"i"`, "jwks_uri": `"j"`, "authorization_endpoint": `"a"`, "token_endpoint": `"t"`, "other": `5`,
	} {
		if err := md.set(name, value); err != nil {
			t.Fatalf("set(%s) = %v, want nil", name, err)
		}
	}
	if md != (serverMetadata{iss: "i", jwksURI: "j", authorizationEndpoint: "a", tokenEndpoint: "t"}) {
		t.Fatalf("set = %+v, want every endpoint recorded", &md)
	}
	issuerJSON := `"https://issuer.example/tenant"`
	// One allocation: the copy that frees the document.
	assertAllocs(t, 1, func() {
		if err := md.set(metaIssuer, issuerJSON); err != nil {
			t.Fatalf("set(issuer) = %v, want nil", err)
		}
	})
	if err := md.set("token_endpoint", `["t"]`); !errors.Is(err, errMetadata) {
		t.Fatalf("set(array endpoint) = %v, want errMetadata", err)
	}
}

func TestSameOrigin(t *testing.T) {
	const idp, local = "https://idp.example/tenant", "http://localhost:8080"
	tests := []struct {
		base, raw string
		want      error
	}{
		{idp, "https://idp.example/keys", nil},
		{idp, "https://IDP.example:443/keys", nil},
		{idp, "https://idp.example:8443/keys", errCrossOrigin},
		{idp, "https://other.example/keys", errCrossOrigin},
		{idp, "https://idp.example.evil/keys", errCrossOrigin},
		{idp, "http://idp.example/keys", ErrInsecureURL},
		{idp, "https://u:p@idp.example/keys", ErrInsecureURL},
		{idp, "/relative/keys", ErrInsecureURL},
		{local, "http://localhost:8080/keys", nil},
		{local, "https://localhost:8080/keys", errCrossOrigin},
		{local, "http://127.0.0.1:8080/keys", errCrossOrigin},
	}
	for _, tc := range tests {
		base, err := url.Parse(tc.base)
		if err != nil {
			t.Fatalf("Parse(%s) = %v, want the URL", tc.base, err)
		}
		if err := sameOrigin(base, tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("sameOrigin(%s, %s) = %v, want %v", tc.base, tc.raw, err, tc.want)
		}
	}
}

func TestNewIssuerLogsFailures(t *testing.T) {
	srv := newMetadataServer(t, nil)
	var logs logCapture
	iss := newIssuer(withDefaults(&Config{ErrorLog: slog.New(&logs), OAuth: OAuthConfig{Issuer: srv.URL}}))
	_, err := iss.metadata.get(marked(t), time.Unix(testUnix, 0))
	if got := logs.logged(); !errors.Is(err, errDiscovery) || !logs.warned("authware: metadata fetch failed",
		errDiscovery) || !got[0].inMarked {
		t.Fatalf("metadata.get = %v with %+v logged, want errDiscovery warned once under the caller's context", err,
			got)
	}
	served := newMetadataServer(t, openIDDoc(func(b string) string { return metadataDoc(b, b) }))
	var quiet logCapture
	iss = newIssuer(withDefaults(&Config{ErrorLog: slog.New(&quiet), OAuth: OAuthConfig{Issuer: served.URL}}))
	if _, err := iss.metadata.get(t.Context(), time.Unix(testUnix, 0)); err != nil || len(quiet.logged()) != 0 {
		t.Fatalf("metadata.get = %v with %+v logged, want the metadata and nothing logged", err, quiet.logged())
	}
}

func TestNewIssuer(t *testing.T) {
	srv := newMetadataServer(t, openIDDoc(func(b string) string { return metadataDoc(b, b) }))
	caller := &http.Client{Transport: srv.Client().Transport, Timeout: time.Minute}
	iss := newIssuer(&Config{HTTPClient: caller, OAuth: OAuthConfig{
		Issuer: srv.URL, KeysCacheTTL: time.Hour, FetchTimeout: time.Second,
	}})
	type summary struct {
		url                         string
		clientTimeout, ttl, timeout time.Duration
		guarded, shared, logging    bool
	}
	got := summary{
		iss.url, iss.client.Timeout, iss.metadata.ttl, iss.metadata.timeout, iss.client.CheckRedirect != nil,
		iss.client == caller, iss.log.Enabled(t.Context(), slog.LevelError),
	}
	if want := (summary{srv.URL, time.Second, time.Hour, time.Second, true, false, false}); got != want ||
		caller.CheckRedirect != nil {
		t.Fatalf("newIssuer = %+v, want %+v with the caller's client untouched and no log", got, want)
	}
	now := time.Unix(testUnix, 0)
	for range 2 {
		if md, err := iss.metadata.get(t.Context(), now); err != nil || md.iss != srv.URL {
			t.Fatalf("metadata.get = %+v, %v, want the metadata of %s", md, err, srv.URL)
		}
	}
	if len(srv.paths) != 1 {
		t.Fatalf("metadata requests = %v, want one", srv.paths)
	}
}

// FuzzFetchMetadata checks every document of the issuer testIssuerURL
// against referenceMetadata: the endpoints it accepts, else its refusal class.
func FuzzFetchMetadata(f *testing.F) {
	f.Add(metadataDoc(testIssuerURL, testIssuerURL))
	f.Add(`{"issuer":"x","jwks_uri":"https://ISSUER.example.com:443/k",` +
		`"token_endpoint":"https://issuer.example.com:8443/t"}`)
	f.Add(`{"authorization_endpoint":"http://issuer.example.com/a","extra":[{"a":1}]}`)
	f.Add(`{"issuer":"https://issuer.example.com","extra":[{"a":1,"a":1}]}`)
	f.Add(`{"issuer":"https://issuer.example.com","x":1e400,"extra":[{"a":-1E+999}]}`)
	f.Add(`{"issuer":null,"jwks_uri":1}`)
	f.Add(`{"token_endpoint":"https://u@issuer.example.com/t","issuer":"i"}x`)
	base, err := url.Parse(testIssuerURL)
	if err != nil {
		f.Fatalf("Parse(%s) = %v, want the URL", testIssuerURL, err)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		client := &http.Client{Transport: answerWith(http.StatusOK, doc)}
		md, err := fetchMetadata(t.Context(), client, testIssuerURL+testOpenIDConfiguration, base)
		want, wantErr := referenceMetadata(doc)
		if !errors.Is(err, wantErr) || (wantErr == nil) != (err == nil) || (md == nil) != (want == nil) ||
			(md != nil && *md != *want) {
			t.Fatalf("fetchMetadata(%q) = %+v, %v; want %+v, %v", doc, md, err, want, wantErr)
		}
	})
}

// referenceMetadata returns the endpoints of doc, testIssuerURL's metadata, or
// errMetadata for a fault or a member neither string nor null, then
// ErrInsecureURL or errCrossOrigin for an endpoint refused or off the origin.
func referenceMetadata(doc string) (*serverMetadata, error) {
	if len(doc) > metadataLimit {
		return nil, errBodyTooLarge
	}
	var md serverMetadata
	fields := map[string]*string{
		"issuer": &md.iss, "jwks_uri": &md.jwksURI, "authorization_endpoint": &md.authorizationEndpoint,
		"token_endpoint": &md.tokenEndpoint,
	}
	err := strictMembers(doc, func(name string, value json.RawMessage) error {
		dst, read := fields[name]
		if !read || string(value) == jsonNull {
			return nil
		}
		s, ok := stringValue(value)
		if !ok {
			return errMetadata
		}
		*dst = s
		return nil
	})
	if err != nil {
		return nil, errMetadata
	}
	for _, endpoint := range []string{md.jwksURI, md.authorizationEndpoint, md.tokenEndpoint} {
		if err := referenceEndpoint(endpoint); err != nil {
			return nil, err
		}
	}
	return &md, nil
}

// referenceEndpoint accepts an endpoint that is empty, or that passes the
// outbound URL policy on the origin of testIssuerURL.
func referenceEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	if _, err := netguard.Check(endpoint, errNoRoute); err != nil {
		return ErrInsecureURL
	}
	if !onIssuerOrigin(endpoint) {
		return errCrossOrigin
	}
	return nil
}

// onIssuerOrigin reports whether raw is an https URL of the host of
// testIssuerURL on the default port, without userinfo.
func onIssuerOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.User == nil &&
		strings.EqualFold(u.Hostname(), "issuer.example.com") && (u.Port() == "" || u.Port() == "443")
}
