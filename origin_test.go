package authware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

func TestOriginResolverOrigin(t *testing.T) {
	tests := []struct {
		name     string
		tls      *tls.ConnectionState
		public   string
		proto    string
		want     string
		trustXFP bool
	}{
		{name: "plain", want: testAPIOrigin},
		{name: "tls", tls: &tls.ConnectionState{}, want: "https://api.example"},
		{name: "untrusted proto", proto: "https", want: testAPIOrigin},
		{name: "trusted proto", proto: " HTTPS , http", trustXFP: true, want: "https://api.example"},
		{name: "trusted bogus", proto: "ftp", trustXFP: true, want: testAPIOrigin},
		{name: "tls wins", tls: &tls.ConnectionState{}, proto: "http", trustXFP: true, want: "https://api.example"},
		{name: "public", public: testPublicURL, tls: &tls.ConnectionState{}, want: testPublicURL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReq(t, http.MethodGet, "http://api.example/mcp", http.NoBody)
			r.TLS = tc.tls
			if tc.proto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			o := originResolver{public: tc.public, trustProto: tc.trustXFP}
			if got := o.origin(r); got != tc.want {
				t.Fatalf("origin = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestForwardedProto(t *testing.T) {
	for in, want := range map[string]string{"": "", "http": "http", "Https,http": "https", "wss": ""} {
		h := http.Header{}
		h.Set("X-Forwarded-Proto", in)
		if got := forwardedProto(h); got != want {
			t.Errorf("forwardedProto(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzForwardedProto checks forwardedProto against a reference: the first
// element of the first X-Forwarded-Proto value, without surrounding white
// space, when it spells http or https in any ASCII case, lower-cased.
func FuzzForwardedProto(f *testing.F) {
	for _, seed := range []string{" HTTPS , http", "http,https", "ftp", "", "\u00a0https", "http\u017f", "htt"} {
		f.Add(seed, netguard.SchemeHTTPS)
	}
	f.Fuzz(func(t *testing.T, first, second string) {
		element, _, _ := strings.Cut(first, ",")
		element = strings.TrimFunc(element, unicode.IsSpace)
		want := ""
		for _, scheme := range []string{netguard.SchemeHTTP, netguard.SchemeHTTPS} {
			if len(element) == len(scheme) && strings.EqualFold(element, scheme) {
				want = scheme
			}
		}
		if got := forwardedProto(http.Header{"X-Forwarded-Proto": {first, second}}); got != want {
			t.Fatalf("forwardedProto(%q, %q) = %q, want %q", first, second, got, want)
		}
	})
}

func TestOriginResolverWriteDocument(t *testing.T) {
	w := httptest.NewRecorder()
	originResolver{}.writeDocument(w, []byte(`{}`))
	h := w.Header()
	if w.Code != http.StatusOK || w.Body.String() != `{}` || h.Get("Content-Type") != testTypeJSON ||
		h.Get("Cache-Control") != "private, max-age=300" || h.Get("Vary") != "Host, X-Forwarded-Proto" {
		t.Fatalf("writeDocument = %d %v, want 200 JSON cached privately and varying by host and proto", w.Code, h)
	}
	w = httptest.NewRecorder()
	originResolver{public: testHTTPS}.writeDocument(w, []byte(`{}`))
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300" || w.Header().Get("Vary") != "" {
		t.Fatalf("writeDocument(fixed origin) = %v, want a public cache without Vary", w.Header())
	}
}
