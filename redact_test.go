package authware

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

const leaked = "TOPSECRET"

// headerValuer logs as a group holding an Authorization attribute.
type headerValuer struct{}

// LogValue returns a group carrying a bearer token and a path.
func (headerValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String(headerAuthorization, "Bearer "+leaked), slog.String("path", "/x"))
}

// nestedValuer resolves to another LogValuer.
type nestedValuer struct{}

func (nestedValuer) LogValue() slog.Value { return slog.AnyValue(headerValuer{}) }

// The message, keys and header names the redactor tests log.
const (
	logMessage   = "m"
	logKey       = "v"
	logRequest   = "req"
	headerCookie = "Cookie"
	headerID     = "X-Id"
)

func redactedLog(t *testing.T, log func(*slog.Logger)) string {
	t.Helper()
	var buf bytes.Buffer
	log(slog.New(NewRedactor(slog.NewTextHandler(&buf, nil), SensitiveHeaders()...)))
	out := buf.String()
	if strings.Contains(out, leaked) {
		t.Fatalf("log = %s, want no %s in it", out, leaked)
	}
	return out
}

// TestNewRedactor logs a credential under every sensitive name, in either
// case, at every depth, and values that carry one: each logs masked.
func TestNewRedactor(t *testing.T) {
	cases := map[string]func(*slog.Logger){
		"valuer": func(l *slog.Logger) { l.Info(logMessage, slog.Any(logRequest, headerValuer{})) },
		"nested": func(l *slog.Logger) {
			l.Info(logMessage, slog.Group("g", slog.Any(logRequest, nestedValuer{})))
		},
		"header": func(l *slog.Logger) {
			l.Info(logMessage, slog.Any("h", http.Header{headerAuthorization: {leaked}, headerID: {"7"}}))
		},
		"with attrs": func(l *slog.Logger) { l.With(slog.Any(logRequest, headerValuer{})).Info(logMessage) },
	}
	for _, name := range SensitiveHeaders() {
		for _, key := range []string{name, strings.ToLower(name)} {
			attr := slog.String(key, leaked)
			cases[key+" top level"] = func(l *slog.Logger) { l.Info(logMessage, attr) }
			cases[key+" group"] = func(l *slog.Logger) { l.Info(logMessage, slog.Group(logRequest, attr)) }
			cases[key+" with group"] = func(l *slog.Logger) { l.WithGroup("g").Info(logMessage, attr) }
			cases[key+" group then attrs"] = func(l *slog.Logger) { l.WithGroup("g").With(attr).Info(logMessage) }
		}
	}
	for name, log := range cases {
		t.Run(name, func(t *testing.T) {
			if out := redactedLog(t, log); !strings.Contains(out, redactedValue) {
				t.Fatalf("log = %s, want %s in it", out, redactedValue)
			}
		})
	}
}

// TestNewRedactorPassesTheContext asks and hands the inner handler the context
// of each record.
func TestNewRedactorPassesTheContext(t *testing.T) {
	inner := &logCapture{onlyMarked: true}
	logger := slog.New(NewRedactor(inner))
	logger.InfoContext(marked(t), logMessage)
	logger.InfoContext(t.Context(), logMessage)
	if got := inner.logged(); len(got) != 1 || !got[0].inMarked {
		t.Fatalf("records = %+v, want the one logged under the marked context", got)
	}
}

// TestNewRedactorCopiesTheKeys masks the names it was given even after the
// caller reuses their slice.
func TestNewRedactorCopiesTheKeys(t *testing.T) {
	var out strings.Builder
	keys := []string{"tenant_key"}
	logger := slog.New(NewRedactor(slog.NewTextHandler(&out, nil), keys...))
	keys[0] = "other_key"
	logger.Info(logMessage, slog.String("tenant_key", leaked))
	if strings.Contains(out.String(), leaked) || !strings.Contains(out.String(), "tenant_key="+redactedValue) {
		t.Fatalf("log after the caller reused its keys = %s, want tenant_key masked", out.String())
	}
}

// TestNewRedactorValues logs every value that can carry credentials under a
// key that is not sensitive: each renders without them.
func TestNewRedactorValues(t *testing.T) {
	secretURL := &url.URL{
		Scheme: netguard.SchemeHTTPS, User: url.UserPassword("svc", leaked), Host: "idp.example", Path: "/t",
	}
	header := http.Header{headerAuthorization: {"Bearer " + leaked}, headerID: {"7"}}
	queryURL, err := url.Parse("https://api.example/cb?code=" + leaked + "&access%5Ftoken=" + leaked +
		"&Client_Secret=" + leaked + "&x-api-key=" + leaked + "&state=s&%zz=v&&k")
	if err != nil {
		t.Fatalf("Parse(query URL) = %v, want nil", err)
	}
	queryReq := newReq(t, http.MethodGet, "https://api.example/cb?id_token="+leaked+"&code_verifier="+leaked+
		"&password="+leaked+"&api_key="+leaked+"&client_assertion="+leaked+"&x=1", http.NoBody)
	req := newReq(t, http.MethodPost, "https://svc:"+leaked+"@api.example/x", http.NoBody)
	req.Header = header.Clone()
	resp := &http.Response{StatusCode: http.StatusTeapot, Header: http.Header{"Set-Cookie": {leaked}}, Request: req}
	for name, tc := range map[string]struct {
		value any
		want  string
	}{
		"header":     {header, `v="map[Authorization:[***] X-Id:[7]]"`},
		"header ref": {&header, `v="map[Authorization:[***] X-Id:[7]]"`},
		"header map": {map[string][]string(header), `v="map[Authorization:[***]`},
		"lower map": {map[string][]string{"cookie": {leaked}, "location": {"/cb?code=" + leaked}},
			`v="map[cookie:[***] location:[/cb?code=***]]"`},
		"url":          {secretURL, "v=https://svc:xxxxx@idp.example/t"},
		"url value":    {*secretURL, "v=https://svc:xxxxx@idp.example/t"},
		"userinfo":     {secretURL.User, "v=svc:xxxxx"},
		"user no pass": {url.User("svc"), "v=svc\n"},
		"url query": {queryURL,
			`v="https://api.example/cb?code=***&access%5Ftoken=***&Client_Secret=***&x-api-key=***&state=s&%zz=v&&k"`},
		"values": {url.Values{"refresh_token": {leaked, leaked}, "s": {"1"}}, `v="map[refresh_token:[*** ***] s:[1]]"`},
		"request query": {queryReq, `v.url="https://api.example/cb?id_token=***&code_verifier=***&password=***` +
			`&api_key=***&client_assertion=***&x=1"`},
		"request":       {req, "v.method=POST v.url=https://svc:xxxxx@api.example/x"},
		"request hdr":   {req, `v.header="map[Authorization:[***] X-Id:[7]]"`},
		"response":      {resp, "v.status=418 v.url=https://svc:xxxxx@api.example/x v.header=map[Set-Cookie:[***]]"},
		"bare response": {&http.Response{StatusCode: http.StatusNoContent}, "v.status=204 v.header=map[]"},
	} {
		out := redactedLog(t, func(l *slog.Logger) { l.Info(logMessage, slog.Any(logKey, tc.value)) })
		if !strings.Contains(out, tc.want) || strings.Contains(out, leaked) {
			t.Errorf("%s: log = %s, want %q in it and no secret", name, out, tc.want)
		}
	}
	nilValues := redactedLog(t, func(l *slog.Logger) {
		l.Info(logMessage, slog.Any("a", (*url.URL)(nil)), slog.Any("b", (*http.Request)(nil)),
			slog.Any("c", (*http.Response)(nil)), slog.Any("d", (*http.Header)(nil)))
	})
	if !strings.Contains(nilValues, `a="" b=<nil> c=<nil> d=<nil>`) {
		t.Errorf("nil values: log = %s, want each as the handler renders nil", nilValues)
	}
	if req.Header.Get(headerAuthorization) != "Bearer "+leaked || header.Get(headerAuthorization) != "Bearer "+leaked {
		t.Fatal("logging masked the caller's headers, want copies masked")
	}
}

// TestNewRedactorLocations logs a URL with credentials in its fragment and a
// redirect whose URL-valued headers carry them: each renders without them.
func TestNewRedactorLocations(t *testing.T) {
	fragmentURL, err := url.Parse("https://app.example/cb?state=s#access_token=" + leaked + "&id_token=" + leaked +
		"&token_type=Bearer")
	if err != nil {
		t.Fatalf("Parse(fragment URL) = %v, want nil", err)
	}
	redirect := &http.Response{StatusCode: http.StatusFound, Header: http.Header{
		"Location":         {"https://app.example/cb?code=" + leaked + "&state=s", "http://bad host/?code=" + leaked},
		"Content-Location": {"/x#access_token=" + leaked}, "Referer": {"https://r.example/?password=" + leaked},
		headerID: {"?code=7"},
	}}
	for name, tc := range map[string]struct {
		log  func(*slog.Logger)
		want string
	}{
		"url fragment": {func(l *slog.Logger) { l.Info(logMessage, slog.Any(logKey, fragmentURL)) },
			`v="https://app.example/cb?state=s#access_token=***&id_token=***&token_type=Bearer"`},
		"redirect": {func(l *slog.Logger) { l.Info(logMessage, slog.Any(logKey, redirect)) },
			`v.header="map[Content-Location:[/x#access_token=***] ` +
				`Location:[https://app.example/cb?code=***&state=s ***] Referer:[https://r.example/?password=***] ` +
				`X-Id:[?code=7]]"`},
	} {
		if out := redactedLog(t, tc.log); !strings.Contains(out, tc.want) {
			t.Errorf("%s: log = %s, want %q in it", name, out, tc.want)
		}
	}
	if !strings.Contains(redirect.Header.Get("Location"), leaked) {
		t.Fatal("logging masked the caller's Location, want a copy masked")
	}
}

// recordCapture is a slog.Handler that keeps the last record it handles.
type recordCapture struct {
	record slog.Record
	mu     sync.Mutex
}

func (*recordCapture) Enabled(context.Context, slog.Level) bool { return true }

// Handle keeps r.
//
//nolint:gocritic // hugeParam: slog.Handler requires the Record by value.
func (c *recordCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.record = r
	c.mu.Unlock()
	return nil
}

func (c *recordCapture) WithAttrs([]slog.Attr) slog.Handler { return c }

func (c *recordCapture) WithGroup(string) slog.Handler { return c }

// TestNewRedactorRecord passes a record through: its time, level, message and
// program counter reach the inner handler unchanged.
func TestNewRedactorRecord(t *testing.T) {
	var pcs [1]uintptr
	runtime.Callers(1, pcs[:])
	at := time.Unix(testUnix, 1).UTC()
	record := slog.NewRecord(at, slog.LevelError, "boom", pcs[0])
	var capture recordCapture
	if err := NewRedactor(&capture).Handle(t.Context(), record); err != nil {
		t.Fatalf("Handle = %v, want nil", err)
	}
	got := capture.record
	if !got.Time.Equal(at) || got.Level != slog.LevelError || got.Message != "boom" || got.PC != pcs[0] {
		t.Fatalf("record = %v %v %q %x, want %v %v %q %x", got.Time, got.Level, got.Message, got.PC, at,
			slog.LevelError, "boom", pcs[0])
	}
}

func TestNewRedactorKeepsOtherValues(t *testing.T) {
	h := http.Header{headerAuthorization: {leaked}, headerID: {"7"}}
	out := redactedLog(t, func(l *slog.Logger) {
		l.Info(logMessage, slog.Any("h", h), slog.Any(logRequest, headerValuer{}), slog.String("user", "u1"),
			slog.Any("ids", []int{7, 8}))
	})
	for _, want := range []string{"X-Id:[7]", "req.path=/x", "user=u1", "ids=\"[7 8]\""} {
		if !strings.Contains(out, want) {
			t.Errorf("log = %s, want %q in it", out, want)
		}
	}
	if h.Get(headerAuthorization) != leaked {
		t.Fatalf("header after logging = %v, want the caller's value kept", h)
	}
}

func TestNewRedactorWithoutKeys(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewRedactor(slog.NewTextHandler(&buf, nil)))
	log.Info(logMessage, slog.String("cookie", leaked), slog.String("x_custom", "kept"))
	if out := buf.String(); strings.Contains(out, leaked) || !strings.Contains(out, "cookie="+redactedValue) ||
		!strings.Contains(out, "x_custom=kept") {
		t.Fatalf("log = %s, want SensitiveHeaders masked and other values kept", out)
	}
	h := NewRedactor(slog.NewJSONHandler(new(bytes.Buffer), &slog.HandlerOptions{Level: slog.LevelWarn}), "x")
	enabled := []bool{h.Enabled(context.Background(), slog.LevelInfo), h.Enabled(context.Background(), slog.LevelError)}
	if !slices.Equal(enabled, []bool{false, true}) {
		t.Fatalf("Enabled(info, error) = %v, want the inner handler's [false true]", enabled)
	}
}

func TestRedactHeader(t *testing.T) {
	tenant := strings.ToLower("X-Tenant")
	auth := []string{"a", "b"}
	h := http.Header{headerAuthorization: auth, headerCookie: {"c"}, "X-Trace": {"ok"}, tenant: {"t"}}
	RedactHeader(h)
	if !slices.Equal(h[headerAuthorization], []string{redactedValue, redactedValue}) ||
		h.Get(headerCookie) != redactedValue || h.Get("X-Trace") != "ok" || !slices.Equal(h[tenant], []string{"t"}) {
		t.Fatalf("RedactHeader = %v, want SensitiveHeaders masked and others kept", h)
	}
	if !slices.Equal(auth, []string{redactedValue, redactedValue}) {
		t.Fatalf("RedactHeader left the Authorization values %q, want them masked in place", auth)
	}
	RedactHeader(h, "X-TENANT")
	if !slices.Equal(h[tenant], []string{redactedValue}) {
		t.Fatalf("RedactHeader(X-TENANT) = %v, want the tenant masked", h)
	}
	if RedactHeader(nil) != nil {
		t.Fatal("RedactHeader(nil) = non-nil, want nil")
	}
}

// TestRedactHeaderAllocs pins that masking two headers in place allocates
// nothing, whether the caller names them or not.
func TestRedactHeaderAllocs(t *testing.T) {
	auth, cookie, trace := []string{"a"}, []string{"c"}, []string{"kept"}
	h := http.Header{}
	for _, keys := range [][]string{nil, {headerAuthorization, headerCookie}} {
		assertAllocs(t, 0, func() {
			h[headerAuthorization], h[headerCookie], h["X-Trace"] = auth, cookie, trace
			RedactHeader(h, keys...)
		})
		if h.Get(headerAuthorization) != redactedValue || h.Get(headerCookie) != redactedValue ||
			h.Get("X-Trace") != "kept" {
			t.Fatalf("RedactHeader(%q) = %v, want Authorization and Cookie masked, X-Trace kept", keys, h)
		}
	}
}

func BenchmarkRedactHeader(b *testing.B) {
	h := http.Header{headerAuthorization: {"Bearer t"}, headerCookie: {"c"}, "Accept": {"*/*"}}
	if got := RedactHeader(h); got.Get(headerAuthorization) != redactedValue || got.Get("Accept") != "*/*" {
		b.Fatalf("RedactHeader = %v, want Authorization masked and Accept kept", got)
	}
	b.ReportAllocs()
	for b.Loop() {
		RedactHeader(h)
	}
}

// Allocations of the redacted copies: a header of two names, the query of a
// URL, and a request or a response with its URL and header.
const (
	maskedHeaderAllocs  = 3
	maskedQueryAllocs   = 3
	maskedMessageAllocs = 6
)

// TestNewRedactorHandleAllocs passes records to a handler that discards them:
// plain attributes cost nothing, the others their masked copy or rendering.
func TestNewRedactorHandleAllocs(t *testing.T) {
	h := NewRedactor(slog.DiscardHandler, SensitiveHeaders()...)
	link, err := url.Parse("https://api.example/cb?code=" + leaked + "&state=s")
	if err != nil {
		t.Fatalf("Parse(callback URL) = %v, want nil", err)
	}
	upper, err := url.Parse("https://api.example/cb?Code=" + leaked + "&State=s")
	if err != nil {
		t.Fatalf("Parse(upper-case callback URL) = %v, want nil", err)
	}
	for _, tc := range []struct {
		attr   slog.Attr
		allocs float64
	}{
		{slog.String(headerAuthorization, "Bearer t"), 0},
		{slog.String("method", "GET"), 0},
		{slog.Any("header", http.Header{headerAuthorization: {"Bearer t"}, headerID: {"7"}}), maskedHeaderAllocs},
		{slog.Any("url", link), 2},
		{slog.Any("upper_url", upper), 2},
		{slog.Any("query", link.Query()), maskedQueryAllocs},
		{slog.Any("request", &http.Request{Method: http.MethodGet, URL: link, Header: http.Header{headerID: {"7"}}}),
			maskedMessageAllocs},
		{slog.Any("response", &http.Response{StatusCode: http.StatusFound, Header: http.Header{headerID: {"7"}},
			Request: &http.Request{URL: link}}), maskedMessageAllocs},
	} {
		record := slog.NewRecord(time.Time{}, slog.LevelInfo, logRequest, 0)
		record.AddAttrs(tc.attr)
		t.Run(tc.attr.Key, func(t *testing.T) {
			assertAllocs(t, tc.allocs, func() {
				if err := h.Handle(t.Context(), record); err != nil {
					t.Fatalf("Handle = %v, want nil", err)
				}
			})
		})
	}
}

func TestSensitiveHeaders(t *testing.T) {
	want := []string{headerAuthorization, "Proxy-Authorization", headerCookie, "Set-Cookie", "X-Api-Key",
		"X-Auth-Token"}
	s := SensitiveHeaders()
	if !slices.Equal(s, want) {
		t.Fatalf("SensitiveHeaders() = %q, want %q", s, want)
	}
	s[0] = "changed"
	if got := SensitiveHeaders()[0]; got != headerAuthorization {
		t.Fatalf("SensitiveHeaders()[0] = %q after caller write, want %q", got, headerAuthorization)
	}
}

func TestRedactorWithGroup(t *testing.T) {
	var buf bytes.Buffer
	h := NewRedactor(slog.NewTextHandler(&buf, nil))
	if got := h.WithGroup(""); got != h {
		t.Fatalf("WithGroup(\"\") = %v, want the receiver %v", got, h)
	}
	slog.New(h.WithGroup("g")).Info(logMessage, slog.String("cookie", leaked), slog.String("k", logKey))
	if out := buf.String(); !strings.Contains(out, "g.cookie="+redactedValue) || !strings.Contains(out, "g.k=v") {
		t.Fatalf("log = %s, want the group g with the cookie masked", out)
	}
}

func ExampleNewRedactor() {
	noTime := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	logger := slog.New(NewRedactor(slog.NewTextHandler(os.Stdout, noTime)))
	logger.Info("request", slog.String("authorization", "Bearer secret"), slog.String("path", "/api"))
	// Output: level=INFO msg=request authorization=*** path=/api
}

func ExampleRedactHeader() {
	h := http.Header{headerAuthorization: {"Bearer secret"}, "Accept": {"*/*"}}
	fmt.Println(RedactHeader(h))
	// Output: map[Accept:[*/*] Authorization:[***]]
}

func BenchmarkNewRedactor(b *testing.B) {
	var out bytes.Buffer
	log := slog.New(NewRedactor(slog.NewTextHandler(&out, nil), SensitiveHeaders()...))
	record := func() {
		out.Reset()
		log.LogAttrs(b.Context(), slog.LevelInfo, logRequest, slog.String("method", "GET"),
			slog.String(headerAuthorization, "Bearer secret"))
	}
	record()
	if got := out.String(); !strings.HasSuffix(got, " method=GET Authorization=***\n") {
		b.Fatalf("record = %q, want the method and a masked Authorization", got)
	}
	b.ReportAllocs()
	for b.Loop() {
		record()
	}
}
