package authware

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

// switchProtocols answers with a bare final 101 on the hijacked connection.
func switchProtocols(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		t.Errorf("Hijack = %v, want the connection", err)
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n")); err != nil {
		t.Errorf("Write = %v, want nil", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

// The document the test handler serves at pathOK, and a limit above its size.
const (
	testDocument = "0123456789"
	documentSize = int64(len(testDocument))
	pathOK       = "/ok"
	maxDocument  = 64
)

// documentHandler serves a ten-byte body at /ok and with status 299 at /299,
// a bare 101 at /101, a redirect at /moved, a longer 503 at /huge and 204
// elsewhere, recording the Accept header into accept.
func documentHandler(t *testing.T, accept *atomic.Value) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		accept.Store(r.Header.Get("Accept"))
		switch r.URL.Path {
		case pathOK:
		case "/299":
			w.WriteHeader(lastSuccess)
		case "/101":
			switchProtocols(t, w)
			return
		case "/moved":
			http.Redirect(w, r, pathOK, http.StatusFound)
			return
		case "/huge":
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := io.WriteString(w, strings.Repeat(" ", maxDocument)); err != nil {
				t.Errorf("WriteString = %v, want nil", err)
			}
			return
		default:
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if _, err := w.Write([]byte(testDocument)); err != nil {
			t.Errorf("Write = %v, want nil", err)
		}
	}
}

func TestGetDocument(t *testing.T) {
	var accept atomic.Value
	srv := httptest.NewServer(documentHandler(t, &accept))
	defer srv.Close()
	client := netguard.Client(srv.Client(), time.Second)
	tests := []struct {
		url   string
		limit int64
		want  error
		body  string
	}{
		{srv.URL + pathOK, documentSize, nil, testDocument},
		{srv.URL + pathOK, documentSize - 1, errBodyTooLarge, ""},
		{srv.URL + "/299", documentSize, nil, testDocument},
		{srv.URL + "/101", documentSize, statusError(http.StatusSwitchingProtocols), ""},
		{srv.URL + "/moved", maxDocument, statusError(http.StatusFound), ""},
		{srv.URL + "/huge", documentSize, statusError(http.StatusServiceUnavailable), ""},
		{srv.URL + "/empty", documentSize, nil, ""},
		{"http://example.com/x", documentSize, ErrInsecureURL, ""},
	}
	for _, tc := range tests {
		body, err := getDocument(t.Context(), client, tc.url, tc.limit)
		if !errorMatches(err, tc.want) || body != tc.body {
			t.Errorf("getDocument(%s, %d) = %q, %v; want %q, %v", tc.url, tc.limit, body, err, tc.body, tc.want)
		}
	}
	if got := accept.Load(); got != "application/json" {
		t.Errorf("Accept = %v, want application/json", got)
	}
	srv.Close()
	var opErr *net.OpError
	if _, err := getDocument(t.Context(), client, srv.URL+pathOK, documentSize); !errors.As(err, &opErr) ||
		opErr.Op != "dial" {
		t.Errorf("getDocument(closed server) = %v, want a dial error", err)
	}
}

// failingBody is a response body whose Close fails with errUpstream.
type failingBody struct {
	io.Reader
}

func (failingBody) Close() error { return errUpstream }

func TestRefusedAnswer(t *testing.T) {
	for _, tc := range []struct {
		code, want string
	}{
		{"", "answer refused: status 404"},
		{"invalid_request", `answer refused: status 404 error "invalid_request"`},
	} {
		err := refusedAnswer(http.StatusNotFound, tc.code, "the peer's text")
		if !errors.Is(err, errRefusedAnswer) || err.Error() != tc.want {
			t.Errorf("refusedAnswer(404, %q) = %v, want %q", tc.code, err, tc.want)
		}
	}
}

func TestGetDocumentBodyErrors(t *testing.T) {
	for name, body := range map[string]io.Reader{
		"close":          strings.NewReader("{}"),
		"read and close": iotest.ErrReader(errNoRoute),
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: failingBody{body}}, nil
		})}
		doc, err := getDocument(t.Context(), client, testJWKSURL, documentSize)
		readFails := name == "read and close"
		if !errors.Is(err, errUpstream) || errors.Is(err, errNoRoute) != readFails || doc != "" {
			t.Errorf("%s: getDocument = %q, %v; want the close failure and the read failure only if any", name, doc,
				err)
		}
	}
}

// TestNewIssuerLogsFailures logs a failed discovery once, under the context
// of its caller, and a discovery that succeeds not at all.
