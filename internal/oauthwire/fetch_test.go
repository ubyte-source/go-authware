package oauthwire

import (
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

// answerTransport answers every request with status and body.
type answerTransport struct {
	body   *closeBody
	status int
}

func (a answerTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: a.status, Header: http.Header{}, Body: a.body}, nil
}

// errRead is the failure of a body that breaks while it is read.
var errRead = errors.New("test: read failed")

// refusal is what refuse makes of an answer that is not 2xx.
type refusal struct {
	status      int
	code        string
	description string
}

func (*refusal) Error() string { return "test: refused" }

// refuse is the refused function of the fetch tests.
func refuse(status int, code, description string) error {
	return &refusal{status: status, code: code, description: description}
}

// fetchAnswer runs Fetch against a transport answering status and body.
func fetchAnswer(t *testing.T, status int, body *closeBody, limit int64) (string, error) {
	t.Helper()
	client := &http.Client{Transport: answerTransport{body: body, status: status}}
	return Fetch(client, NewGetRequest(t.Context(), tokenURL()), limit, errTooLarge, refuse)
}

// refusedAs returns the refusal err carries, or the zero refusal.
func refusedAs(err error) refusal {
	var r *refusal
	if errors.As(err, &r) {
		return *r
	}
	return refusal{}
}

// lastSuccess is the last 2xx status.
const lastSuccess = 299

func TestFetch(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, lastSuccess} {
		body := &closeBody{Reader: strings.NewReader(testBody)}
		if got, err := fetchAnswer(t, status, body, bodySize); err != nil || got != testBody || body.closes != 1 {
			t.Errorf("status %d: Fetch = %q, %v after %d closes, want the body after 1", status, got, err, body.closes)
		}
	}
	for _, status := range []int{http.StatusOK - 1, lastSuccess + 1, http.StatusNotFound} {
		body := &closeBody{Reader: strings.NewReader(testBody)}
		got, err := fetchAnswer(t, status, body, bodySize)
		if want := (refusal{status: status, description: testBody}); got != "" || refusedAs(err) != want ||
			body.closes != 1 {
			t.Errorf("status %d: Fetch = %q, %v after %d closes, want %+v after 1", status, got, err, body.closes, want)
		}
	}
	coded := `{"error":"invalid_client","error_description":"unknown client"}`
	_, err := fetchAnswer(t, http.StatusUnauthorized, &closeBody{Reader: strings.NewReader(coded)}, bodySize)
	if want := (refusal{http.StatusUnauthorized, "invalid_client", "unknown client"}); refusedAs(err) != want {
		t.Errorf("coded refusal: Fetch = %v, want %+v", err, want)
	}
}

// TestFetchReadsTheStatusFirst refuses an error answer over any limit by its
// status, reading only its first 4 KiB.
func TestFetchReadsTheStatusFirst(t *testing.T) {
	t.Parallel()
	const errorBodyRead = 4 << 10
	src := strings.NewReader(strings.Repeat("x", 3*errorBodyRead))
	body := &closeBody{Reader: src}
	got, err := fetchAnswer(t, http.StatusServiceUnavailable, body, bodySize)
	if r := refusedAs(err); got != "" || r.status != http.StatusServiceUnavailable || errors.Is(err, errTooLarge) ||
		src.Len() != 2*errorBodyRead || body.closes != 1 {
		t.Fatalf("oversized 503: Fetch = %q, %v with %d bytes unread after %d closes; want its refusal, %d unread, "+
			"1 close", got, err, src.Len(), body.closes, 2*errorBodyRead)
	}
}

// TestFetchRejectsAFailedClose fails a read answer whose body does not close,
// keeping the refusal of an error answer.
func TestFetchRejectsAFailedClose(t *testing.T) {
	t.Parallel()
	body := &closeBody{Reader: strings.NewReader(testBody), err: errClose}
	if got, err := fetchAnswer(t, http.StatusOK, body, bodySize); got != "" || !errors.Is(err, errClose) ||
		body.closes != 1 {
		t.Errorf("success: Fetch = %q, %v after %d closes, want errClose after 1", got, err, body.closes)
	}
	body = &closeBody{Reader: strings.NewReader(testBody), err: errClose}
	if got, err := fetchAnswer(t, http.StatusNotFound, body, bodySize); got != "" || !errors.Is(err, errClose) ||
		refusedAs(err).status != http.StatusNotFound || body.closes != 1 {
		t.Errorf("refusal: Fetch = %q, %v after %d closes, want the refusal and errClose after 1", got, err,
			body.closes)
	}
}

// TestFetchRejectsAFailedRead refuses an error answer by what arrived before its
// body failed, and fails a success answer whose body fails.
func TestFetchRejectsAFailedRead(t *testing.T) {
	t.Parallel()
	failing := &closeBody{Reader: io.MultiReader(strings.NewReader(testBody), iotest.ErrReader(errRead))}
	if _, err := fetchAnswer(t, http.StatusBadGateway, failing, bodySize); !errors.Is(err, errRead) ||
		refusedAs(err) != (refusal{status: http.StatusBadGateway, description: testBody}) || failing.closes != 1 {
		t.Errorf("refusal read failure: Fetch = %v, want the refusal of what arrived and the read failure", err)
	}
	failing = &closeBody{Reader: iotest.ErrReader(errRead)}
	if got, err := fetchAnswer(t, http.StatusOK, failing, bodySize); got != "" || !errors.Is(err, errRead) ||
		failing.closes != 1 {
		t.Errorf("success read failure: Fetch = %q, %v, want the read failure", got, err)
	}
}

// TestFetchRejectsAnOversizedAnswer fails a success answer past the limit.
func TestFetchRejectsAnOversizedAnswer(t *testing.T) {
	t.Parallel()
	body := &closeBody{Reader: strings.NewReader(testBody)}
	if got, err := fetchAnswer(t, http.StatusOK, body, bodySize-1); got != "" || !errors.Is(err, errTooLarge) ||
		body.closes != 1 {
		t.Errorf("oversized Fetch = %q, %v after %d closes, want errTooLarge after 1", got, err, body.closes)
	}
}

// TestFetchDeclaredSize reads a success answer whose Content-Length no memory
// holds whole under the largest limit.
func TestFetchDeclaredSize(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := &closeBody{Reader: strings.NewReader(testBody)}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: math.MaxInt64 - 1, Body: body}, nil
	})}
	got, err := Fetch(client, NewGetRequest(t.Context(), tokenURL()), math.MaxInt64, errTooLarge, refuse)
	if err != nil || got != testBody {
		t.Fatalf("Fetch(Content-Length MaxInt64-1, limit MaxInt64) = %q, %v, want %s", got, err, testBody)
	}
}

// TestFetchRejectsATransportFailure returns the failure of the transport.
func TestFetchRejectsATransportFailure(t *testing.T) {
	t.Parallel()
	refusing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errSend
	})}
	if got, err := Fetch(refusing, NewGetRequest(t.Context(), tokenURL()), bodySize, errTooLarge, refuse); got != "" ||
		!errors.Is(err, errSend) {
		t.Errorf("transport failure: Fetch = %q, %v, want errSend", got, err)
	}
}

// TestReadHead keeps at most the first 4 KiB, or what arrived before a failed
// read, and leaves the body open.
func TestReadHead(t *testing.T) {
	t.Parallel()
	const head = 4 << 10
	short := strings.Repeat("x", head-1)
	for _, tc := range []struct {
		name  string
		body  *closeBody
		want  string
		cause error
	}{
		{"longer", &closeBody{Reader: strings.NewReader(short + "yz")}, short + "y", nil},
		{"exact", &closeBody{Reader: strings.NewReader(short + "y")}, short + "y", nil},
		{"shorter", &closeBody{Reader: strings.NewReader(short)}, short, nil},
		{"read failure", &closeBody{Reader: io.MultiReader(strings.NewReader(testBody), iotest.ErrReader(errRead))},
			testBody, errRead},
	} {
		got, err := readHead(tc.body)
		if string(got) != tc.want || !errors.Is(err, tc.cause) || (err == nil) != (tc.cause == nil) ||
			tc.body.closes != 0 {
			t.Errorf("%s: readHead = %d bytes, %v after %d closes, want %d bytes, %v and the body open", tc.name,
				len(got), err, tc.body.closes, len(tc.want), tc.cause)
		}
	}
	if _, err := readHead(iotest.ErrReader(errRead)); !errors.Is(err, errRead) ||
		err.Error() != "read body: test: read failed" {
		t.Errorf("readHead failure = %v, want the read failure behind read body", err)
	}
}
