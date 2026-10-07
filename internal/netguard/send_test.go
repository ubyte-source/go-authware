package netguard

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// roundTrip adapts a function to http.RoundTripper.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errSend is the failure of the transport that refusing returns.
var errSend = errors.New("test: send failed")

// refusing returns a client whose transport fails every request with errSend.
func refusing() *http.Client {
	return &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return nil, errSend })}
}

// answering returns a client whose transport answers status and body.
func answering(status int, rc io.ReadCloser) *http.Client {
	return &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: rc}, nil
	})}
}

// TestExchange hands read the response with its body open, then closes it
// once and returns what read made.
func TestExchange(t *testing.T) {
	t.Parallel()
	rc := &trackedBody{Reader: strings.NewReader(atLimit)}
	read := func(resp *http.Response) (string, error) {
		if resp.StatusCode != http.StatusAccepted || resp.Body != rc || rc.closes != 0 {
			t.Errorf("read got %+v after %d closes, want the 202 with its body open", resp, rc.closes)
		}
		return atLimit, nil
	}
	if got, err := Exchange(answering(http.StatusAccepted, rc), outbound(t, nil), read); err != nil || got != atLimit ||
		rc.closes != 1 {
		t.Fatalf("Exchange = %q, %v after %d closes, want 12345 and 1 close", got, err, rc.closes)
	}
}

// TestExchangeFailures returns the zero value with the failure of the read,
// of the close, or of both joined.
func TestExchangeFailures(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		readErr, closeErr error
		want              []error
	}{
		"read":  {errRead, nil, []error{errRead}},
		"close": {nil, errClose, []error{errClose}},
		"both":  {errRead, errClose, []error{errRead, errClose}},
	} {
		rc := &trackedBody{Reader: strings.NewReader(atLimit), err: tc.closeErr}
		got, err := Exchange(answering(http.StatusOK, rc), outbound(t, nil), func(*http.Response) (string, error) {
			return atLimit, tc.readErr
		})
		if got != "" || rc.closes != 1 || err == nil {
			t.Fatalf("%s: Exchange = %q, %v after %d closes, want the zero value, a failure and 1 close", name, got,
				err, rc.closes)
		}
		for _, want := range tc.want {
			if !errors.Is(err, want) {
				t.Errorf("%s: Exchange = %v, want it to wrap %v", name, err, want)
			}
		}
	}
}

// TestExchangeTransportFailure wraps a transport failure as a failed send
// without calling read.
func TestExchangeTransportFailure(t *testing.T) {
	t.Parallel()
	got, err := Exchange(refusing(), outbound(t, nil), func(*http.Response) (string, error) {
		t.Error("read called after a failed send, want no read")
		return atLimit, nil
	})
	var uerr *url.Error
	if got != "" || err == nil || !errors.Is(err, errSend) || !errors.As(err, &uerr) ||
		!strings.HasPrefix(err.Error(), "send request: ") {
		t.Fatalf("Exchange = %q, %v; want errSend behind send request", got, err)
	}
}
