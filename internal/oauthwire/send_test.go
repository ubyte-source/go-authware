package oauthwire

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// probeHeader marks the header of the answers of the send tests.
const probeHeader = "X-Probe"

// sendAnswer runs Send against a transport answering status, body and a
// probe header.
func sendAnswer(t *testing.T, status int, body *closeBody) (Answer, error) {
	t.Helper()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{probeHeader: {"1"}}, Body: body}, nil
	})}
	return Send(client, NewTokenRequest(t.Context(), tokenURL(), url.Values{}), errTooLarge)
}

// TestSend returns the answer of any status with its header and body, closed.
func TestSend(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusBadGateway} {
		body := &closeBody{Reader: strings.NewReader(testBody)}
		ans, err := sendAnswer(t, status, body)
		if err != nil || ans.Status != status || string(ans.Body) != testBody || ans.Header.Get(probeHeader) != "1" ||
			body.closes != 1 {
			t.Errorf("Send = %+v, %v after %d closes, want status %d, the body and 1 close", ans, err, body.closes,
				status)
		}
	}
}

// TestSendSized reads the body into room made for its Content-Length.
func TestSendSized(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := &closeBody{Reader: strings.NewReader(testBody)}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: bodySize, Body: body}, nil
	})}
	ans, err := Send(client, NewTokenRequest(t.Context(), tokenURL(), url.Values{}), errTooLarge)
	if err != nil || string(ans.Body) != testBody || cap(ans.Body) >= bytes.MinRead {
		t.Fatalf("Send = %q, %v in %d bytes, want %s in a buffer sized from the Content-Length", ans.Body, err,
			cap(ans.Body), testBody)
	}
}

// TestSendRejects fails an answer past the 1 MiB bound, joining a failed close,
// and accepts one at the bound.
func TestSendRejects(t *testing.T) {
	t.Parallel()
	const mib = 1 << 20
	body := &closeBody{Reader: strings.NewReader(strings.Repeat("x", mib+1)), err: errClose}
	ans, err := sendAnswer(t, http.StatusOK, body)
	if ans.Body != nil || ans.Status != 0 || !errors.Is(err, errTooLarge) || !errors.Is(err, errClose) ||
		body.closes != 1 {
		t.Fatalf("Send(1 MiB + 1) = %d bytes, %v after %d closes, want errTooLarge and errClose after 1",
			len(ans.Body), err, body.closes)
	}
	body = &closeBody{Reader: strings.NewReader(strings.Repeat("x", mib))}
	if ans, err := sendAnswer(t, http.StatusOK, body); err != nil || len(ans.Body) != mib {
		t.Fatalf("Send(1 MiB) = %d bytes, %v, want the whole body", len(ans.Body), err)
	}
}

// TestSendTransportFailure returns the failure of the transport.
func TestSendTransportFailure(t *testing.T) {
	t.Parallel()
	refusing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errSend
	})}
	ans, err := Send(refusing, NewTokenRequest(t.Context(), tokenURL(), url.Values{}), errTooLarge)
	if ans.Status != 0 || ans.Body != nil || !errors.Is(err, errSend) {
		t.Fatalf("transport failure: Send = %+v, %v, want errSend", ans, err)
	}
}
