package oauthwire

import (
	"net/http"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

// Answer is the answer of a token endpoint, its body read and closed.
type Answer struct {
	// Header is the header of the answer as the transport returned it.
	Header http.Header
	// Body is the whole body, at most MaxTokenBody bytes.
	Body []byte
	// Status is the status code, of any class: Send refuses no status.
	Status int
}

// Send sends req, a token request, through client and returns the answer, its
// body read within MaxTokenBody bytes from its ContentLength and closed; it fails
// with tooLarge past that bound, and when the send, the read or the close fails.
func Send(client *http.Client, req *http.Request, tooLarge error) (Answer, error) {
	return netguard.Exchange(client, req, func(resp *http.Response) (Answer, error) {
		body, err := netguard.ReadSized(resp.Body, resp.ContentLength, MaxTokenBody, tooLarge)
		return Answer{Header: resp.Header, Body: body, Status: resp.StatusCode}, err
	})
}
