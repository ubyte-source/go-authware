package oauthwire

import (
	"errors"
	"io"
	"net/http"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

// maxErrorBody bounds in bytes what Fetch reads of an answer that is not 2xx.
const maxErrorBody = 4 << 10

// Fetch sends req and returns the body of a 2xx answer, failing with tooLarge past
// limit bytes; another status fails with the error, never nil, that refused makes of it
// and the OAuth error in its first 4 KiB; a failed send, read or close fails it too.
func Fetch(client *http.Client, req *http.Request, limit int64, tooLarge error,
	refused func(status int, code, description string) error,
) (string, error) {
	return netguard.Exchange(client, req, func(resp *http.Response) (string, error) {
		return readAnswer(resp, limit, tooLarge, refused)
	})
}

// readAnswer returns the body of resp when it is 2xx, failing with tooLarge past
// limit bytes, and otherwise refused of its status and the OAuth error in its
// first 4 KiB, with a failed read joined; the body stays open.
func readAnswer(resp *http.Response, limit int64, tooLarge error,
	refused func(status int, code, description string) error,
) (string, error) {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		head, err := readHead(resp.Body)
		code, description := errorMembers(head)
		return "", errors.Join(refused(resp.StatusCode, code, description), err)
	}
	body, err := netguard.ReadSized(resp.Body, resp.ContentLength, limit, tooLarge)
	return string(body), err
}

// readHead returns the first maxErrorBody bytes of r, or those before a failed
// read, which it wraps.
func readHead(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxErrorBody))
	if err != nil {
		return data, netguard.ReadFailure(err)
	}
	return data, nil
}
