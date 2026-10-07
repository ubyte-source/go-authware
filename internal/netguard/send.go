package netguard

import (
	"fmt"
	"net/http"
)

// Exchange sends req, built from a URL Check accepted, through client, returns
// what read makes of the response and closes its body; a failed send fails it,
// and so do a failed read and close, joined, with the zero T.
func Exchange[T any](client *http.Client, req *http.Request, read func(*http.Response) (T, error)) (T, error) {
	var zero T
	resp, err := client.Do(req) //nolint:gosec // callers build req from a policy-checked URL
	if err != nil {
		return zero, fmt.Errorf("send request: %w", err)
	}
	v, readErr := read(resp)
	if err := joinClose(readErr, resp.Body.Close()); err != nil {
		return zero, err
	}
	return v, nil
}
