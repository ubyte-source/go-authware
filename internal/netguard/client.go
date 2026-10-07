package netguard

import (
	"net/http"
	"time"
)

// Client returns a copy of base that refuses every redirect. Its timeout is the smaller
// positive value of base.Timeout and timeout, none when neither is positive; a nil base
// yields a fresh client. base itself is never modified.
func Client(base *http.Client, timeout time.Duration) *http.Client {
	c := &http.Client{}
	if base != nil {
		*c = *base
	}
	switch {
	case c.Timeout <= 0:
		c.Timeout = timeout
	case timeout > 0:
		c.Timeout = min(c.Timeout, timeout)
	}
	c.CheckRedirect = refuseRedirect
	return c
}

// refuseRedirect makes the client return a redirect as the response.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
