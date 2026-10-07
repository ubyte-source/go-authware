package authware

import (
	"fmt"
	"net/url"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

// CheckOutboundURL parses raw and returns it when it is an absolute https URL,
// or an http URL to a loopback host, with a host and no userinfo; the error
// wraps ErrInsecureURL and never echoes raw, which may hold credentials.
func CheckOutboundURL(raw string) (*url.URL, error) {
	u, err := netguard.Check(raw, ErrInsecureURL)
	if err != nil {
		return nil, fmt.Errorf("%s%w", errPrefix, err)
	}
	return u, nil
}
