package authware

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckOutboundURL(t *testing.T) {
	for _, raw := range []string{
		testIssuerURL + "/v2.0?x=1", "http://localhost:8080/cb", "http://127.0.0.2/", "http://[::1]/",
	} {
		if u, err := CheckOutboundURL(raw); err != nil || u.String() != raw {
			t.Errorf("CheckOutboundURL(%q) = %v, %v; want it accepted", raw, u, err)
		}
	}
	for _, raw := range []string{
		"http://idp.example", "https://user:s3cret@idp.example", "https://", "%zz", "ftp://localhost",
	} {
		u, err := CheckOutboundURL(raw)
		if u != nil || !errors.Is(err, ErrInsecureURL) || strings.Contains(err.Error(), "s3cret") ||
			!strings.HasPrefix(err.Error(), "authware: insecure URL: ") {
			t.Errorf("CheckOutboundURL(%q) = %v, %v; want authware: ErrInsecureURL without the userinfo", raw, u, err)
		}
	}
}
