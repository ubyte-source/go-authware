package authware

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

var errRefusedAnswer = errors.New("answer refused")

// getDocument GETs the JSON document at raw, which must pass the outbound URL
// policy, through client with oauthwire.Fetch.
func getDocument(ctx context.Context, client *http.Client, raw string, limit int64) (string, error) {
	u, err := netguard.Check(raw, ErrInsecureURL)
	if err != nil {
		return "", err
	}
	req := oauthwire.NewGetRequest(ctx, u)
	req.Header.Set("Accept", oauthwire.JSONContentType)
	return oauthwire.Fetch(client, req, limit, errBodyTooLarge, refusedAnswer)
}

// refusedAnswer reports a document answer that is not 2xx by its status and
// OAuth error code, leaving out the peer's description.
func refusedAnswer(status int, code, _ string) error {
	if code == "" {
		return fmt.Errorf("%w: status %d", errRefusedAnswer, status)
	}
	return fmt.Errorf("%w: status %d error %q", errRefusedAnswer, status, code)
}
