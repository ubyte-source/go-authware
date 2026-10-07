package authware

import (
	"errors"
	"net/http"

	"github.com/ubyte-source/go-jsonfast"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

var (
	errClientMetadata = errors.New("invalid client metadata")
	errClientShape    = jsonobj.Refusal(errClientMetadata)
	errRedirectURIs   = errors.New("invalid redirect_uris")
)

// descInvalidRedirectURIs tells the client which redirect_uris are accepted.
const descInvalidRedirectURIs = "redirect_uris must be a non-empty array of https or loopback http URLs"

// serveRegister answers a dynamic registration with the pinned client ID of
// a public client, echoing the validated redirect URIs.
func (f *facade) serveRegister(w http.ResponseWriter, r *http.Request) {
	body, err := netguard.ReadRequest(r, maxFacadeBodyBytes, errBodyTooLarge)
	if err != nil {
		badRequest(codeInvalidClientMetadata, descUnreadableBody).write(w)
		return
	}
	uris, err := redirectURIs(body)
	switch {
	case errors.Is(err, errRedirectURIs):
		badRequest(codeInvalidRedirectURI, descInvalidRedirectURIs).write(w)
		return
	case err != nil:
		badRequest(codeInvalidClientMetadata, "client metadata must be a JSON object").write(w)
		return
	}
	b := jsonfast.Acquire()
	defer jsonfast.Release(b)
	b.BeginObject()
	b.AddStringField(oauthwire.ParamClientID, f.params.clientID)
	b.AddStringField("token_endpoint_auth_method", authMethodNone)
	b.AddStringArrayField("grant_types", []string{grantAuthorizationCode, oauthwire.GrantRefreshToken})
	b.AddStringArrayField("response_types", []string{responseTypeCode})
	b.AddStringArrayField("redirect_uris", uris)
	b.EndObject()
	oauthwire.WriteJSON(w, http.StatusCreated, b.Bytes())
}

// redirectURIs returns the redirect_uris of the client metadata in body, a
// UTF-8 JSON object.
func redirectURIs(body []byte) ([]string, error) {
	var uris []string
	err := jsonobj.Iterate(string(body), errClientShape, func(name, value string) error {
		if name != "redirect_uris" {
			return nil
		}
		collect := func(uri string) error {
			if !validRedirectURI(uri) {
				return errRedirectURIs
			}
			uris = append(uris, uri)
			return nil
		}
		if jsonfast.IterateStringArray(value, collect) != nil {
			return errRedirectURIs
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(uris) == 0 {
		return nil, errRedirectURIs
	}
	return uris, nil
}
