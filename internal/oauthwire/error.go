package oauthwire

import (
	"errors"
	"strings"
	"unicode"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
)

// maxErrorExcerpt bounds in bytes each text kept from an answer that is not 2xx.
const maxErrorExcerpt = 256

// errNotOAuth refuses a body that is not a strict OAuth error object.
var errNotOAuth = errors.New("not an OAuth error object")

// The members of an OAuth error object.
const (
	ParamError            = "error"
	ParamErrorDescription = "error_description"
)

// CodeTemporarilyUnavailable is the error code of a server that cannot
// answer the request now.
const CodeTemporarilyUnavailable = "temporarily_unavailable"

// errorMembers returns the code and the description of body, an answer that
// is not 2xx, each kept as its excerpt; a body that is not a strict OAuth error
// object with a code has no code and becomes the description.
func errorMembers(body []byte) (code, description string) {
	text := string(body)
	err := jsonobj.Iterate(text, errNotOAuth, func(name, value string) error {
		switch name {
		case ParamError:
			return jsonobj.CopyString(&code, name, value, errNotOAuth)
		case ParamErrorDescription:
			return jsonobj.CopyString(&description, name, value, errNotOAuth)
		}
		return nil
	})
	if code = excerpt(code); err == nil && code != "" {
		return code, excerpt(description)
	}
	return "", excerpt(text)
}

// excerpt copies s cut to maxErrorExcerpt bytes past its leading space, drops
// invalid UTF-8, a rune split by the cut included, and trims the result, so
// an error never keeps the body it quotes.
func excerpt(s string) string {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	return strings.Clone(strings.TrimSpace(strings.ToValidUTF8(s[:min(len(s), maxErrorExcerpt)], "")))
}
