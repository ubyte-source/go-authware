package cred

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
	"github.com/ubyte-source/go-authware/v2/secret"
)

// basicTokenType is the scheme of HTTP Basic credentials.
const basicTokenType = "Basic"

// Basic returns the Token that sends user and password as HTTP Basic
// credentials. user must be a clean header value without a colon; password
// may be empty. The error wraps ErrInvalidConfig.
func Basic(user string, password secret.Value) (*Token, error) {
	if !syntax.IsFieldValue(user) || strings.Contains(user, ":") {
		return nil, fmt.Errorf("%w: basic user must be a header value without a colon", ErrInvalidConfig)
	}
	raw := base64.StdEncoding.EncodeToString([]byte(user + ":" + password.Reveal()))
	return &Token{Value: secret.New(raw), Type: basicTokenType}, nil
}
