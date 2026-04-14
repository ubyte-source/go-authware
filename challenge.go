package authware

import (
	"errors"
	"net/http"
	"strings"
)

func unauthorizedError(message string) error {
	return &authError{status: http.StatusUnauthorized, code: "invalid_token", message: message, scheme: "Bearer"}
}

func insufficientScopeError(scope []string) error {
	return &authError{
		status:  http.StatusForbidden,
		code:    "insufficient_scope",
		message: "missing required scope",
		scheme:  "Bearer",
		scope:   strings.Join(scope, " "),
	}
}

func challengeFromError(realm string, err error, resourceMetadataURL string) (status int, header, message string) {
	status = http.StatusUnauthorized
	message = "unauthorized"

	var ae *authError
	if errors.As(err, &ae) {
		status = ae.status
		message = ae.message

		if ae.scheme == "Bearer" {
			return status, bearerChallenge(realm, ae, resourceMetadataURL), message
		}
	}

	return status, "", message
}

func bearerChallenge(realm string, ae *authError, resourceMetadataURL string) string {
	var b strings.Builder
	b.Grow(128)

	b.WriteString(`Bearer realm="`)
	escapeHeaderValue(&b, realm)
	b.WriteByte('"')

	if resourceMetadataURL != "" {
		b.WriteString(`, resource_metadata="`)
		escapeHeaderValue(&b, resourceMetadataURL)
		b.WriteByte('"')
	}

	if ae.code != "" {
		b.WriteString(`, error="`)
		escapeHeaderValue(&b, ae.code)
		b.WriteByte('"')
	}

	if ae.message != "" {
		b.WriteString(`, error_description="`)
		escapeHeaderValue(&b, ae.message)
		b.WriteByte('"')
	}

	if ae.scope != "" {
		b.WriteString(`, scope="`)
		escapeHeaderValue(&b, ae.scope)
		b.WriteByte('"')
	}

	return b.String()
}

// escapeHeaderValue escapes backslashes, quotes, and control characters
// for safe inclusion in HTTP header values.
func escapeHeaderValue(b *strings.Builder, value string) {
	for i := range len(value) {
		switch value[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			b.WriteByte(value[i])
		}
	}
}
