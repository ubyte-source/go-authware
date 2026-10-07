package authware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
	"github.com/ubyte-source/go-authware/v2/internal/reply"
	"github.com/ubyte-source/go-authware/v2/internal/retry"
)

const (
	schemeBearer = "Bearer"
	schemeAPIKey = "ApiKey"
)

// maxChallengeParams counts the auth-params a Bearer challenge may carry:
// realm, error, error_description, scope and resource_metadata.
const maxChallengeParams = 5

// writeChallenge answers a failed request with the challenge of scheme, or the
// one e holds, and a fixed body naming only the status; a 503 asks for a retry
// after the backoff. A 401 without a challenge names no scheme, so it is a 403.
func writeChallenge(w http.ResponseWriter, scheme, realm string, e *authError, metadataURL string) {
	status, name, value := e.status, reply.Challenge, e.rendered
	if value == "" {
		value = challengeHeader(scheme, realm, e, metadataURL)
	}
	switch {
	case value != "":
	case status == http.StatusServiceUnavailable:
		name, value = reply.RetryAfter, retryAfter()
	case status == http.StatusUnauthorized:
		status = http.StatusForbidden
	}
	reply.Error(w, status, name, value)
}

// retryAfter returns the Retry-After of a 503 refusal, which carries no challenge:
// the seconds of the pause that follows a failed fetch.
func retryAfter() string { return strconv.Itoa(int(retry.After / time.Second)) }

// challengeHeader renders WWW-Authenticate: every 401 of a challenge
// scheme, and a Bearer 403 for insufficient scope.
func challengeHeader(scheme, realm string, e *authError, metadataURL string) string {
	switch {
	case scheme == schemeAPIKey && e.status == http.StatusUnauthorized:
		return challenge(schemeAPIKey, [2]string{"realm", realm})
	case scheme != schemeBearer || !e.challenged():
		return ""
	}
	params := append(make([][2]string, 0, maxChallengeParams), [2]string{"realm", realm})
	if e.code != "" {
		params = append(params, [2]string{oauthwire.ParamError, e.code},
			[2]string{oauthwire.ParamErrorDescription, e.description()})
	}
	if e.scope != "" {
		params = append(params, [2]string{oauthwire.ParamScope, e.scope})
	}
	if metadataURL != "" {
		params = append(params, [2]string{"resource_metadata", metadataURL})
	}
	return challenge(schemeBearer, params...)
}

// challenge renders scheme followed by its auth-params, name/value pairs as
// comma-separated name="value".
func challenge(scheme string, pairs ...[2]string) string {
	size := len(scheme)
	for _, pair := range pairs {
		size += len(", ") + len(pair[0]) + len(`=""`) + len(pair[1])
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString(scheme)
	for i, pair := range pairs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte(' ')
		b.WriteString(pair[0])
		b.WriteString(`="`)
		writeQuoted(&b, pair[1])
		b.WriteByte('"')
	}
	return b.String()
}

// writeQuoted writes v with its control bytes blanked and its quotes and
// backslashes escaped, so the value stays inside one quoted-string.
func writeQuoted(b *strings.Builder, v string) {
	v = sanitizeHeaderValue(v)
	for i := range len(v) {
		if c := v[i]; c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
}
