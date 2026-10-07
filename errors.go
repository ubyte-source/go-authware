package authware

import (
	"cmp"
	"errors"
	"net/http"
	"strings"
)

// errPrefix starts the text of every error the package returns and of every log
// message it writes.
const errPrefix = "authware: "

var (
	// ErrInvalidConfig reports an invalid configuration; New joins one per
	// problem.
	ErrInvalidConfig = errors.New(errPrefix + "invalid config")
	// ErrMissingCredentials reports a request that carries no credentials.
	ErrMissingCredentials = errors.New(errPrefix + "missing credentials")
	// ErrInvalidCredentials reports credentials that fail verification.
	ErrInvalidCredentials = errors.New(errPrefix + "invalid credentials")
	// ErrTokenExpired reports a token past its expiry.
	ErrTokenExpired = errors.New(errPrefix + "token expired")
	// ErrInsufficientScope reports an identity lacking a required scope.
	ErrInsufficientScope = errors.New(errPrefix + "insufficient scope")
	// ErrKeysUnavailable reports that verification keys cannot be obtained.
	ErrKeysUnavailable = errors.New(errPrefix + "verification keys unavailable")
	// ErrInsecureURL reports a URL refused by the outbound URL policy of
	// CheckOutboundURL, which New and every fetch of a Gate apply.
	ErrInsecureURL = errors.New("insecure URL")

	// errBodyTooLarge reports a request or answer body over its limit.
	errBodyTooLarge = errors.New("body too large")
)

const (
	codeInvalidToken      = "invalid_token"
	codeInsufficientScope = "insufficient_scope"
)

// authError is an authentication or authorization failure: msg is a fixed
// client-safe description, cause is reachable only through Unwrap, and rendered,
// when set, is the WWW-Authenticate value rendered once for the gate it answers.
type authError struct {
	class    error
	msg      string
	cause    error
	status   int
	code     string
	scope    string
	rendered string
}

// failure builds the authError of kind with its status and challenge code;
// msg is the client-visible description, read without a cause or in a
// challenge.
func failure(kind error, msg string, cause error) *authError {
	e := &authError{class: kind, msg: msg, cause: cause, status: http.StatusUnauthorized, code: codeInvalidToken}
	switch {
	case errors.Is(kind, ErrMissingCredentials):
		e.code = ""
	case errors.Is(kind, ErrInsufficientScope):
		e.status, e.code = http.StatusForbidden, ""
	case errors.Is(kind, ErrKeysUnavailable):
		e.status, e.code = http.StatusServiceUnavailable, ""
	}
	return e
}

// insufficientScope reports that the identity lacks scopes, which the
// challenge names.
func insufficientScope(scopes []string) *authError {
	e := failure(ErrInsufficientScope, "missing required scope", nil)
	e.code, e.scope = codeInsufficientScope, strings.Join(scopes, " ")
	return e
}

// Error returns the class, then the cause or, without one, the message.
func (e *authError) Error() string {
	kind := e.class.Error()
	switch {
	case e.cause != nil:
		return kind + ": " + e.cause.Error()
	case e.msg == "":
		return kind
	}
	return kind + ": " + e.msg
}

// Is matches the sentinel naming the failure class.
func (e *authError) Is(target error) bool { return target == e.class }

// Unwrap returns the underlying cause.
func (e *authError) Unwrap() error { return e.cause }

// description is the client-safe text of the challenge: the message, else
// the class without its prefix.
func (e *authError) description() string {
	return cmp.Or(e.msg, strings.TrimPrefix(e.class.Error(), errPrefix))
}

// challenged reports whether a Bearer challenge answers e: every 401, and a
// 403 for insufficient scope.
func (e *authError) challenged() bool {
	return e.status == http.StatusUnauthorized || e.code == codeInsufficientScope
}

// authFailure returns e to a caller that holds it as an error.
func (e *authError) authFailure() *authError { return e }

// tokenError is a token validation failure whose text is safe to show the
// client.
type tokenError string

// Error returns the client-safe text.
func (e tokenError) Error() string { return string(e) }
