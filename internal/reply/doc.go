// Package reply writes the plain-text refusals of the middleware: [Error]
// answers 401, 403 or 503 byte for byte as [net/http.Error] does, with at most
// one more header, such as the challenge ([Challenge]) or the pause before a
// retry ([RetryAfter]), all its header values held in one array. No argument may
// be nil.
package reply
