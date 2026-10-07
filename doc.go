// Package authware authenticates HTTP requests for Go servers. A [Gate] built by
// [New] from a [Config], or from the environment through [ConfigFromEnv],
// enforces exactly one explicit [Mode]: [ModeNone] admits everyone, [ModeBearer]
// and [ModeAPIKey] compare a shared secret, [ModeOAuth] verifies JWT access tokens
// from an issuer, and [ModeMTLS] checks the client certificate. The Gate stores
// the caller's [Identity] in the request context, guards handlers with
// [Capability] checks and serves the OAuth metadata and authorization server
// facade, while [SecurityHeaders] and [NewRedactor] harden handlers and keep
// credentials out of logs. Only New builds a usable Gate. A Gate and an Identity
// are safe for concurrent use, and a zero Identity, like a nil one, has no
// subject, mode, scope, certificate or claim. The zero value of each config
// struct holds no setting, and its methods only read it, so it is safe for
// concurrent use while nothing modifies it; New copies its Config, using as it
// is only the logger it names, and a copy of the client that follows no redirect
// and bounds its timeout. Arguments of pointer, interface and function types,
// handlers and contexts included, must not be nil, in the functions the package
// returns too, unless a godoc says what nil means.
package authware
