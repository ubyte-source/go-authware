// Package authware provides pluggable HTTP authentication for Go servers.
//
// Five mutually exclusive modes are supported: [ModeNone], [ModeBearer],
// [ModeAPIKey], [ModeOAuth] and [ModeMTLS]. Mode selection is explicit
// via [Config.Mode] or inferred from the populated fields.
//
// [Middleware] authenticates the request, stores the [Identity] in the
// request context, and writes a WWW-Authenticate challenge on failure.
// [RequireCapability] composes admission predicates over the stored
// identity; [RequireScopes] is the scope-only specialisation.
//
// [MaxBytes] caps inbound body size, [SecurityHeaders] writes a fixed
// pre-computed set of response headers, [CSRF] is a thin wrapper over
// [net/http.CrossOriginProtection]. [NewRedactor] wraps a slog handler
// to redact sensitive attribute values; [RedactHeader] does the same
// in-place on an [net/http.Header].
//
// JWT validation auto-discovers the JWKS endpoint from the issuer when
// [Config.OAuthJWKSURL] is empty.
//
// [AuthCheckHandler] is an [net/http.Handler] compatible with the nginx
// auth_request module: on success it sets X-Auth-Subject, X-Auth-Method
// and X-Auth-Scopes response headers.
//
// [OAuthProxy] bridges clients that require Dynamic Client Registration
// with upstream IdPs where the application client is pre-registered
// out-of-band. It exposes [OAuthProxy.ASMetadataHandler],
// [OAuthProxy.AuthorizeHandler], [OAuthProxy.RegisterHandler] and
// [OAuthProxy.TokenHandler].
//
// [ConfigFromEnv] builds a [Config] from AUTH_* environment variables.
package authware
