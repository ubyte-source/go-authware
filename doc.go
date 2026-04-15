// Package authware provides pluggable HTTP authentication for Go servers.
//
// Designed for high-throughput production services where authentication must
// be both correct and fast. Supports four modes out of the box:
//
//   - None — pass-through, no authentication
//   - Bearer — static token comparison (constant-time)
//   - API Key — header or Authorization scheme comparison
//   - OAuth / JWT — full JWT validation with JWKS auto-discovery
//
// All static comparisons use crypto/subtle.ConstantTimeCompare.
// JWT validation uses zero-allocation unsafe string→[]byte views for
// token parsing and single-pass claims extraction via go-jsonfast.
//
// The OAuth mode implements:
//   - JWT signature verification (HMAC-SHA256/384/512, RSA, RSA-PSS, ECDSA)
//   - OIDC auto-discovery from any OpenID Connect provider
//   - Automatic JWKS key rotation with cache TTL
//   - Stampede prevention via serialized refresh with double-check
//   - RFC 9728 Protected Resource Metadata
//   - RFC 8414 AS Metadata via OAuth proxy
//   - RFC 7591 Dynamic Client Registration shim
//   - Scope validation (scope and scp claims)
//   - Clock skew tolerance for nbf/iat claims
//
// # OIDC Auto-Discovery
//
// When OAuthJWKSURL is not configured, the library automatically discovers
// the JWKS endpoint by fetching {issuer}/.well-known/openid-configuration.
// This works with any OIDC-compliant provider: Google, Auth0, Keycloak,
// Azure AD, Okta, and others.
//
// # Middleware
//
// The package provides standard HTTP middleware for common auth patterns:
//
//	auth, _ := authware.New(cfg, nil)
//	mux := http.NewServeMux()
//	mux.Handle("/api/", authware.Middleware(auth)(apiHandler))
//	mux.Handle("/admin/", authware.Middleware(auth)(
//	    authware.RequireScopes("admin")(adminHandler),
//	))
//
// The authenticated identity is stored in the request context and can be
// retrieved via IdentityFromContext. WithIdentity injects an identity
// manually, which is useful in tests and custom middleware:
//
//	id, ok := authware.IdentityFromContext(r.Context())
//	ctx := authware.WithIdentity(r.Context(), id)
//
// # Nginx auth_request
//
// AuthCheckHandler returns an http.Handler compatible with nginx's
// auth_request module. On success it sets X-Auth-Subject, X-Auth-Method,
// and X-Auth-Scopes response headers for the upstream:
//
//	mux.Handle("/check", authware.AuthCheckHandler(auth))
//
// # Environment Configuration
//
// ConfigFromEnv reads AUTH_* environment variables to build a Config,
// making it easy to configure the provider without code changes:
//
//	cfg := authware.ConfigFromEnv()
//	auth, err := authware.New(cfg, nil)
//
// # Direct Usage
//
//	auth, err := authware.New(cfg, nil)
//	id, err := auth.Authenticate(r)
//
// # OAuth Proxy
//
// OAuthProxy bridges MCP clients (e.g. Claude Desktop) with upstream IdPs
// that don't support RFC 7591 Dynamic Client Registration. It provides
// four handlers: ASMetadataHandler, AuthorizeHandler, RegisterHandler,
// and TokenHandler.
// All proxy JSON serialization uses go-jsonfast Builder with pooled buffers.
//
// For confidential-client token exchange (e.g. Azure AD), set
// OAuthClientSecret in addition to OAuthClientID. The TokenHandler
// automatically injects client_id and client_secret into the upstream
// token request, bridging MCP public-client flows with IdPs that require
// a client secret.
//
//	proxy := authware.NewOAuthProxy(cfg, slog.Default())
//	mux.HandleFunc("GET /.well-known/oauth-authorization-server", proxy.ASMetadataHandler())
//	mux.HandleFunc("GET /authorize", proxy.AuthorizeHandler())
//	mux.HandleFunc("POST /register", proxy.RegisterHandler())
//	mux.HandleFunc("POST /token", proxy.TokenHandler())
//
// # Dependencies
//
// This library depends only on go-jsonfast
// (https://github.com/ubyte-source/go-jsonfast) for zero-allocation JWT
// claims parsing and proxy JSON serialization. No other external modules
// are required.
package authware
