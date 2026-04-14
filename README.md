# go-authware

> Minimal-dependency HTTP authentication library for Go servers.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![CI](https://github.com/ubyte-source/go-authware/actions/workflows/ci.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ubyte-source/go-authware)](https://goreportcard.com/report/github.com/ubyte-source/go-authware)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubyte-source/go-authware.svg)](https://pkg.go.dev/github.com/ubyte-source/go-authware)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Features

- **Five auth modes**: None, Bearer, API Key, OAuth/JWT, OAuth Proxy
- **OIDC auto-discovery** — works with any OpenID Connect provider
- **Minimal dependencies** — stdlib + [go-jsonfast](https://github.com/ubyte-source/go-jsonfast) for zero-alloc JSON
- **Constant-time comparisons** via `crypto/subtle` on all secret paths
- **JWT/JWKS support**: HMAC-SHA256/384/512, RSA (PKCS1v15 + PSS), ECDSA (P-256/384/521)
- **JWKS auto-refresh** with cache TTL and stampede prevention
- **RFC 9728** Protected Resource Metadata
- **RFC 8414** AS Metadata via OAuth proxy
- **RFC 7591** Dynamic Client Registration shim
- **Zero-alloc hot paths** using `unsafe.Slice` for string→[]byte views
- **go-jsonfast Builder** for zero-alloc JSON serialization in proxy handlers
- **Nginx auth_request** compatible handler
- **Environment variable configuration** via `ConfigFromEnv`
- **PGO-optimized** with `default.pgo` profile

## Install

```bash
go get github.com/ubyte-source/go-authware
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/ubyte-source/go-authware"
)

func main() {
    auth, err := authware.New(&authware.Config{
        Mode:        authware.ModeBearer,
        BearerToken: "my-secret-token",
    }, nil)
    if err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
        id, err := auth.Authenticate(r)
        if err != nil {
            status, header, msg := auth.Challenge(err, "")
            if header != "" {
                w.Header().Set("WWW-Authenticate", header)
            }
            http.Error(w, msg, status)
            return
        }
        fmt.Fprintf(w, "Hello, %s (method: %s)", id.Subject, id.Method)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Middleware

```go
auth, _ := authware.New(cfg, nil)
mux := http.NewServeMux()
mux.Handle("/api/", authware.Middleware(auth)(apiHandler))
mux.Handle("/admin/", authware.Middleware(auth)(
    authware.RequireScopes("admin")(adminHandler),
))
```

The authenticated identity is available in the request context:

```go
id, ok := authware.IdentityFromContext(r.Context())
// id.Subject, id.Method, id.Scopes
```

## OAuth / JWT with OIDC Auto-Discovery

When `OAuthJWKSURL` is omitted, the library fetches
`{issuer}/.well-known/openid-configuration` to resolve the JWKS endpoint
automatically. Works with Google, Auth0, Keycloak, Azure AD, Okta,
Anthropic, and any other OIDC-compliant provider.

```go
auth, err := authware.New(&authware.Config{
    Mode:                authware.ModeOAuth,
    OAuthIssuer:         "https://accounts.google.com",
    OAuthAudience:       "my-api",
    OAuthRequiredScopes: []string{"api:read"},
}, nil)
```

Explicit JWKS URL is still supported:

```go
auth, err := authware.New(&authware.Config{
    Mode:          authware.ModeOAuth,
    OAuthIssuer:   "https://auth.example.com",
    OAuthAudience: "my-api",
    OAuthJWKSURL:  "https://auth.example.com/.well-known/jwks.json",
}, nil)
```

## OAuth Proxy (MCP 3/26)

The `OAuthProxy` bridges MCP clients (e.g. Claude Desktop) that require
RFC 7591 Dynamic Client Registration and public-client auth with upstream
IdPs (e.g. Azure AD, Okta) that don't natively support them.

It provides three HTTP handlers:

- **`ASMetadataHandler`** — serves `/.well-known/oauth-authorization-server`
  with a custom RFC 8414 metadata document (fetched once, cached)
- **`RegisterHandler`** — minimal RFC 7591 DCR shim returning a pre-configured
  `client_id`
- **`TokenHandler`** — proxies token exchange requests to the upstream IdP

```go
proxy := authware.NewOAuthProxy(&authware.Config{
    OAuthAuthorizationServers: []string{"https://login.microsoftonline.com/tenant/v2.0"},
    OAuthClientID:             "my-app-client-id",
}, slog.Default())

if proxy != nil {
    mux.HandleFunc("/.well-known/oauth-authorization-server", proxy.ASMetadataHandler())
    mux.HandleFunc("/oauth/register", proxy.RegisterHandler())
    mux.HandleFunc("/oauth/token", proxy.TokenHandler())
}
```

All proxy JSON serialization uses [go-jsonfast](https://github.com/ubyte-source/go-jsonfast)
`Builder` with pooled buffers — zero `encoding/json.Marshal` calls on the hot path.

## Nginx auth_request

The `AuthCheckHandler` returns an `http.Handler` compatible with nginx's
[auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
module. On success it returns 200 with identity headers; on failure 401/403.

```go
mux.Handle("/check", authware.AuthCheckHandler(auth))
```

nginx configuration:

```nginx
location /api/ {
    auth_request /check;
    auth_request_set $auth_subject $upstream_http_x_auth_subject;
    auth_request_set $auth_method  $upstream_http_x_auth_method;
    proxy_set_header X-Auth-Subject $auth_subject;
    proxy_set_header X-Auth-Method  $auth_method;
    proxy_pass http://backend;
}

location = /check {
    internal;
    proxy_pass http://127.0.0.1:9090/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
```

The `AuthCheckHandler` can be used to build a standalone auth-check
microservice that sits behind nginx and validates every incoming request.

## Environment Configuration

`ConfigFromEnv` reads `AUTH_*` environment variables for easy deployment.
See [.env.example](.env.example) for all available variables.

```go
cfg := authware.ConfigFromEnv()
auth, err := authware.New(cfg, nil)
```

## Auth Modes

| Mode | Config Fields | Description |
|------|--------------|-------------|
| `none` | — | Pass-through, no authentication |
| `bearer` | `BearerToken` | Static bearer token in `Authorization: Bearer <token>` |
| `apikey` | `APIKey`, `APIKeyHeader` | Static key in custom header or `Authorization: ApiKey <key>` |
| `oauth` | `OAuthIssuer` + optional fields | Full JWT validation with JWKS / OIDC discovery |

## Benchmarks

Measured on Intel Xeon Gold 6426Y (32 cores):

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Bearer (accept) | 19 | 0 | 0 |
| Bearer (reject) | 10 | 0 | 0 |
| API Key | 23 | 0 | 0 |
| API Key (Authorization header) | 37 | 0 | 0 |
| None | 4 | 0 | 0 |
| OAuth HMAC HS256 | 1086 | 24 | 1 |
| Scope check | 33 | 0 | 0 |
| Secure equal | 22 | 0 | 0 |
| Proxy: Register (DCR) | 4356 | 6475 | 22 |
| Proxy: AS Metadata (cached) | 2874 | 6533 | 19 |
| Proxy: Token | 85083 | 50920 | 120 |
| Middleware (Bearer) | 361 | 624 | 7 |

Hot paths (Bearer, API Key, None, Scope check, Secure equal) are **zero-allocation**.
OAuth HMAC has a single allocation for the HMAC hash buffer reuse.
Proxy handlers use pooled go-jsonfast builders.

## 📁 Project Structure

```
go-authware/
├── authware.go         # Constructor, config, middleware, context helpers
├── types.go            # Config, Identity, Authenticator interface
├── bearer.go           # Bearer token authenticator
├── apikey.go           # API key authenticator
├── none.go             # Pass-through authenticator
├── jwt.go              # OAuth/JWT validation with JWKS auto-discovery
├── oidc.go             # OIDC auto-discovery
├── proxy.go            # OAuth proxy (AS metadata, DCR shim, token proxy)
├── challenge.go        # HTTP challenge/error response formatting
├── handler.go          # Nginx auth_request handler
├── env.go              # Environment variable configuration
├── doc.go              # Package documentation
├── bench_test.go       # Performance benchmarks (12 benchmarks)
├── default.pgo         # PGO profile for build optimization
├── .golangci.yml       # Ultra-strict linter config (27 linters)
├── Makefile            # Build, test, bench, lint
├── CONTRIBUTING.md     # Contribution guidelines
├── SECURITY.md         # Security policy
└── LICENSE             # MIT
```

## 🤝 Contributing

Contributions are welcome. Please fork the repository, create a feature branch, and submit a pull request.

For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 🔖 Versioning

We use [SemVer](https://semver.org/) for versioning. For available versions, see the [tags on this repository](https://github.com/ubyte-source/go-authware/tags).

---

## 👤 Authors

- **Paolo Fabris** — _Initial work_ — [ubyte.it](https://ubyte.it/)

See also the list of [contributors](https://github.com/ubyte-source/go-authware/contributors) who participated in this project.

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ☕ Support This Project

If go-authware has been useful for your projects, consider supporting its development:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-orange?style=for-the-badge&logo=buy-me-a-coffee)](https://coff.ee/ubyte)

---

**Star this repository if you find it useful.**

For questions, issues, or contributions, visit our [GitHub repository](https://github.com/ubyte-source/go-authware).
