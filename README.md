# go-authware

> Minimal-dependency HTTP authentication library for Go servers.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![CI](https://github.com/ubyte-source/go-authware/actions/workflows/ci.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ubyte-source/go-authware)](https://goreportcard.com/report/github.com/ubyte-source/go-authware)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubyte-source/go-authware.svg)](https://pkg.go.dev/github.com/ubyte-source/go-authware)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Features

- **Four auth modes**: None, Bearer, API Key, OAuth/JWT
- **OIDC auto-discovery** — works with any OpenID Connect provider
- **Minimal dependencies** — stdlib + [go-jsonfast](https://github.com/ubyte-source/go-jsonfast) for zero-alloc JSON parsing
- **Constant-time comparisons** via `crypto/subtle` on all secret paths
- **JWT/JWKS support**: HMAC-SHA256/384/512, RSA (PKCS1v15 + PSS), ECDSA (P-256/384/521)
- **JWKS auto-refresh** with cache TTL and stampede prevention
- **RFC 9728** Protected Resource Metadata
- **Zero-alloc hot paths** using `unsafe.Slice` for string→[]byte views
- **Nginx auth_request** compatible handler
- **Environment variable configuration** via `ConfigFromEnv`

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
├── challenge.go        # HTTP challenge/error response formatting
├── handler.go          # Nginx auth_request handler
├── env.go              # Environment variable configuration
├── doc.go              # Package documentation
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
