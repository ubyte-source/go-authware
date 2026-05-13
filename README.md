# go-authware

> Pluggable HTTP authentication, outbound credentials, secret management, and
> anti-replay for Go services. Stdlib + `go-jsonfast`. Nothing else.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![Lint](https://github.com/ubyte-source/go-authware/actions/workflows/lint.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/lint.yml)
[![Test](https://github.com/ubyte-source/go-authware/actions/workflows/test.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/test.yml)
[![Security](https://github.com/ubyte-source/go-authware/actions/workflows/security.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/security.yml)
[![Fuzz](https://github.com/ubyte-source/go-authware/actions/workflows/fuzz.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/fuzz.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ubyte-source/go-authware)](https://goreportcard.com/report/github.com/ubyte-source/go-authware)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubyte-source/go-authware.svg)](https://pkg.go.dev/github.com/ubyte-source/go-authware)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Packages

| Import path | Purpose |
|---|---|
| `github.com/ubyte-source/go-authware`         | Server-side authentication (Bearer, API Key, OAuth/JWT, mTLS, OAuth proxy, hardening middleware) |
| `github.com/ubyte-source/go-authware/cred`    | Outbound credentials (OAuth2, AWS SigV4, Azure MSI/SPN, GCP, mTLS, Cache, RoundTripper) |
| `github.com/ubyte-source/go-authware/secret`  | Secret providers (Static, Env, File) and per-tenant Resolver |
| `github.com/ubyte-source/go-authware/replay`  | HMAC anti-replay envelope (Signer, Verifier, NonceStore, Memory) |

The four packages are independent. Import only what you need.

## Install

```bash
go get github.com/ubyte-source/go-authware
```

## Server-side authentication

Five mutually exclusive modes, selected by `Config.Mode` or inferred from the
fields you populate:

```go
auth, err := authware.New(&authware.Config{
    Mode:        authware.ModeBearer,
    BearerToken: "my-secret-token",
}, nil)
if err != nil { log.Fatal(err) }

mux := http.NewServeMux()
mux.Handle("/api/", authware.Middleware(auth)(apiHandler))
```

The authenticated identity is stored in the request context as a
read-only `*Identity`:

```go
id, ok := authware.IdentityFromContext(r.Context())
// id.Subject, id.Method, id.Scopes, id.PeerCert
// id.Claim(name) for OAuth claims (lazy decode, zero alloc on miss)
// id.RangeClaims(fn) to walk every claim
```

JWT claims are not eagerly decoded into a `map[string]any`. Use
`id.Claim(name)` for the common single-claim case (zero alloc on miss,
one parse on hit) or `id.RangeClaims(fn)` to iterate the payload.

### Mode reference

| Mode             | Required fields                       | Notes |
|------------------|---------------------------------------|-------|
| `ModeNone`       | —                                     | Pass-through; useful for tests and dev |
| `ModeBearer`     | `BearerToken`                         | Constant-time comparison |
| `ModeAPIKey`     | `APIKey`, optional `APIKeyHeader`     | Custom header or `Authorization: ApiKey <key>` |
| `ModeOAuth`      | `OAuthIssuer` (+ optional fields)     | JWT validation with JWKS / OIDC discovery |
| `ModeMTLS`       | `MTLSAllowedSubjects` and/or `MTLSAllowedSPKIPins` | Verifies peer certificate against an allowlist |

### Capability-based authorization

`RequireCapability` composes admission predicates over the authenticated
identity. `RequireScopes` is a thin wrapper for the common case.

```go
mux.Handle("/admin/", authware.Middleware(auth)(
    authware.RequireCapability(
        authware.HasMethod(authware.ModeOAuth),
        authware.HasAllScopes("admin"),
        authware.HasClaim("tenant", "acme"),
    )(adminHandler),
))
```

Built-in predicates: `HasScope`, `HasAnyScope`, `HasAllScopes`,
`HasClaim`, `HasMethod`, `HasSubject`. Custom predicates are any
`func(*Identity) bool`.

### OIDC auto-discovery

Omit `OAuthJWKSURL` and the library fetches
`{issuer}/.well-known/openid-configuration` once, caching the JWKS with
TTL and stampede-prevented refresh. Works with Google, Auth0, Keycloak,
Azure AD, Okta, and any other OIDC-compliant provider.

```go
auth, _ := authware.New(&authware.Config{
    Mode:                authware.ModeOAuth,
    OAuthIssuer:         "https://accounts.google.com",
    OAuthAudience:       "my-api",
    OAuthRequiredScopes: []string{"api:read"},
}, nil)
```

The issuer URL and the JWKS URL it advertises must use `https://`.
Plain `http://` is accepted only for loopback hosts (`localhost`,
`127.0.0.1`, `::1`) so that test fixtures keep working. RSA keys with a
modulus shorter than 2048 bits are rejected (NIST SP 800-131A Rev. 2).

### Server mTLS

```go
auth, _ := authware.New(&authware.Config{
    Mode:                authware.ModeMTLS,
    MTLSAllowedSubjects: []string{"client.example"},
    MTLSAllowedSPKIPins: [][]byte{spkiSHA256Pin},
}, nil)
```

The verified `*x509.Certificate` is exposed as `Identity.PeerCert`. Pin
matching uses `subtle.ConstantTimeCompare` on the SHA-256 SPKI digest.

### Hardening middleware

```go
maxBytes := authware.MaxBytes(1 << 20)                 // 1 MiB body cap
sec      := authware.SecurityHeaders(&authware.SecureHeadersConfig{
    HSTSMaxAge:         31536000,
    HSTSIncludeSubs:    true,
    ContentTypeNosniff: true,
    FrameOptions:       "DENY",
    ReferrerPolicy:     "no-referrer",
})
csrf, err := authware.CSRF(authware.CSRFOptions{
    TrustedOrigins: []string{"https://app.example"},
    BypassPaths:    []string{"/api/webhook"},
})
```

`SecurityHeaders` precomputes the `(name, value)` pairs once and writes them
via direct `http.Header` map assignment — zero-allocation per request. `CSRF`
is a thin shim over `http.NewCrossOriginProtection` (Go 1.25+).

### Log redaction

```go
handler := authware.NewRedactor(slog.NewJSONHandler(os.Stdout, nil),
    authware.SensitiveHeaders...)
slog.SetDefault(slog.New(handler))

// In an http handler before logging request headers:
authware.RedactHeader(r.Header.Clone())
```

`NewRedactor` walks slog records (and grouped attributes) replacing
matched keys with `***`. `RedactHeader` mutates an `http.Header` in place.

### OAuth proxy (MCP 2025-11-25)

`OAuthProxy` bridges public-client MCP flows with upstream IdPs that don't
natively support RFC 7591 Dynamic Client Registration:

```go
proxy := authware.NewOAuthProxy(&authware.Config{
    OAuthAuthorizationServers: []string{"https://login.microsoftonline.com/tenant/v2.0"},
    OAuthClientID:             "my-app-client-id",
    OAuthClientSecret:         "my-app-client-secret",
}, slog.Default())

if proxy != nil {
    mux.HandleFunc("GET /.well-known/oauth-authorization-server", proxy.ASMetadataHandler())
    mux.HandleFunc("GET /authorize", proxy.AuthorizeHandler())
    mux.HandleFunc("POST /register", proxy.RegisterHandler())
    mux.HandleFunc("POST /token",    proxy.TokenHandler())
}
```

### Nginx auth_request

`AuthCheckHandler` returns an `http.Handler` compatible with the nginx
[auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
module. On success it returns 200 with `X-Auth-Subject`, `X-Auth-Method`,
and `X-Auth-Scopes` response headers. Header values are sanitised
against CR/LF/control bytes (CWE-113) so a JWT-derived subject cannot
inject additional response headers.

```go
mux.Handle("/check", authware.AuthCheckHandler(auth))
```

### Environment configuration

`ConfigFromEnv` reads the `AUTH_*` environment variables. See
[.env.example](.env.example) for the full list (auth modes, OAuth,
mTLS, hardening headers, CSRF).

```go
cfg := authware.ConfigFromEnv()
auth, err := authware.New(cfg, nil)
```

## Outbound credentials — `cred`

```go
import "github.com/ubyte-source/go-authware/cred"
```

| Symbol                            | Role |
|-----------------------------------|------|
| `Token`                           | Outbound credential; `Apply` writes it to `*http.Request` |
| `TokenSource`, `TokenSourceFunc`  | Produces tokens; safe for concurrent use |
| `Signer`, `SignerFunc`            | Signs a request in place (for SigV4-style schemes) |
| `AsSigner(TokenSource) Signer`    | Adapts a token source to a signer |
| `Cache(TokenSource, ...)`         | TTL caching with manual singleflight; zero-alloc hit path |
| `RoundTripper(base, Signer)`      | `http.RoundTripper` that clones the request and signs it |
| `ClientCredentials`               | OAuth2 `client_credentials` grant (RFC 6749 §4.4) |
| `AuthorizationCode`               | OAuth2 `refresh_token` grant with rotation |
| `SigV4`                           | AWS Signature Version 4 (canonical form, no SDK) |
| `AzureMSI`                        | Azure Instance Metadata Service (managed identity) |
| `AzureSPN`                        | Azure AD service principal via `client_credentials` |
| `GCPMetadata`                     | GCP metadata server (access token or audience-bound ID token) |
| `LoadClientTLS`, `ReloadingClientTLS` | Outbound TLS configuration with on-demand reload |

End-to-end flow:

```go
src := &cred.ClientCredentials{
    TokenURL: "https://issuer.example/oauth2/token",
    ClientID: "id", ClientSecret: "secret",
    Scopes: []string{"api:read"},
}
cached := cred.Cache(src)                          // TTL + singleflight
client := &http.Client{
    Transport: cred.RoundTripper(nil, cred.AsSigner(cached)),
}

req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example/v1/items", nil)
resp, err := client.Do(req)                        // Authorization auto-attached
```

AWS SigV4:

```go
signer := &cred.SigV4{
    AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
    SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
    Region:    "us-east-1",
    Service:   "execute-api",
}
client := &http.Client{Transport: cred.RoundTripper(nil, signer)}
```

The package validates against the AWS-published `get-vanilla` test vector
byte-for-byte.

## Secret management — `secret`

```go
import "github.com/ubyte-source/go-authware/secret"
```

```go
p := secret.Static(map[string]string{"db_password": "p4ss"})
v, _ := p.Secret(ctx, "db_password")     // → "p4ss"
```

Three providers shipped:

- `secret.Static(map)` — in-memory.
- `secret.Env(prefix)` — environment variables under `prefix`.
- `secret.File(path)` — flat JSON document loaded once.

Per-tenant resolution:

```go
r := secret.MapResolver(map[string]secret.Provider{
    "alpha": secret.Static(...),
    "beta":  secret.Env("BETA_"),
}, secret.Static(defaults))
v, _ := r.For(tenantID).Secret(ctx, "db_password")
```

Vault, AWS Secrets Manager, GCP Secret Manager, and SOPS adapters are
intentionally excluded. Each is a 30-line wrapper around `secret.Provider`
that you add to your own binary, keeping go-authware dependency-free.

## Anti-replay HMAC — `replay`

```go
import "github.com/ubyte-source/go-authware/replay"
```

Three headers carry the envelope: `X-Auth-Timestamp`, `X-Auth-Nonce`,
`X-Auth-Signature`. Signed string is `method "\n" path "\n" timestamp "\n" nonce`
(body is not part of the signature; use `cred.SigV4` if you need body
binding).

Server side:

```go
v := &replay.Verifier{
    Key:        sharedKey,                // ≥ 32 bytes
    Window:     5 * time.Minute,
    NonceStore: replay.Memory(8192),
}
mux.Handle("/api/", replay.Middleware(v)(apiHandler))
```

Client side:

```go
s := &replay.Signer{Key: sharedKey}
client := &http.Client{Transport: cred.RoundTripper(nil, s)}
```

`Memory` is an LRU+TTL store suitable for single-instance deployments.
For fleets, plug in any `NonceStore` implementation (Redis, etc.).

## Benchmarks

Measured on Intel Xeon Gold 6426Y. Hot paths designed for zero allocation
are achieved.

### Server authentication (`go-authware` root)

| Benchmark              | ns/op | B/op | allocs/op | Notes |
|------------------------|------:|-----:|----------:|-------|
| None                   |   1.5 |    0 |         0 | Pre-built shared `*Identity` |
| Bearer                 |    16 |    0 |         0 | Constant-time compare; shared identity |
| API Key (header)       |    22 |    0 |         0 | |
| API Key (Authorization)|    36 |    0 |         0 | |
| HasRequiredScopes      |    10 |    0 |         0 | `slices.Contains` |
| RequireCapability      |    29 |    0 |         0 | Pointer-in-context lookup |
| MTLS accept (subject)  |    43 |   80 |         1 | Identity per request |
| MTLS accept (pin)      |   192 |   80 |         1 | SHA-256 SPKI compare |
| SecurityHeaders        |    70 |    0 |         0 | Pre-computed headerKV slice |
| MaxBytes               |    80 |   64 |         1 | Inherent `http.MaxBytesReader` alloc |
| Middleware (Bearer)    |   136 |  368 |         2 | `r.WithContext` + ctx node |
| AuthCheckHandler       |   137 |   32 |         2 | nginx auth_request handler |
| OAuth HMAC HS256       |  1432 |  289 |         5 | jsonfast claims, lazy decode |
| RedactHeader           |   217 |   48 |         3 | Pre-canonicalised sensitive set |
| Redactor (slog hit)    |  1007 |   16 |         1 | Recursive group walk |

### Outbound credentials (`cred`)

| Benchmark           | ns/op | B/op | allocs/op | Notes |
|---------------------|------:|-----:|----------:|-------|
| Cache hit           |    77 |    0 |         0 | `atomic.Pointer.Load` + freshness |
| Token.Apply         |   118 |   40 |         2 | inherent `http.Header.Set` |
| RoundTripper        |   572 | 1160 |         9 | dominated by `r.Clone(ctx)` |
| ParseTokenResponse  |   294 |   88 |         4 | jsonfast iteration |
| SigV4 sign          |  8282 | 4944 |        62 | HMAC chain + canonical encoding |

### Anti-replay (`replay`)

| Benchmark    | ns/op | B/op | allocs/op | Notes |
|--------------|------:|-----:|----------:|-------|
| Memory.Seen  |   362 |   71 |         1 | Typed doubly-linked LRU + TTL |
| Signer.Sign  |  2257 | 1538 |        20 | Pooled scratch + 3 header sets |
| Verify.Hit   |  4334 | 2145 |        32 | Sign + Verify together |

### Secrets (`secret`)

| Benchmark   | ns/op | B/op | allocs/op | Notes |
|-------------|------:|-----:|----------:|-------|
| Static.Hit  |   8.4 |    0 |         0 | map lookup |
| Env.Hit     |   112 |   32 |         2 | `strings.ToUpper` + `os.LookupEnv` |

## Project layout

```
go-authware/
├── *.go ↔ *_test.go                # Server-side auth, hardening, OAuth proxy
├── doc.go example_test.go
├── cred/                           # Outbound credentials
│   ├── *.go ↔ *_test.go
│   └── doc.go example_test.go
├── secret/                         # Secret providers
│   ├── secret.go ↔ secret_test.go
│   └── doc.go example_test.go
└── replay/                         # Anti-replay HMAC
    ├── replay.go ↔ replay_test.go
    └── doc.go example_test.go
```

Every production `.go` file has a paired `<name>_test.go` so the test for
any unit of code is easy to find.

## Security

The threat model, implemented defenses, operational limits, and the
continuous-verification gates (`go vet`, `-race`, `golangci-lint`
including `gosec`, `govulncheck`, native fuzz suite) are documented in
[SECURITY.md](SECURITY.md). Vulnerability reports go through GitHub's
private reporting flow described there.

## Dependencies

```
github.com/ubyte-source/go-jsonfast
```

That's it. No `golang.org/x/oauth2`, no AWS SDK, no Azure/GCP SDKs, no
Vault adapters. Each provider is implemented directly against the
relevant RFC or vendor metadata endpoint.

## License

MIT — see [LICENSE](LICENSE).

## Authors

- **Paolo Fabris** — [ubyte.it](https://ubyte.it/)

## Support

If go-authware is useful for your services, consider supporting the work:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-orange?style=for-the-badge&logo=buy-me-a-coffee)](https://coff.ee/ubyte)
