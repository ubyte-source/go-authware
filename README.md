# go-authware

> HTTP authentication, outbound credentials, secrets and anti-replay signing
> for Go services. Standard library plus `go-jsonfast`, nothing else.

[![Go Version](https://img.shields.io/badge/Go-1.25.1+-blue.svg)](https://golang.org)
[![Lint](https://github.com/ubyte-source/go-authware/actions/workflows/lint.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/lint.yml)
[![Test](https://github.com/ubyte-source/go-authware/actions/workflows/test.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/test.yml)
[![Security](https://github.com/ubyte-source/go-authware/actions/workflows/security.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/security.yml)
[![Fuzz](https://github.com/ubyte-source/go-authware/actions/workflows/fuzz.yml/badge.svg)](https://github.com/ubyte-source/go-authware/actions/workflows/fuzz.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubyte-source/go-authware/v2.svg)](https://pkg.go.dev/github.com/ubyte-source/go-authware/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Packages

| Import path | Purpose |
|---|---|
| `github.com/ubyte-source/go-authware/v2`        | Inbound authentication: the `Gate` (none, bearer, API key, OAuth/JWT, mTLS), OAuth metadata and authorization server facade, hardening middleware, log redaction |
| `github.com/ubyte-source/go-authware/v2/cred`   | Outbound credentials: OAuth2 client credentials and refresh token, Azure MSI, GCP metadata, AWS SigV4, client mTLS, token cache, signing transport |
| `github.com/ubyte-source/go-authware/v2/secret` | `secret.Value`, which never prints its content, providers (`Static`, `Env`, `File`) and a per-tenant `MapResolver` |
| `github.com/ubyte-source/go-authware/v2/replay` | HMAC-SHA256 request signing with nonce replay protection (`NewSigner`, `NewVerifier`, `NewMemoryStore`) |

Import only what you need. `cred` and `replay` hold their keys in
`secret.Value`; `replay.Signer` plugs into `cred.NewTransport`.

## Install

```bash
go get github.com/ubyte-source/go-authware/v2
```

## API conventions

The module path is `github.com/ubyte-source/go-authware/v2`. These
constructors validate their input and return an error: `authware.New`,
`authware.ConfigFromEnv`, `cred.NewClientCredentials`, `cred.NewRefreshToken`,
`cred.NewAzureMSI`, `cred.NewGCPMetadata`, `cred.NewSigV4`, `cred.Basic`,
`cred.NewCachedSource`, `cred.LoadClientTLS`, `secret.File`,
`replay.NewSigner`, `replay.NewVerifier` and `replay.NewMemoryStore`;
`authware`, `cred` and `replay` each name their configuration error
`ErrInvalidConfig`. `authware.NewRedactor`, `cred.AsSigner` and
`cred.NewTransport` take a dependency that must not be nil and do not check
it. Settings travel in typed configs (`authware.Config`,
`cred.ClientCredentialsConfig`, `cred.ClientTLSConfig` and so on) or in
options typed per constructor. Secrets are `secret.Value`, never plain
strings.

## Server-side authentication

A `Gate` enforces exactly one mode. The mode is always explicit, and `New`
reports every configuration problem at once, each error wrapping
`ErrInvalidConfig`.

```go
gate, err := authware.New(&authware.Config{
    Mode: authware.ModeOAuth,
    OAuth: authware.OAuthConfig{
        Issuer:         "https://login.example.com/tenant",
        Audience:       "api://orders",
        RequiredScopes: []string{"orders.read"},
    },
})
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/mcp", gate.Middleware(mcpHandler))
gate.Mount(mux, "/mcp") // protected resource metadata for /mcp
```

| Mode         | Settings                                   | Credential |
|--------------|--------------------------------------------|------------|
| `ModeNone`   | none                                       | Admits every request |
| `ModeBearer` | `Bearer.Token` (at least 32 bytes, no control byte, space or tab) | `Authorization: Bearer <token>` |
| `ModeAPIKey` | `APIKey.Key` (at least 32 bytes, no space or tab at either end, no control byte but an inner tab), `APIKey.Header` (default `X-Api-Key`) | The header, or `Authorization: ApiKey <key>` when the header is absent and the key has no space or tab |
| `ModeOAuth`  | `OAuth.Issuer`, `OAuth.Audience`, plus `JWKSURL` or `HMACSecret` or neither (discovery) | `Authorization: Bearer <JWT>` |
| `ModeMTLS`   | `MTLS.AllowedSubjects` and/or `MTLS.AllowedSPKIPins` | Client certificate |

Static credentials are compared as SHA-256 digests in constant time, and the
`Authorization` scheme must be an ASCII token before it is compared
case-insensitively. A repeated `Authorization` or API key header is
rejected. The sections of the other modes must stay empty; `Realm` (default
`restricted`) names the protection space in challenges.

### Identity

`Gate.Middleware` stores the authenticated `*Identity` in the request
context; `Gate.Authenticate` returns it directly.

```go
id, ok := authware.IdentityFromContext(r.Context())
fmt.Println(ok, id.Subject(), id.Mode(), id.Scopes(), id.HasScope("orders.read"))
team, ok := id.ClaimString("team")
fmt.Println(team, ok)
```

`PeerCertificate` returns the client certificate in `ModeMTLS`; `Claim`,
`ClaimString`, `ClaimInt64`, `ClaimFloat64`, `ClaimBool` and `Claims`
read the token claims in `ModeOAuth`. An Identity is immutable. Claims are
kept as an owned copy of the JWT payload and decoded on demand. The subject
is `sub`, else `client_id`, else `azp`; static modes report `static-bearer`
or `static-apikey`, and mTLS the matched common or distinguished name; a pin
reports the DN of a verified chain, else `sha256/` and the base64 pin.

### Failures

`Gate.Authenticate` errors match one sentinel with `errors.Is`, and the
middleware answers with a fixed body naming only the status:

| Sentinel                | Status | `WWW-Authenticate` (Bearer) |
|-------------------------|--------|-----------------------------|
| `ErrMissingCredentials` | 401    | `realm` only |
| `ErrInvalidCredentials` | 401    | `error="invalid_token"` |
| `ErrTokenExpired`       | 401    | `error="invalid_token"` |
| `ErrInsufficientScope`  | 403    | `error="insufficient_scope"`, `scope` |
| `ErrKeysUnavailable`    | 503    | none; `Retry-After: 30` |

In `ModeOAuth` every 401 and scope 403 challenge also carries
`resource_metadata`, pointing at the protected resource metadata of the
requested path. API key challenges are `ApiKey realm="..."`. `ModeMTLS` and
`ModeNone` have no challenge scheme, so they answer 403 without
`WWW-Authenticate` where a 401 would need one. Parameter values are
quoted-string escaped.

A refused request is answered, never logged, and `Gate.Authenticate` returns
its cause. `Config.ErrorLog`, when set, receives at warn level the causes no
answer carries: every failed fetch of the keys or the issuer metadata, also
while stale ones are served, and every facade request the upstream fails.

### Authorization

`Require` admits requests whose identity passes every `Capability`. Without
an identity it answers 401 (403 in `ModeMTLS` and `ModeNone`); a failed
scope capability answers 403, naming the scopes in the Bearer challenge in
`ModeBearer` and `ModeOAuth`, and any other failed capability a plain 403.

```go
admin := gate.Middleware(gate.Require(
    authware.HasMode(authware.ModeOAuth),
    authware.HasAllScopes("admin"),
    authware.HasClaim("tenant", "acme"),
)(adminHandler))
```

Built-in capabilities: `HasAnyScope`, `HasAllScopes`, `HasClaim` (a JSON
string, integer, number or boolean equal to a `string`, `int64`, `float64`
or `bool`, read as `ClaimString`, `ClaimInt64`, `ClaimFloat64` or
`ClaimBool` read it), `HasMode`, `HasSubject`; `NewCapability(fn)` wraps
any predicate.

### OAuth: JWT access tokens

Keys come from `JWKSURL`, from the `jwks_uri` discovered from `Issuer`, or
from `HMACSecret` (at least 32 bytes, exclusive with `JWKSURL`). A token is
accepted only when all of these hold:

- At most 16 KiB, checked before any decoding; exactly three strict
  base64url segments.
- Header and payload are UTF-8 JSON objects without duplicate members or
  lone surrogate escapes, nested at most 32 levels.
- `alg` is one of RS256/384/512, PS256/384/512 (salt length equal to the
  hash), ES256/384/512 (fixed-length R||S, curve pinned), EdDSA (Ed25519),
  or, in HMAC mode only, HS256/384/512 under a secret at least as long as
  the hash (32, 48 or 64 bytes). JWKS mode refuses HS*, HMAC mode refuses
  the rest.
- `typ` is absent, `JWT`, `application/jwt`, `at+jwt` or
  `application/at+jwt`, in any ASCII case; `RequireAccessTokenType`
  accepts only the `at+jwt` forms. `crit` in any form rejects the token;
  `jku`, `x5u`, `jwk` and `x5c` are never used.
- `iss` equals `Issuer` byte for byte; `aud`, a string or an array of
  strings, is required and contains `Audience`.
- `exp` is required and the token is expired once now is past
  `exp + ClockSkew` (default 30s); `nbf` and `iat` may not lie beyond
  now plus the skew. Time claims are JSON numbers from 0 to 2^53.
- ID tokens are refused: `at_hash`, `c_hash`, or `nonce` without any of
  `scope`, `scp` or `roles`.
- Every `RequiredScopes` entry is granted by `scope` (space-separated) or
  `scp` (string or array); otherwise 403 `insufficient_scope`.

**Keys.** A JWKS keeps its usable keys and skips the others: unknown
`kty` or curve, RSA outside 2048 to 8192 bits or with an even exponent or
one outside 3 to 2^31-1, EC coordinates off the curve or not full length,
`use` other than `sig`, `key_ops` without `verify`, or a JWK `alg` that
does not fit the key. A set without a usable key is an error. A token `kid`
selects among the keys with that `kid`; without `kid` exactly one
compatible key must exist. A JWK `alg`, when present, must equal the token
`alg`.

**Cache.** Keys live for `KeysCacheTTL` (default 5m). The issuer metadata
is cached the same way and shared by the keys and the facade, so a key
refresh discovers again only once the metadata is older than
`KeysCacheTTL`. Concurrent refreshes share one fetch, bounded by
`FetchTimeout` (default 10s) and detached from the caller's cancellation.
A token whose key is missing forces one refresh, at most every 30s, which
the tokens missing a key wait for while it runs; such a token gets 503 with
`Retry-After` when that refresh fails and while a failed fetch backs off.
While fetching fails, the last good set is served until 24h after it was
fetched, so a `KeysCacheTTL` of 24h or more serves nothing stale, and no
new fetch starts for 30s after a failure; with no usable set the request
gets 503 with `Retry-After`.

**Discovery.** Without `JWKSURL`, the gate fetches
`{issuer}/.well-known/openid-configuration`, then
`{origin}/.well-known/oauth-authorization-server{path}`. The document `issuer`
must equal `Issuer` exactly, and `jwks_uri`, `authorization_endpoint` and
`token_endpoint` must share the scheme, host and port of the issuer. An
identity provider that publishes its keys on another origin, such as Google
(`https://www.googleapis.com/oauth2/v3/certs`), needs `JWKSURL`.

Every outbound URL (issuer, JWKS, discovered endpoints) must be `https`,
or `http` to `localhost`, `127.0.0.0/8` or `::1`, and must not carry
userinfo (`ErrInsecureURL`); `CheckOutboundURL` applies the same policy to a
URL of your own. Outbound requests go through a copy of `Config.HTTPClient`
that never follows redirects and whose timeout is at most `FetchTimeout`;
key and discovery fetches treat any non-2xx status as a failure, of which
they read at most 4 KiB, accept a document of at most 1 MiB (JWKS) or
256 KiB (metadata) and refuse one that is not a UTF-8 JSON object without
duplicate members or lone surrogate escapes, nested at most 32 levels.

### OAuth: protected resource metadata

`Gate.Mount(mux, endpoints...)` registers, in `ModeOAuth` only, `GET
/.well-known/oauth-protected-resource` plus that path followed by each
endpoint and its sub-paths; the bare path describes the first endpoint.

- `resource`: `Resource.Identifier`, else origin plus the escaped request path
  after `/.well-known/oauth-protected-resource`, or for that bare path the
  first endpoint unless it is `/`.
- `authorization_servers`: the origin when the facade is enabled (an
  explicit `Resource.AuthorizationServers` is then a configuration error),
  else `Resource.AuthorizationServers`, which defaults to `Issuer` when it
  is a secure URL; omitted when empty.
- `scopes_supported`: `RequiredScopes`; `bearer_methods_supported`:
  `["header"]`; `resource_name` and `resource_documentation` when set.

The origin is `PublicURL` when set (it must be `scheme://host[:port]` in
lower case, without the default port of the scheme). Otherwise it is `https`
for TLS connections, or the first `X-Forwarded-Proto` element (http or
https) when `TrustForwardedProto` is set, else `http`, joined with the
request `Host`. Documents derived from the request are sent with
`Cache-Control: private, max-age=300` and `Vary: Host, X-Forwarded-Proto`;
with `PublicURL` they are `public, max-age=300`.

### OAuth: authorization server facade

Setting `OAuth.Facade.ClientID` turns the gate into an authorization server
for public clients, such as MCP clients that expect dynamic registration,
relaying to the issuer as one pre-registered upstream client. `Mount` then
also serves:

| Route | Behavior |
|---|---|
| `GET /.well-known/oauth-authorization-server` | Metadata with `issuer` = origin, the three endpoints below, `response_types_supported` `[code]`, `grant_types_supported` `[authorization_code, refresh_token]`, `code_challenge_methods_supported` `[S256]`, `token_endpoint_auth_methods_supported` `[none]`, `scopes_supported` = `RequiredScopes` plus `offline_access`; cached like the resource metadata |
| `GET /authorize` | Requires `response_type=code`, `code_challenge_method=S256` with a 43-character challenge, and an `https` or loopback `http` `redirect_uri` without fragment, and refuses `request` and `request_uri`; anything else gets a 400 JSON error and never a redirect. Valid requests get a 302 to the upstream authorization endpoint, whose own query parameters win |
| `POST /register` | UTF-8 JSON object of at most 64 KiB without duplicate members or lone surrogate escapes, nested at most 32 levels, with a non-empty `redirect_uris` array of `https` or loopback `http` URLs; answers 201 with the pinned `client_id`, `token_endpoint_auth_method: none`, both grant types, `response_types: [code]` and the `redirect_uris` |
| `POST /token` | `application/x-www-form-urlencoded` body of at most 64 KiB without repeated parameters; only `authorization_code` (with a 43 to 128 character `code_verifier`) and `refresh_token`, and a `redirect_uri`, when sent, that `/authorize` accepts. A 2xx or 4xx upstream answer of at most 1 MiB, other than a 204 with a body, is relayed with its status, body, `Content-Type` and `WWW-Authenticate` |

Parameters are rewritten in the upstream client's terms: repeated
parameters are refused and only an allowlist is relayed, so `audience`,
`claims`, client credentials and any other name never reach the issuer.
`/authorize` relays `response_type`, `redirect_uri`, `state`,
`code_challenge`, `code_challenge_method`, `nonce`, `prompt` and
`login_hint`; `/token` relays `grant_type`, `code`, `redirect_uri`,
`code_verifier` and `refresh_token`. Both add the pinned `client_id`, and
the upstream client authenticates in the form body with `ClientSecret`
(none for a public client). `scope` is qualified with `ScopePrefix`: bare
scopes, colon names such as `memory:read` included, get the prefix;
`openid`, `offline_access`, `profile`, `email` and scopes already under the
prefix pass unchanged; URI scopes (`://` or `urn:`) outside the prefix and
any token that is not an OAuth scope-token (visible ASCII but `"` and `\`)
are refused with `invalid_scope`. `/authorize` always asks for `openid
offline_access` plus the requested scopes, or `RequiredScopes` when none
are requested, so `New` refuses a facade whose `RequiredScopes` holds a URI
scope outside `ScopePrefix`. `/token` qualifies `scope` only when present.
`resource` is `UpstreamResource`, or absent when that is empty. `New`
refuses a `ScopePrefix` that is not a scope token and an `UpstreamResource`
that is not an absolute URI without a fragment.

The upstream endpoints come from the issuer metadata the keys use,
refreshed after `KeysCacheTTL` and served for up to 24h while discovery
fails; after a failed discovery with nothing to serve, or an upstream
answer neither 2xx nor 4xx, a 204 with a body or oversized, the facade
answers 503 `temporarily_unavailable` with `Retry-After: 30`, and a failed
discovery is not retried for 30s. Every facade response other than the
metadata is `Cache-Control: no-store`, and relayed token responses also
carry `Pragma: no-cache`. Keep PKCE enforced at the upstream provider too:
clients can obtain codes from the upstream authorization endpoint directly.

```go
gate, err := authware.New(&authware.Config{
    Mode: authware.ModeOAuth,
    OAuth: authware.OAuthConfig{
        Issuer:    "https://login.microsoftonline.com/contoso/v2.0",
        Audience:  "api://orders",
        PublicURL: "https://mcp.example.com",
        Facade: authware.FacadeConfig{
            ClientID:     "orders-mcp",
            ClientSecret: clientSecret,
            ScopePrefix:  "api://orders",
        },
    },
})
if err != nil {
    log.Fatal(err)
}
mux := http.NewServeMux()
mux.Handle("/mcp", gate.Middleware(mcpHandler))
gate.Mount(mux, "/mcp") // metadata, /authorize, /register, /token
```

### Server mTLS

```go
gate, err := authware.New(&authware.Config{
    Mode: authware.ModeMTLS,
    MTLS: authware.MTLSConfig{
        AllowedSubjects: []string{"client.example", "CN=admin,O=corp"},
        AllowedSPKIPins: [][]byte{spkiSHA256},
    },
})
```

A subject entry containing `=` is a distinguished name and any other entry a
common name, each written as `pkix.Name.String` renders it, escapes included,
except that a value of a dotted type is `#` and the hex of its DER on every Go
version: `svc\;blue` admits the common name `svc;blue`, and `New` refuses an
entry that is never rendered, such as `CN=a, O=b`, `cn=a,o=b` or `O=b,CN=a` for
`CN=a,O=b`. A subject that repeats its common name or serial number, of which
`pkix.Name` keeps only the last, matches no entry. Subjects match only when the
TLS layer verified the chain (`ClientAuth: tls.RequireAndVerifyClientCert`), since
anyone can self-sign a subject. SPKI pins (SHA-256 of the SubjectPublicKeyInfo, 32
bytes each) bind the key itself and also admit unverified chains; a pin reports
the DN of a verified chain, else `sha256/` followed by the base64 pin, never the
unproven DN. A missing or refused certificate gets 403 without a challenge. The
certificate is available as `Identity.PeerCertificate()`.

### nginx auth_request

`Gate.CheckHandler()` serves the nginx
[auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
protocol: 200 with `X-Auth-Subject` (the identity's subject, so the pin form for a pin
without a verified chain), `X-Auth-Method` and, for an identity with scopes,
`X-Auth-Scopes`, or the challenge (403 in a mode without one, 503 with `Retry-After`
while the keys are unavailable). Responses are `Cache-Control: no-store`, and identity
values have control bytes blanked so a token cannot inject header lines. In `ModeOAuth`
the challenge names the metadata of the path in `X-Original-URI`, or without that
header the bare metadata path, which `Mount` serves for its first endpoint.

```go
mux.Handle("/auth/check", gate.CheckHandler())
```

```nginx
location = /auth/check {
    internal;
    proxy_pass http://gate;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
```

### Hardening middleware

```go
headers := authware.SecurityHeaders(&authware.SecurityHeadersConfig{
    HSTSMaxAge:            31536000,
    HSTSIncludeSubDomains: true,
    ContentTypeNosniff:    true,
    FrameOptions:          "DENY",
    ReferrerPolicy:        "no-referrer",
})
handler := headers(apiHandler)
```

`SecurityHeaders` computes its headers once. Request body limits and the
cross-origin check come from the standard library: `http.MaxBytesHandler` and
`http.CrossOriginProtection`.

### Log redaction

```go
logger := slog.New(authware.NewRedactor(slog.NewTextHandler(os.Stdout, noTime)))
logger.Info("request", slog.String("authorization", "Bearer secret"), slog.String("path", "/api"))
// Output: level=INFO msg=request authorization=*** path=/api
```

`RedactHeader(h, keys...)` masks the same names in an `http.Header` in place
and returns it.

`NewRedactor` masks attributes whose key matches, case-insensitively, at any
depth. `LogValuer` values are resolved first; an `http.Header`, `*http.Header`
or `map[string][]string` is logged as a masked copy, and an `*http.Request` or
`*http.Response` as a group of its method or status, masked URL and masked
header. A `url.URL`, `*url.URL` or `*url.Userinfo` logs its password as
`URL.Redacted` writes it, and a URL query or fragment or `url.Values` logs as
`***` the value of every parameter named in the keys or carrying a credential:
`access_token`, `refresh_token`, `id_token`, `code`, `code_verifier`,
`client_secret`, `client_assertion`, `password` and `api_key`, in any case. In
a logged header, the URLs of `Location`, `Content-Location` and `Referer` are
masked the same way, and a value that is not a URL logs as `***`. Without
keys, `NewRedactor` and `RedactHeader` use `SensitiveHeaders()`:
`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`
and `X-Auth-Token`. A custom `APIKey.Header` is not in that list; pass it to
`NewRedactor` and `RedactHeader`.

### Environment configuration

`ConfigFromEnv(prefix string) (*Config, error)` reads the variables below,
each name preceded by `prefix` (`""` reads them as listed, `"MCP_INBOUND_"`
reads `MCP_INBOUND_AUTH_MODE` and so on), and reports every malformed one,
by name and never by value, in one error wrapping `ErrInvalidConfig`. Lists
are comma-separated, except subjects, which are separated by semicolons
because distinguished names hold commas. A backslash keeps the byte after
it, and itself, in the element, as the escapes of a rendered subject need;
an empty element or one ending in a lone backslash is refused. Pins are
base64 SHA-256 digests and durations use `time.ParseDuration`.
[.env.example](.env.example) documents each one.

```
AUTH_MODE  AUTH_REALM  AUTH_BEARER_TOKEN  AUTH_APIKEY  AUTH_APIKEY_HEADER
AUTH_OAUTH_ISSUER  AUTH_OAUTH_AUDIENCE  AUTH_OAUTH_JWKS_URL  AUTH_OAUTH_HMAC_SECRET
AUTH_OAUTH_REQUIRED_SCOPES  AUTH_OAUTH_REQUIRE_AT_JWT  AUTH_OAUTH_CLOCK_SKEW
AUTH_OAUTH_KEYS_CACHE_TTL  AUTH_OAUTH_FETCH_TIMEOUT  AUTH_OAUTH_PUBLIC_URL
AUTH_OAUTH_TRUST_FORWARDED_PROTO  AUTH_OAUTH_RESOURCE  AUTH_OAUTH_RESOURCE_NAME
AUTH_OAUTH_RESOURCE_DOCUMENTATION  AUTH_OAUTH_AUTHORIZATION_SERVERS
AUTH_OAUTH_FACADE_CLIENT_ID  AUTH_OAUTH_FACADE_CLIENT_SECRET
AUTH_OAUTH_FACADE_SCOPE_PREFIX  AUTH_OAUTH_FACADE_UPSTREAM_RESOURCE
AUTH_MTLS_ALLOWED_SUBJECTS  AUTH_MTLS_SPKI_PINS
```

```go
cfg, err := authware.ConfigFromEnv("EXAMPLE_")
if err != nil {
    log.Fatal(err)
}
gate, err := authware.New(cfg)
```

`Config.Validate` reports, without building a `Gate`, every problem `New`
would refuse the configuration for, so a service can join them with its own
configuration errors at boot. `EnvNames(prefix)` lists the variables
`ConfigFromEnv(prefix)` reads, so a service can tell a misspelled name under
its own prefix from these and warn about it.

## Outbound credentials: `cred`

```go
import "github.com/ubyte-source/go-authware/v2/cred"
```

| Symbol | Role |
|---|---|
| `Token`, `Token.Apply`, `Token.Sign`, `Token.Validate` | Outbound credential written to a request header (`Authorization: Bearer` by default, the value alone when `Bare` is set); a `*Token` is a `Signer` of itself; `Validate` refuses a nil token, a header or scheme that is not a token, a scheme on a `Bare` token and a value that is empty or not a clean header value |
| `Basic(user, password) (*Token, error)` | HTTP Basic credentials as a `Token`; `user` must be a clean header value without a colon |
| `TokenSource`, `TokenSourceFunc` | Produces tokens; safe for concurrent use |
| `Signer`, `SignerFunc`, `AsSigner` | Signs a request in place; `AsSigner` adapts a `TokenSource` |
| `NewTransport(base, signer)` | Signs a clone of every request, with a copy of a `*Token` signer taken when the transport is built; a redirect chain that left the origin goes unsigned, also after it comes back |
| `NewCachedSource(src, opts...) (*CachedSource, error)` | Memoizes tokens until `WithSkew` (default 30s, at most half the lifetime) before expiry, sharing its own copy of each with the header value rendered once; a token already expired when it arrives counts as a failed refresh; `WithTimeout` bounds each refresh and `WithErrorLog` receives every failed one |
| `NewClientCredentials(&ClientCredentialsConfig{...})` | OAuth2 `client_credentials` grant: the token endpoint `ClientConfig` plus `Audience` |
| `NewRefreshToken(&ClientConfig{...}, store)` | OAuth2 `refresh_token` grant; rotated tokens saved through a `RefreshTokenStore` (`NewMemoryRefreshStore`) |
| `NewAzureMSI` | Azure managed identity |
| `NewGCPMetadata` | GCE metadata access tokens, or ID tokens for an audience, below `BaseURL` |
| `NewSigV4(&SigV4Config{...})` | AWS Signature Version 4 `Signer` |
| `LoadClientTLS(&ClientTLSConfig{...})` | Client TLS config for mutual TLS; a positive `Interval` reloads the key pair, and `ErrorLog` receives every failed reload |

Every config above has a `Validate` method that reports, joined, what its
constructor would refuse, a nil store or source aside.

```go
src, err := cred.NewClientCredentials(&cred.ClientCredentialsConfig{
    ClientConfig: cred.ClientConfig{
        TokenURL:     idp.URL + "/oauth2/token",
        ClientID:     "orders-sync",
        ClientSecret: clientSecret,
        Scopes:       []string{"orders.read"},
    },
})
if err != nil {
    log.Fatal(err)
}
cached, err := cred.NewCachedSource(src)
if err != nil {
    log.Fatal(err)
}
client := &http.Client{Transport: cred.NewTransport(nil, cred.AsSigner(cached))}
```

An Azure service principal is a client credentials grant on its tenant's
v2.0 endpoint, `loginHost` being `https://login.microsoftonline.com`, with
the secret in the form and the scope `<resource>/.default`:

```go
src, err := cred.NewClientCredentials(&cred.ClientCredentialsConfig{
    ClientConfig: cred.ClientConfig{
        HTTPClient:   client,
        TokenURL:     loginHost + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token",
        ClientID:     "orders-sync",
        ClientSecret: clientSecret,
        Scopes:       []string{resource + "/.default"},
        AuthStyle:    cred.AuthStyleParams,
    },
})
```

- The `New*` constructors validate their configuration once and report every problem at
  once: bad settings, scopes that are not scope tokens or repeat one and negative timeouts
  included, wrap `ErrInvalidConfig`; an insecure token or metadata URL also wraps
  `ErrInsecureTokenURL`. `NewSigV4` requires the access key, region and service to be
  header tokens and a session token to be a clean header value, and refuses
  `UnsignedPayload` unless `Service` is one of S3's signing names (s3, s3-object-lambda,
  s3-outposts, s3express); `NewGCPMetadata` requires scope tokens without a comma and
  refuses `Scopes` together with `Audience`. `NewCachedSource` and `NewRefreshToken`
  refuse a nil source or store with an error wrapping `ErrInvalidConfig`.
- Token endpoints must be `https`, or `http` to a loopback host, and are
  reached through a copy of `HTTPClient` that refuses redirects. Cloud
  metadata endpoints may also be plain `http` on a link-local address or
  `metadata.google.internal`. The `Timeout` of each source config bounds
  every exchange (default 10s).
- Every error that stops `AsSigner` or `NewTransport` from attaching a
  credential wraps `ErrCredential`. An error answer of a token endpoint or a
  metadata service is an `*OAuth2Error` whatever its size, read from its
  first 4 KiB; `Transient()` reports 5xx, 429, `temporarily_unavailable` and
  `slow_down`. Success answers over 1 MiB or malformed, and network tokens
  that are not clean header credentials, wrap `ErrInvalidTokenResponse`.
- Concurrent `CachedSource` refreshes share one call, detached from the
  caller's cancellation and bounded by `WithTimeout` (default 10s, also for
  zero). A failed refresh goes to the `WithErrorLog` logger at warn level,
  and no other refresh starts for 30s: meanwhile a cached token that has not
  expired is still served, and without one `Token` fails at once with an
  error wrapping that failure.
- With `AsSigner` over a `CachedSource`, a 401 answer invalidates the token
  it carried, at most once every 30s, so an upstream that rejects every
  token costs one token fetch per pause. A request whose body can be
  replayed is then retried once when the source yields another token, after
  the 401 body is drained (at most 4 KiB) so the connection is reused;
  otherwise the 401 is returned.
- `NewRefreshToken` never runs two exchanges at once, and a rotated refresh
  token is saved before the access token is returned. When `Save` fails, the
  exchange returns no token and an error wrapping `ErrRotationNotSaved` and
  the store error; the rotated token stays in memory and the next exchange
  saves it again before presenting it. While `Load` returns the zero Value,
  each exchange fails with `ErrNoRefreshToken` and reads the store again.

AWS SigV4, verified against the AWS test suite vectors. The signature covers
the hash of a body of at most 1 MiB; a larger body fails with
`ErrBodyTooLarge` unless `UnsignedPayload` is set, which only an S3 `Service`
accepts.

```go
signer, err := cred.NewSigV4(&cred.SigV4Config{
    AccessKey: accessKeyID,
    SecretKey: secretKey,
    Region:    "us-east-1",
    Service:   "execute-api",
})
if err != nil {
    log.Fatal(err)
}
client := &http.Client{Transport: cred.NewTransport(nil, signer)}
```

## Secrets: `secret`

```go
import "github.com/ubyte-source/go-authware/v2/secret"
```

A non-zero `secret.Value` renders as `***` through `fmt`, `log/slog`, JSON
and text encoders when used directly or in an exported field, and the zero
Value as nothing; `fmt` prints its type for `%T`, and a pointer address,
never the secret, for `%p`, for `%w` and inside an unexported field.
`Reveal()` is the only way to read it and `Equal` compares in constant time
(Values are not comparable with `==`).

```go
p := secret.Static(map[string]string{"db_password": "p4ss"})
v, err := p.Secret(ctx, "db_password")
```

- `secret.Static(map)`: an in-memory copy.
- `secret.Env(prefix)`: key `K` reads `strings.ToUpper(prefix + K)`.
- `secret.File(path)`: a flat JSON object of string members in a regular
  file, read once. It fails with an error wrapping `ErrInvalidFile` on a path
  that is not a regular file, a file that cannot be opened, read or closed
  (whose error it wraps too), over 1 MiB, truncated, with trailing data or
  with a duplicate key.
- `secret.MapResolver(m, fallback)`: one provider per tenant.

A missing key, or one whose value is empty, wraps `ErrNotFound`. Every
provider and resolver is safe for concurrent use, and `Resolver.For` never
returns nil. Vault or cloud secret managers are not bundled: implement
`secret.Provider` in your own binary.

```go
r := secret.MapResolver(map[string]secret.Provider{
    "alpha": secret.Static(alphaSecrets),
    "beta":  secret.Env("BETA_"),
}, secret.Static(defaults))
tenantID := "alpha"
v, err := r.For(tenantID).Secret(ctx, name)
```

## Anti-replay signing: `replay`

```go
import "github.com/ubyte-source/go-authware/v2/replay"
```

Three headers carry the envelope: `X-Auth-Timestamp` (Unix seconds),
`X-Auth-Nonce` (16 random bytes, hex) and `X-Auth-Signature` (hex
HMAC-SHA256). The signed input joins six lines: method, host with ASCII
letters lowercased and without an IPv6 zone (net/http drops it from the
wire), request URI (escaped path and raw query), hex SHA-256 of the body,
timestamp and nonce. Sign the host and URI the verifier receives: a proxy
that rewrites either breaks verification.

```go
const capacity, window = 8192, 5 * time.Minute
key := secret.New("an example key of at least 32 bytes")

store, err := replay.NewMemoryStore(capacity)
if err != nil {
    log.Fatal(err)
}
verifier, err := replay.NewVerifier(key, store, replay.WithWindow(window))
if err != nil {
    log.Fatal(err)
}
mux.Handle("/api/", verifier.Middleware(apiHandler))

signer, err := replay.NewSigner(key)
if err != nil {
    log.Fatal(err)
}
client := &http.Client{Transport: cred.NewTransport(nil, signer)}
```

- `NewSigner` draws each nonce from `crypto/rand` and stamps the time of
  `time.Now`; `NewVerifier` takes `WithWindow` (whole seconds from 1s to
  1h, default 5m) and reads the same clock.
- `NewSigner`, `NewVerifier` and `NewMemoryStore` refuse a short key, a
  window out of range, a nil store or a capacity below 1 with an error
  wrapping `ErrInvalidConfig`.
- `Verify` requires each header exactly once in canonical form, checks the
  timestamp window, accepts a body of at most 1 MiB (and restores it),
  compares the MAC in constant time and only then records the nonce,
  checking the window again once the store finds the nonce fresh. Request
  failures wrap `ErrRejected`.
- `Verifier.Middleware` serves the next handler a bodiless request itself,
  and a copy of a request with a body carrying the verified body, and
  changes no field of the caller's request. It answers rejected requests
  401 `unauthorized` with a `WWW-Authenticate` challenge naming
  `X-Auth-Signature`, and 503 `service unavailable` with `Retry-After: 1`
  when the store fails; call `Verify` for the cause.
- `NewMemoryStore(capacity)` is an in-process store ordered by expiry that
  reads time from `time.Now`; full of live nonces it fails closed with
  `ErrStoreFull`, so size it above peak signed requests per second times
  twice the window plus one second, the longest a nonce stays live. A fleet
  of verifiers needs a shared `NonceStore`.

## Benchmarks

Medians of six samples of `go test -run '^$' -bench . -benchmem -count=6`
with Go 1.25.9 on an Intel Xeon Gold 6442Y at a load average below 10.
Tokens carry `"typ":"JWT"`, and cached tokens expire.

| Package    | Benchmark                                        |   ns/op |  B/op | allocs/op |
|------------|--------------------------------------------------|--------:|------:|----------:|
| root       | `StaticAuthenticator` shared token (43 bytes)    |     156 |     0 |         0 |
| root       | `StaticAuthenticator` shared key (64 bytes)      |     156 |     0 |         0 |
| root       | `MTLSAuthenticator` common name                  |      52 |    80 |         1 |
| root       | `MTLSAuthenticator` subject DN                   |     970 |   440 |        15 |
| root       | `MTLSAuthenticator` SPKI pin                     |     668 |   240 |         8 |
| root       | `OAuthAuthenticatorValidateToken` RS256          |   33393 |  1635 |        12 |
| root       | `OAuthAuthenticatorValidateToken` RS384          |   34913 |  1635 |        12 |
| root       | `OAuthAuthenticatorValidateToken` RS512          |   34476 |  1635 |        12 |
| root       | `OAuthAuthenticatorValidateToken` PS256          |   34839 |  1587 |        16 |
| root       | `OAuthAuthenticatorValidateToken` PS384          |   35811 |  1715 |        16 |
| root       | `OAuthAuthenticatorValidateToken` PS512          |   35333 |  1747 |        16 |
| root       | `OAuthAuthenticatorValidateToken` ES256          |   77640 |   850 |        13 |
| root       | `OAuthAuthenticatorValidateToken` ES384          |  591542 |  1082 |        20 |
| root       | `OAuthAuthenticatorValidateToken` ES512          | 1585967 |  1504 |        20 |
| root       | `OAuthAuthenticatorValidateToken` EdDSA          |   48078 |   256 |         3 |
| root       | `OAuthAuthenticatorValidateToken` HS256          |    1993 |   257 |         3 |
| root       | `OAuthAuthenticatorValidateToken` HS384          |    2541 |   257 |         3 |
| root       | `OAuthAuthenticatorValidateToken` HS512          |    2549 |   257 |         3 |
| root       | `GateAuthenticate` static token                  |     139 |     0 |         0 |
| root       | `GateAuthenticate` OAuth token                   |    2118 |   224 |         3 |
| root       | `GateAuthenticate` malformed token               |     557 |   120 |         3 |
| root       | `GateMiddleware` accept                          |    2552 |   593 |         5 |
| root       | `GateMiddleware` deny                            |    1288 |   408 |         6 |
| root       | `GateMiddleware` static deny                     |     617 |   240 |         3 |
| root       | `GateCheckHandler` bearer                        |     274 |    64 |         1 |
| root       | `GateCheckHandler` OAuth                         |    2512 |   337 |         5 |
| root       | `GateCheckHandler` bearer deny                   |     649 |   304 |         4 |
| root       | `GateCheckHandler` OAuth deny                    |    1396 |   472 |         7 |
| root       | `GateRequire` any scope                          |      27 |     0 |         0 |
| root       | `GateRequire` all scopes                         |      20 |     0 |         0 |
| root       | `GateRequire` deny                               |      98 |    48 |         1 |
| root       | `GateRequire` no identity                        |     426 |   224 |         3 |
| root       | `KeySourceKey` known kid                         |      32 |     0 |         0 |
| root       | `KeySourceKey` unknown kid                       |      82 |     0 |         0 |
| root       | `KeySourceKeyParallel` unknown kid               | 4.0–4.1 |     0 |         0 |
| root       | `KeySourceGet` (parallel)                        | 0.5–1.8 |     0 |         0 |
| root       | `LookupAlgorithm`                                |      15 |     0 |         0 |
| root       | `Identity` Subject                               |     1.8 |     0 |         0 |
| root       | `Identity` Mode                                  |     1.8 |     0 |         0 |
| root       | `Identity` Scopes (one scope)                    |      29 |    16 |         1 |
| root       | `Identity` HasScope                              |     2.5 |     0 |         0 |
| root       | `Identity` PeerCertificate                       |     1.8 |     0 |         0 |
| root       | `Identity` Claim (20-byte value)                 |     192 |    16 |         1 |
| root       | `Identity` ClaimString (20-byte value)           |     152 |     0 |         0 |
| root       | `Identity` ClaimInt64                            |      60 |     0 |         0 |
| root       | `Identity` ClaimFloat64                          |     145 |     0 |         0 |
| root       | `Identity` ClaimBool                             |     163 |     0 |         0 |
| root       | `HasClaim` string                                |     154 |     0 |         0 |
| root       | `HasClaim` int64                                 |      58 |     0 |         0 |
| root       | `FacadeEndpoints`                                |      18 |     0 |         0 |
| root       | `SecurityHeaders`                                |     127 |    48 |         1 |
| root       | `NewRedactor` (log record)                       |     832 |     0 |         0 |
| root       | `RedactHeader` (default names)                   |     187 |    32 |         2 |
| `cred`     | `CachedSourceToken` (hit, expiring token)        |      65 |     0 |         0 |
| `cred`     | `TokenApply` (1.5 KiB token)                     |     410 |  1808 |         2 |
| `cred`     | `AsSigner` (cached token)                        |     180 |    16 |         1 |
| `cred`     | `NewTransport` plain (1.5 KiB token)             |     500 |  1024 |         6 |
| `cred`     | `NewTransport` renewing (1.5 KiB expiring token) |     572 |  1024 |         6 |
| `cred`     | `SigV4Sign`                                      |    3126 |   730 |        13 |
| `cred`     | `SigV4SignBody` (4 KiB s3 PUT, STS)              |    4786 |  1938 |        18 |
| `cred`     | `WriteLowerName/writeLowerName` (4 names)        |     306 |   128 |         2 |
| `cred`     | `WriteLowerName/strings.ToLower` (4 names)       |     866 |   144 |         5 |
| `cred`     | `AppendQueryComponent/appendQueryComponent`      |     258 |     0 |         0 |
| `cred`     | `AppendQueryComponent/url` (QueryUnescape+QueryEscape) |     601 |   128 |         3 |
| `cred`     | `HexString/hexString` (SHA-256 sum)              |     140 |    64 |         1 |
| `cred`     | `HexString/hex.EncodeToString` (SHA-256 sum)     |     142 |   128 |         2 |
| `cred`     | `JoinLines/joinLines` (IAM canonical request)    |     293 |   256 |         1 |
| `cred`     | `JoinLines/strings.Join` (IAM canonical request) |     935 |   512 |         2 |
| `jsonobj`  | `Iterate`                                        |     206 |     0 |         0 |
| `syntax`   | `AppendSegment`                                  |     181 |     0 |         0 |
| `keyedmac` | `MACSum` (43-byte message)                       |     183 |     0 |         0 |
| `replay`   | `SignerSign` no body                             |    1201 |   160 |         2 |
| `replay`   | `SignerSign` 4 KiB body                          |    3996 |   209 |         4 |
| `replay`   | `SignerSignParallel`                             |     184 |   168 |         2 |
| `replay`   | `VerifierVerify` no body                         |     707 |     0 |         0 |
| `replay`   | `VerifierVerify` 4 KiB body                      |    4292 |  4944 |         3 |
| `replay`   | `VerifierVerifyReplayedParallel`                 |     378 |     3 |         0 |
| `replay`   | `VerifierMiddleware` no body                     |    1114 |     0 |         0 |
| `replay`   | `VerifierMiddleware` no body parallel            |     283 |     1 |         0 |
| `replay`   | `MemoryStoreSeen`                                |     242 |    48 |         1 |
| `replay`   | `MemoryStoreSeenFreshParallel`                   |     500 |    53 |         1 |
| `replay`   | `MemoryStoreSeenReplayedParallel`                |     117 |     0 |         0 |
| `replay`   | `AppendRequestURI` appendRequestURI              |      47 |     0 |         0 |
| `replay`   | `AppendRequestURI` URL.RequestURI                |      94 |    16 |         1 |
| `replay`   | `AppendLower` appendLower                        |      20 |     0 |         0 |
| `replay`   | `AppendLower` strings.ToLower                    |      89 |    16 |         1 |
| `replay`   | `ExpiryHeap` expiryHeap (1024 entries)           |  170586 |     0 |         0 |
| `replay`   | `ExpiryHeap` container/heap (1024 entries)       |  216839 |     0 |         0 |
| `secret`   | `Value` Reveal (1 KiB secret)                    |     1.9 |     0 |         0 |
| `secret`   | `Value` Equal (1 KiB secret)                     |     363 |     0 |         0 |

`KeySourceGet` and `KeySourceKeyParallel` call from 32 goroutines at once
and divide the wall time among them; where they land on the cores moves each
sample, so their rows give the lowest and the highest of the six.

## Project layout

```
go-authware/
├── doc.go, doc_test.go        # package documentation, shared test fixtures
├── *.go ↔ *_test.go           # Gate, modes, JWT, discovery, facade, hardening
├── internal/
│   ├── flight/                # detached single-flight
│   ├── jsonobj/               # strict JSON objects through go-jsonfast
│   ├── keyedmac/              # pooled HMAC states of one key
│   ├── netguard/              # outbound URL policy, no-redirect client, bounded bodies and digests
│   ├── oauthwire/             # OAuth token requests, responses, errors and parameter names
│   ├── problems/              # configuration problems joined under one sentinel, scope tokens and lists
│   ├── reply/                 # plain-text 401, 403 and 503 answers
│   ├── retry/                 # the 30s backoff after a failed fetch
│   └── syntax/                # URI, header, scope and compact JWS rules
├── cred/                      # outbound credentials
├── secret/                    # secret values and providers
├── replay/                    # anti-replay signing
└── .github/                   # CI workflows, CodeQL config, Dependabot
```

Every code file `foo.go` has one `foo_test.go` holding all of its tests,
benchmarks, fuzz targets and examples; `doc.go` has none, and `doc_test.go`
holds only shared fixtures.

## Development

```bash
make ci          # modcheck, vet, lint, vuln, deadcode, test, race, bench-smoke, cover
make final       # fmtcheck, ci, nilaway, race-repeat, fuzz-final, testtime, treecheck, on an idle machine
make bench       # every benchmark with allocations
make fuzz        # every fuzz target (or FUZZ_TARGETS=pkg:Target), FUZZTIME each (default 30s)
make fuzz-list   # every fuzz target as the JSON array of the fuzz workflow
make help        # every target
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the conventions and
[SECURITY.md](SECURITY.md) for the security policy.

## Security

The threat model, the defenses the code enforces, its limits and the
verification gates are in [SECURITY.md](SECURITY.md). Report
vulnerabilities through GitHub's private reporting flow described there.

## Dependencies

```
github.com/ubyte-source/go-jsonfast v0.3.0
```

No `golang.org/x/oauth2`, no cloud SDKs: every protocol is implemented
against the standard library, with JSON through go-jsonfast.

## License

MIT, see [LICENSE](LICENSE).

## Authors

- **Paolo Fabris**, [ubyte.it](https://ubyte.it/)

## Support

If go-authware is useful for your services, consider supporting the work:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-orange?style=for-the-badge&logo=buy-me-a-coffee)](https://coff.ee/ubyte)
