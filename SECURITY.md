# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x (`github.com/ubyte-source/go-authware/v2`), latest release | :white_check_mark: |

## Fix Releases

Every security fix ships as a patch release of the supported major
version, together with a GitHub Security Advisory naming the affected
version range, so that `govulncheck` and Dependabot flag older pins. The
same change set bumps the known consumers of the library to the fixed
release.

## Reporting a Vulnerability

1. **Do not** open a public GitHub issue.
2. Use GitHub's private vulnerability reporting (Security, Report a
   vulnerability).
3. Include a description, steps to reproduce and the impact.
4. Receipt is acknowledged within 48 hours, with a fix timeline.

## Threat Model

go-authware sits between an HTTP server and untrusted clients, and calls
identity providers (JWKS, discovery, token endpoints) and cloud metadata
services. It defends against:

- Forged, expired, mis-addressed or ID tokens presented as access tokens.
- Algorithm confusion (`alg=none`, HMAC keyed with a public key, alg and
  key type mismatch) and key injection through JOSE headers.
- Hostile or compromised discovery documents steering fetches or
  credentials elsewhere (off-origin endpoints, redirects, userinfo URLs).
- Outbound credentials following a redirect to another origin.
- Configurations that silently disable or never match a check.
- Plaintext transport of signing material and client credentials.
- Timing side channels in secret comparison.
- Header and log injection through attacker-controlled claims.
- Resource exhaustion through oversized tokens, bodies or nested JSON.
- Replayed signed requests.
- Open redirects and parameter smuggling through the authorization server
  facade.
- Secrets leaking through logs, `fmt` or JSON encoding.

## Implemented Defenses

- **Outbound URL policy.** Issuer, JWKS, discovered endpoints, facade
  upstream and `cred` token URLs must be `https`, or `http` to `localhost`,
  `127.0.0.0/8` or `::1`, and must not carry userinfo. Only `cred` cloud
  metadata endpoints may also be plain `http` to a link-local address or
  `metadata.google.internal`. Every outbound client is a copy of the
  configured one that refuses redirects, so the checked URL is the one
  contacted. Error texts never echo a URL with its userinfo.
  `CheckOutboundURL` applies the same policy to a service's own URLs.
- **Outbound signing.** `cred.NewTransport` signs a request only while every
  hop of its redirect chain stayed on the origin of the first one; a chain
  that left it goes unsigned, also after it comes back.
- **Fail-closed configuration.** `New` refuses a setting in the section of a
  mode other than the selected one, a bearer token or API key that cannot
  travel in a header, a `PublicURL` that is not a canonical origin (lower
  case, no default port) and an mTLS subject that is not written as
  `pkix.Name.String` renders it, with the value of a dotted type as `#` and
  the hex of its DER on every Go version.
- **Discovery pinning.** The discovered `issuer` must equal the configured
  issuer exactly, and `jwks_uri`, `authorization_endpoint` and
  `token_endpoint` must share the issuer's scheme, host and port.
- **Strict JWT parsing.** Tokens over 16 KiB are refused before decoding;
  segments are strict base64url; header and payload are UTF-8 JSON objects
  without duplicate members or lone surrogate escapes, nested at most 32
  levels; `crit` rejects the token; `jku`, `x5u`, `jwk` and `x5c` are never
  used.
- **Algorithm binding.** One table binds each accepted alg (RS, PS, ES,
  EdDSA, and HS in HMAC mode only) to its key type, curve and hash. JWKS
  mode refuses HS*, HMAC mode refuses everything else and an HS alg whose
  hash is longer than the secret, a JWK `alg` must equal the token `alg`,
  ECDSA signatures must be fixed-length R||S on the pinned curve and PSS
  salts must equal the hash length.
- **Key hygiene.** JWKS keys are skipped unless usable for verification:
  RSA 2048 to 8192 bits with an odd exponent from 3 to 2^31-1, EC points on
  P-256, P-384 or P-521 with full-length coordinates, 32-byte Ed25519 keys,
  `use` absent or `sig`, `key_ops` absent or containing `verify`. A token
  without `kid` needs exactly one compatible key.
- **Claim policy.** `iss` exact, `aud` required, `exp` required with
  `ClockSkew`, `nbf` and `iat` bounded, time claims numbers from 0 to 2^53,
  `at_hash` or `c_hash`, or `nonce` without any of `scope`, `scp` or
  `roles`, refused as ID tokens, `RequireAccessTokenType` for `at+jwt`.
- **Key availability.** Key and issuer metadata fetches are single-flighted,
  detached from the caller and bounded by `FetchTimeout`. Stale keys and
  metadata are served while fetches fail until 24h after their fetch, so a
  `KeysCacheTTL` of 24h or more serves nothing stale; failed fetches back
  off for 30s, and a missing key forces at most one refresh every 30s,
  which the tokens that need the key wait for. Unavailable keys answer 503
  with `Retry-After`, never a verification bypass, and so does a missing key
  when its forced refresh fails or a failed fetch backs off;
  `Config.ErrorLog` receives every failed fetch, also while stale values are
  served.
- **Constant-time comparison.** Bearer tokens and API keys compare SHA-256
  digests with `crypto/subtle`, once the `Authorization` scheme matched as
  an ASCII token; HMAC signatures, replay MACs and `secret.Value.Equal` are
  constant time.
- **Header and log injection.** Challenge parameters are quoted-string
  escaped and control bytes blanked; `CheckHandler` blanks control bytes
  in identity headers and sends `Cache-Control: no-store`. Error bodies are
  fixed words; client-visible error descriptions are fixed texts.
- **Facade.** `/authorize` validates `redirect_uri`, `response_type=code`
  and an S256 PKCE challenge before redirecting, and answers anything else
  with 400 JSON instead of a redirect. Repeated parameters and request
  objects are refused, only an allowlist of parameters is relayed with
  `client_id` pinned, so client secrets, assertions, `audience` and `claims`
  never reach the issuer, scopes of other resources and malformed scopes are
  refused, a scope prefix or upstream resource that is not well formed is a
  configuration error, `/token` accepts only the code (with a well-formed
  `code_verifier`) and refresh grants, with a valid `redirect_uri` when one
  is sent, and responses carrying credentials are `no-store`. Upstream PKCE
  enforcement remains recommended, since codes can be obtained from the
  upstream authorization endpoint directly.
- **Metadata origin.** Protected resource and authorization server
  metadata take their origin from `PublicURL`, or from the request with
  `X-Forwarded-Proto` trusted only when `TrustForwardedProto` is set;
  request-derived documents are `private` and vary by host and scheme.
- **mTLS.** Subjects match only on a chain verified by the TLS layer; SPKI
  pins bind the key itself, and a pin without a verified chain reports the
  subject `sha256/<base64 pin>`, never the certificate's self-asserted DN,
  so `HasSubject` and `X-Auth-Subject` cannot be spoofed through a pinned
  key. A subject repeating its common name or serial number, of which
  `pkix.Name` keeps only the last, matches nothing. A refused certificate
  gets 403 without a challenge.
- **Secrets.** A non-zero `secret.Value` renders as `***` through `fmt`,
  `log/slog`, JSON and text encoding, the zero Value as nothing, but `fmt`
  prints its type for `%T` and the address it holds, never the secret, for
  `%p`, for `%w` and inside an unexported field; `NewRedactor` and
  `RedactHeader` mask sensitive log attributes and headers, and
  `NewRedactor` logs URLs without their password or the values of
  credential query and fragment parameters, URL-valued headers
  (`Location`, `Content-Location`, `Referer`) included, and requests and
  responses as method or status, masked URL and masked header;
  `cred.Token` logs only its type and expiry.
- **Anti-replay.** `replay` binds method, host, request URI, body digest,
  timestamp and nonce under HMAC-SHA256, checks the MAC before recording
  the nonce and the window again after it, so a replay whose body outlasts
  the nonce's record is refused, and its memory store fails closed when
  full instead of evicting live nonces.
- **Refresh token rotation.** `cred.NewRefreshToken` serializes exchanges
  and saves a rotated refresh token before returning the access token or
  presenting it; while the store fails to save it, exchanges return no token.
- **Strict JSON.** Every token response, OAuth error body, metadata
  document, JWKS, JWT, client registration request and secrets file meets
  one strict rule of
  [go-jsonfast](https://github.com/ubyte-source/go-jsonfast), checked in one
  pass: invalid UTF-8, lone surrogate escapes, a member name repeated in any
  object, trailing data and nesting beyond 32 levels are refused. An error
  body that is not a strict OAuth error object is kept as the description;
  code and description are cut to 256 bytes. Production code does not import
  `encoding/json` or `unsafe`.

## Operational Limits

| Parameter | Limit |
|---|---|
| JWT length | 16 KiB |
| JWKS body | 1 MiB |
| Discovery document | 256 KiB |
| JSON nesting | 32 levels |
| Facade `/register` and `/token` request bodies | 64 KiB |
| Facade `/token` `code_verifier` | 43 to 128 unreserved characters |
| Token endpoint response (`cred`, facade relay) | 1 MiB |
| Cloud metadata response | 1 MiB |
| Token endpoint, metadata and discovery error answer read (`cred`, root) | 4 KiB |
| `cred.NewTransport` 401 answer drained before its retry | 4 KiB |
| Token endpoint error code and description kept | 256 bytes each |
| Token lifetime | `expires_in` positive, clamped to 1ns to 1 year; an absolute expiry positive and capped at 1 year from now |
| Bearer token, API key, replay key | at least 32 bytes |
| HMAC secret | at least 32 bytes; 48 for HS384, 64 for HS512 |
| Clock skew (`ClockSkew`) | 30s default |
| Key cache TTL (`KeysCacheTTL`) | 5m default |
| Fetch timeout (`FetchTimeout`, `Timeout` of each `cred` source) | 10s default |
| Stale keys and issuer metadata served while fetches fail | until 24h after their fetch |
| Backoff after a failed key or metadata fetch, or `cred.CachedSource` refresh | 30s |
| Forced key refresh interval | 30s minimum |
| Time claims | 0 to 2^53 seconds |
| RSA modulus | 2048 to 8192 bits |
| RSA exponent | odd, 3 to 2^31-1 |
| EC curves | P-256, P-384, P-521 |
| `replay` body read | 1 MiB |
| Secrets file (`secret.File`) | 1 MiB, a regular file |
| `cred.NewSigV4` signed body | 1 MiB; `UnsignedPayload` (S3 services) above |
| `replay` window | 1s to 1h, 5m default |
| `replay.NewMemoryStore` capacity | at least 1 live nonce; a full store fails closed |
| `replay` canonical input kept between calls | 4 KiB per pooled state; a larger buffer is dropped |
| `cred.NewCachedSource` refresh skew | 30s default, at most half the token lifetime |

## Continuous Verification

- `make ci` runs every gate below but CodeQL and fuzzing, and the workflows
  run the same Makefile targets.
- `make modcheck` (`go mod download`, `go mod verify`, `go mod tidy -diff`),
  `make test` (the tests with `-shuffle=on` and their allocation counts),
  `make cover` (the tests with `-race` and `-shuffle=on`, failing below 100%
  statement coverage) and `make bench-smoke` (100 iterations of every
  benchmark) on Go 1.25.14 and Go 1.27.1 (`test.yml`); `make vet`
  (`lint.yml`).
- `golangci-lint` v2.14.0, built with Go 1.27.1 (`lint.yml`, `make lint`),
  with the repository `.golangci.yml`: every linter of its enable list and the
  `gofmt` and `goimports` formatters, `gosec` included, test files linted. Its
  part shared with go-jsonfast and mcp-server leaves out `run.go` and the
  rules each repository adds; here the `depguard` rule `production` denies
  `encoding/json` and `unsafe` to the production files, and the
  `gomodguard_v2` allowlist admits go-jsonfast alone. govet's `fieldalignment`
  is off, since struct fields are grouped by meaning. `revive` runs every
  rule, `add-constant` and `line-length-limit` at 120 columns included, and
  `unhandled-error` skips the calls errcheck excludes by default. `wrapcheck`
  lets pass the errors of go-authware's internal packages and those a
  decorator forwards from its delegate, and `depguard` and `gomodguard_v2`
  block assertion libraries. Every `nolint` directive names the linter and
  gives a reason.
- `deadcode -test` v0.50.0 (`lint.yml`, `make deadcode`): no function that
  neither a test nor an entry point reaches.
- Every action is pinned by commit with its version, and every workflow has
  top-level permissions no wider than `contents: read` (CodeQL's in
  `security.yml`), no `pull_request_target` trigger and checkouts without
  persisted credentials. Every `nolint` directive names the linter and gives
  a reason.
- `govulncheck` v1.8.0 and CodeQL with the `security-and-quality` suite
  (`security.yml`).
- Native fuzzing (`fuzz.yml`, weekly, and `make fuzz`) over every `Fuzz`
  function in the module, listed by `make fuzz-list`: token parsing
  (`FuzzParseJWS`, `FuzzParseHeader`, `FuzzSplitJWS`, `FuzzAppendSegment`),
  signatures of every algorithm against the standard library
  (`FuzzVerifySignature`, `FuzzEncodeDER`), key sets (`FuzzParseJWKS`), claims
  (`FuzzClaimPolicyValidateClaims`, `FuzzDecodeClaimValue`), end-to-end
  validation (`FuzzOAuthAuthenticatorValidateToken`), the Authorization header
  (`FuzzAuthorizationCredential`), `X-Forwarded-Proto` (`FuzzForwardedProto`),
  the `X-Original-URI` request target (`FuzzOriginalPath`), mTLS subject names
  (`FuzzSubjectDN`), discovery documents (`FuzzFetchMetadata`), the facade
  authorization redirect, token relay, upstream token answers and client
  registration (`FuzzFacadeServeAuthorize`, `FuzzFacadeServeToken`,
  `FuzzFacadeServeTokenUpstreamAnswer`, `FuzzRedirectURIs`), header sanitizing
  (`FuzzSanitizeHeaderValue`), the environment list splitter
  (`FuzzSplitList`), the strict JSON objects (`FuzzIterate`), the outbound URL
  policy (`FuzzCheck`), outbound body digests (`FuzzDigesterDigest`), token
  and error answers (`FuzzParseTokenResponse`, `FuzzErrorMembers`,
  `FuzzParseMSIResponse`, `FuzzParseIDToken`, `FuzzParseAccessToken`,
  `FuzzParseEpoch`), SigV4 signing (`FuzzSigningHost`, `FuzzCanonicalHeaders`,
  `FuzzCanonicalQuery`, `FuzzAppendQueryComponent`, `FuzzAWSEncodePath`),
  secrets files (`FuzzDecodeFile`), replay signing and verification
  (`FuzzAppendHost`, `FuzzAppendRequestURI`, `FuzzVerifierVerify`).
