# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in go-authware, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Use GitHub's private vulnerability reporting feature, or email the maintainers directly.
3. Include: description, steps to reproduce, and impact assessment.
4. We will acknowledge receipt within 48 hours and provide a fix timeline.

## Threat Model

go-authware sits at the trust boundary between an HTTP server and untrusted
clients. It also makes outbound calls to identity providers (JWKS, OIDC
discovery, token endpoints). The threat model covers:

- Forged or replayed JWTs targeting the inbound authentication path.
- Algorithm-confusion attacks (`alg=none`, HMAC vs RSA cross-use).
- MITM on signing-material delivery (JWKS, OIDC discovery, OAuth proxy).
- Timing side-channels in secret comparison.
- HTTP header injection via attacker-controlled JWT claims.
- Log injection via attacker-controlled request bodies.
- Denial of service via crafted token sizes, nested JSON, or URL parsing.
- Memory safety of `unsafe.Slice` / `unsafe.String` zero-allocation views.
- Cache poisoning of JWKS or OIDC metadata.

## Implemented Defenses

- **HTTPS-only signing material.** JWKS, OIDC discovery, OAuth proxy
  upstreams must use `https://`. Plain `http://` is accepted only for
  loopback hosts (`localhost`, `127.0.0.1`, `::1`) so that test fixtures
  keep working — public-host plaintext is rejected at runtime.
- **NIST SP 800-131A Rev. 2 RSA keys.** Public keys with a modulus
  shorter than 2048 bits are rejected at JWKS load. The exponent must be
  ≥ 65537.
- **Constant-time secret comparison.** Bearer tokens, API keys, mTLS
  SPKI pins, and HMAC-JWT signatures use `crypto/subtle` /
  `crypto/hmac.Equal`.
- **Algorithm-confusion blocked.** HMAC and JWKS verifiers reject
  cross-algorithm tokens; `alg=none` is never accepted; the alg is
  resolved against the key type before signature verification.
- **Header injection defense (CWE-113).** `AuthCheckHandler` sanitises
  every identity-derived response header against CR/LF/control bytes.
- **Log injection defense (CWE-117).** Untrusted request-body fields
  (e.g. DCR `redirect_uris`) are not interpolated into log lines; only
  bounded metadata such as length is logged.
- **JWKS refresh single-flighted.** Refresh attempts are serialized;
  no thundering herd against the upstream IdP.
- **OAuth proxy retry.** Upstream metadata fetch is single-flighted and
  retried on every request until it succeeds — a transient outage at
  startup does not wedge the proxy until restart.
- **No `encoding/json` in production.** Every JSON path uses
  [go-jsonfast](https://github.com/ubyte-source/go-jsonfast) (one
  third-party dependency, fuzzed upstream).
- **Anti-replay primitives.** The `replay` subpackage signs with
  HMAC-SHA256 and binds method, path, timestamp, and nonce; nonces are
  replay-rejected via an LRU+TTL store.

## Operational Limits

The library enforces the following bounds to prevent resource exhaustion:

| Parameter                                          | Limit            |
|----------------------------------------------------|------------------|
| Maximum JWT length                                 | 16 KiB           |
| Pooled JWT decode buffer (header + payload + sig)  | ~12.4 KiB        |
| JWKS response body (read-cap)                      | 1 MiB            |
| OIDC discovery body (read-cap)                     | 256 KiB          |
| OAuth proxy DCR / token request body (read-cap)    | 64 KiB           |
| OAuth proxy upstream token response (read-cap)     | 256 KiB          |
| `replay.Memory` default capacity                   | 8192 entries     |
| `replay` minimum HMAC key length                   | 32 bytes         |
| `replay` default timestamp window                  | 5 minutes        |
| JWKS cache TTL                                     | 5 minutes        |
| JWT clock-skew tolerance                           | 30 seconds       |
| Minimum RSA modulus                                | 2048 bits        |
| Minimum RSA public exponent                        | 65537            |
| Accepted EC curves                                 | P-256, P-384, P-521 |

## Continuous Verification

- `go vet ./...` — clean.
- `go test -race -count=1 ./...` — all pass.
- `golangci-lint run ./...` — 0 issues under a 39-linter strict config
  with no exclusions for test files. `gosec` is part of this run, with
  rule **G704** excluded at the config level (every external URL is
  gated at runtime by `requireHTTPS`, which gosec's flow-insensitive
  taint analysis cannot recognise) and per-line `nolint:gosec` on the
  remaining audited cases (`unsafe.Slice`/`unsafe.String` for
  zero-allocation views, operator-supplied paths, OIDC-discovered
  redirect targets).
- `govulncheck ./...` — no known vulnerabilities.
- Native fuzz suite — 9 targets covering `splitJWT`,
  `parseJWTHeaderDirect`, `extractClaims`, `decodeAlg`,
  `decodeClaimValue`, `sanitizeHeaderValue`, `requireHTTPS`,
  `algorithmConfusion`, and `replay.Verify` — every parser and security
  guard is exercised on millions of mutated inputs without panic.
