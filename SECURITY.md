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

## Scope

go-authware is an HTTP authentication library. Security concerns include:

- Timing side-channels in token comparison (mitigated by `crypto/subtle`).
- JWT signature bypass via algorithm confusion.
- JWKS endpoint SSRF or cache poisoning.
- Denial of service via crafted JWT headers or payloads.
- Memory safety of `unsafe.Slice` usage for zero-alloc comparisons.

## Design Principles

- All secret comparisons use `crypto/subtle.ConstantTimeCompare`.
- JWT algorithm is verified against the key type before signature check.
- JWKS refresh is serialized to prevent thundering herd.
- Minimal external dependencies — stdlib plus [go-jsonfast](https://github.com/ubyte-source/go-jsonfast).
