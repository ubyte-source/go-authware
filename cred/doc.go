// Package cred provides outbound HTTP credentials.
//
// Two small interfaces shape the package:
//
//   - [TokenSource] produces a [Token]. Implementations cover OAuth2
//     client_credentials, refresh_token grants, Azure Managed Identity,
//     Azure SPN, and GCP Workload Identity.
//   - [Signer] modifies a request in-place. Use it for signing schemes
//     that depend on per-request data (e.g. AWS SigV4).
//
// [Cache] wraps a [TokenSource] with TTL-aware caching. The cache-hit
// path is zero-allocation; concurrent refresh attempts are coalesced
// so the upstream is called at most once per refresh window.
//
// [RoundTripper] composes a [Signer] into an [net/http.RoundTripper]
// that clones the request before signing.
//
// [AsSigner] adapts a [TokenSource] to a [Signer]; [TokenSourceFunc]
// and [SignerFunc] are zero-cost adapters for inline implementations.
package cred
