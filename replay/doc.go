// Package replay implements anti-replay HMAC for HTTP requests.
//
// Each protected request carries three headers:
//
//   - X-Auth-Timestamp — Unix epoch seconds at signing time
//   - X-Auth-Nonce     — 16 random bytes hex-encoded
//   - X-Auth-Signature — hex(HMAC-SHA256(key, method "\n" path "\n" timestamp "\n" nonce))
//
// Body is intentionally not part of the signed input: this package keeps
// signing zero-copy and small. Consumers that need body binding should use
// AWS SigV4 (cred.SigV4) or a custom signer.
//
// # Server side
//
// [Verifier] checks the three headers, the timestamp window, the HMAC, and
// the nonce uniqueness via a [NonceStore]. [Middleware] wraps the verifier
// in an [net/http] handler that returns 401 on failure.
//
// # Client side
//
// [Signer] populates the three headers on an outbound [net/http.Request].
// It implements [github.com/ubyte-source/go-authware/cred.Signer] so it
// composes with [github.com/ubyte-source/go-authware/cred.RoundTripper].
//
// # Stores
//
// [Memory] is an in-memory LRU+TTL store suitable for single-instance
// deployments. Larger fleets should plug in a Redis or distributed store
// implementing [NonceStore].
package replay
