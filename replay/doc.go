// Package replay signs outbound HTTP requests with HMAC-SHA256 and rejects replayed
// ones: a [Signer], which implements
// [github.com/ubyte-source/go-authware/v2/cred.Signer], attaches a timestamp, a nonce
// and a signature of the request, and a [Verifier], directly or through its
// Middleware, checks the signature in constant time and the timestamp against a
// window before it records the nonce in a [NonceStore], such as the bounded
// in-process store of [NewMemoryStore]; a fleet of verifiers needs a shared one.
// Signers, Verifiers and memory stores are safe for concurrent use, and only their
// constructors build them. Sign and Verify take requests as net/http builds them,
// with a URL, and Middleware a handler that is not nil. A request has no body when
// its Body is nil or http.NoBody, or when it is a server request, RequestURI set,
// whose ContentLength is 0. Sign hashes a GetBody copy of a body, or swaps a body
// without GetBody for a copy, setting GetBody and ContentLength, or for http.NoBody
// when that read fails; Verify restores a body it reads in full.
package replay
