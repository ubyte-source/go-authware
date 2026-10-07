// Package cred attaches credentials to outbound HTTP requests: a [TokenSource]
// produces a [Token], a [Signer] modifies a request in place, [AsSigner] turns
// a TokenSource into a Signer, [Basic] builds the Token of HTTP Basic
// credentials and [NewTransport] signs a clone of every request a
// [net/http.Client] sends. When the source is an [Invalidator], a 401 answer
// invalidates the token it carried, which [CachedSource] drops at most once
// every 30s, and a request whose body can be replayed is retried once when the
// source yields another token. Failures of AsSigner and NewTransport wrap
// [ErrCredential], so callers can tell them from transport errors.
// [NewCachedSource] memoizes tokens until shortly before they expire; the
// sources cover the OAuth client_credentials and refresh_token grants, Azure
// managed identities and GCE metadata, each exchange bounded by the Timeout of
// its config; [NewSigV4] signs with AWS Signature Version 4, and
// [LoadClientTLS] builds mutual TLS configs, reloading the key pair at an
// interval when asked. Token endpoints must be https, or http to a loopback
// host, and are reached through clients that refuse redirects; cloud metadata
// services may also be plain http on link-local addresses or the GCE metadata
// name. Secrets are held in [secret.Value], which never prints them. Every
// TokenSource, Signer and transport the package returns is safe for concurrent
// use, and a Token that a TokenSource returns may be shared, so its callers
// must not modify it. A CachedSource comes from NewCachedSource; the zero value
// of every other struct type is ready to use, and its methods only read it, so
// it is safe for concurrent use while nothing modifies it.
package cred
