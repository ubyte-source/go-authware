// Package secret provides a small interface for fetching credentials
// from a backing store plus three built-in providers (Static, Env,
// File) and a per-tenant Resolver.
//
// The package intentionally bundles no adapters for external secret
// stores; each is a thin wrapper around [Provider] kept in the
// consumer's binary, leaving go-authware dependency-free.
//
//   - [Static] returns secrets from an in-memory map.
//   - [Env] reads from environment variables under a configurable prefix.
//   - [File] reads a flat JSON object once at construction.
//   - [MapResolver] picks a provider per tenant with an optional fallback.
//
// [ErrSecretNotFound] is returned when a key is missing.
package secret
