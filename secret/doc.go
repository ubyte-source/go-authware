// Package secret carries secret strings and the providers that load them: a
// non-zero [Value] renders as *** through fmt, log/slog and the JSON and text
// encoders, but fmt prints its type for %T and the address it holds for %p, %w and
// in an unexported field; [Value.Reveal] alone reads it back and [Value.Equal]
// compares in constant time, while [Static], [Env], [File] and [MapResolver] build
// the [Provider] and [Resolver] that resolve keys to Values, a missing key or an
// empty value yielding [ErrNotFound]. Every Provider and Resolver of the package
// is safe for concurrent use.
package secret
