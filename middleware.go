package authware

import (
	"context"
	"net/http"
	"slices"
)

// IdentityFromContext returns the authenticated identity stored in ctx
// by [Middleware]. The returned pointer is read-only.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(*Identity)
	return id, ok
}

// WithIdentity returns a copy of ctx carrying id.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// Middleware authenticates every request, stores the [Identity] in the
// request context on success, and writes a WWW-Authenticate challenge
// on failure.
func Middleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := auth.Authenticate(r)
			if err != nil {
				status, header, message := auth.Challenge(err, "")
				if header != "" {
					w.Header().Set("WWW-Authenticate", header)
				}
				http.Error(w, message, status)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}

// Capability is a predicate over an authenticated [Identity].
type Capability func(*Identity) bool

// RequireCapability admits a request only if every check returns true
// against the identity stored in r.Context. Must be applied after
// [Middleware].
func RequireCapability(checks ...Capability) func(http.Handler) http.Handler {
	if len(checks) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := IdentityFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			for _, check := range checks {
				if !check(id) {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireScopes admits a request only if the identity carries every
// scope listed.
func RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return RequireCapability(HasAllScopes(scopes...))
}

// HasScope matches when scope is present in id.Scopes.
func HasScope(scope string) Capability {
	return func(id *Identity) bool { return slices.Contains(id.Scopes, scope) }
}

// HasAnyScope matches when at least one scope is present.
func HasAnyScope(scopes ...string) Capability {
	if len(scopes) == 0 {
		return alwaysFalse
	}
	return func(id *Identity) bool {
		for _, want := range scopes {
			if slices.Contains(id.Scopes, want) {
				return true
			}
		}
		return false
	}
}

// HasAllScopes matches when every scope is present.
func HasAllScopes(scopes ...string) Capability {
	if len(scopes) == 0 {
		return alwaysTrue
	}
	return func(id *Identity) bool {
		for _, want := range scopes {
			if !slices.Contains(id.Scopes, want) {
				return false
			}
		}
		return true
	}
}

// HasClaim matches when id.Claim(name) equals value.
func HasClaim(name string, value any) Capability {
	return func(id *Identity) bool {
		got, ok := id.Claim(name)
		return ok && got == value
	}
}

// HasMethod matches when id.Method equals m.
func HasMethod(m Mode) Capability {
	return func(id *Identity) bool { return id.Method == m }
}

// HasSubject matches when id.Subject equals subject.
func HasSubject(subject string) Capability {
	return func(id *Identity) bool { return id.Subject == subject }
}

func alwaysTrue(*Identity) bool  { return true }
func alwaysFalse(*Identity) bool { return false }
