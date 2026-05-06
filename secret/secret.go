package secret

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/ubyte-source/go-jsonfast"
)

// ErrSecretNotFound is returned when the requested key is absent from
// the backing store.
var ErrSecretNotFound = errors.New("secret: not found")

// Provider returns a secret value for a given key. Implementations
// must be safe for concurrent use.
type Provider interface {
	Secret(ctx context.Context, key string) (string, error)
}

// Resolver chooses a Provider for a tenant identifier.
type Resolver interface {
	For(tenant string) Provider
}

var (
	_ Provider = staticProvider(nil)
	_ Provider = envProvider("")
	_ Provider = notFoundProvider{}
	_ Resolver = (*mapResolver)(nil)
)

// Static returns a Provider backed by an in-memory map. The map is
// copied at construction time.
func Static(m map[string]string) Provider {
	cp := make(map[string]string, len(m))
	maps.Copy(cp, m)
	return staticProvider(cp)
}

type staticProvider map[string]string

func (s staticProvider) Secret(_ context.Context, key string) (string, error) {
	if v, ok := s[key]; ok {
		return v, nil
	}
	return "", fmt.Errorf("%w: %q", ErrSecretNotFound, key)
}

// Env returns a Provider that reads values from environment variables.
// For a request key K it reads strings.ToUpper(prefix + K).
func Env(prefix string) Provider {
	return envProvider(prefix)
}

type envProvider string

func (e envProvider) Secret(_ context.Context, key string) (string, error) {
	full := strings.ToUpper(string(e) + key)
	if v, ok := os.LookupEnv(full); ok {
		return v, nil
	}
	return "", fmt.Errorf("%w: env %q", ErrSecretNotFound, full)
}

// File returns a Provider that reads a flat JSON object once at
// construction. On-disk changes are not observed.
func File(path string) (Provider, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("secret: read %q: %w", path, err)
	}
	m, err := decodeFlatJSON(data)
	if err != nil {
		return nil, fmt.Errorf("secret: parse %q: %w", path, err)
	}
	return staticProvider(m), nil
}

// MapResolver returns a Resolver that picks Provider by tenant. When
// tenant is absent, fallback is returned; nil falls back to
// [ErrSecretNotFound].
func MapResolver(m map[string]Provider, fallback Provider) Resolver {
	cp := make(map[string]Provider, len(m))
	maps.Copy(cp, m)
	return &mapResolver{providers: cp, fallback: fallback}
}

type mapResolver struct {
	providers map[string]Provider
	fallback  Provider
}

func (r *mapResolver) For(tenant string) Provider {
	if p, ok := r.providers[tenant]; ok {
		return p
	}
	if r.fallback != nil {
		return r.fallback
	}
	return notFoundProvider{}
}

type notFoundProvider struct{}

func (notFoundProvider) Secret(_ context.Context, key string) (string, error) {
	return "", fmt.Errorf("%w: %q", ErrSecretNotFound, key)
}

// decodeFlatJSON parses a flat JSON object into a map[string]string.
// Non-string values or non-object roots produce an error.
func decodeFlatJSON(data []byte) (map[string]string, error) {
	if len(data) == 0 {
		return nil, errors.New("empty body")
	}
	trimmed := trimJSONWhitespace(data)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		return nil, errors.New("not a JSON object")
	}
	out := make(map[string]string, 8)
	var iterErr error
	jsonfast.IterateFields(trimmed, func(key, value []byte) bool {
		k, v, err := decodeFlatJSONField(key, value)
		if err != nil {
			iterErr = err
			return false
		}
		out[k] = v
		return true
	})
	if iterErr != nil {
		return nil, iterErr
	}
	return out, nil
}

func decodeFlatJSONField(key, value []byte) (name, decoded string, err error) {
	if len(key) < 2 || key[0] != '"' || key[len(key)-1] != '"' {
		return "", "", fmt.Errorf("malformed key %q", key)
	}
	name = string(key[1 : len(key)-1])
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", "", fmt.Errorf("non-string value for key %q", name)
	}
	decoded, ok := jsonfast.DecodeString(value)
	if !ok {
		return "", "", fmt.Errorf("invalid string for key %q", name)
	}
	return name, decoded, nil
}

func trimJSONWhitespace(data []byte) []byte {
	for len(data) > 0 && isJSONSpace(data[0]) {
		data = data[1:]
	}
	for len(data) > 0 && isJSONSpace(data[len(data)-1]) {
		data = data[:len(data)-1]
	}
	return data
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
