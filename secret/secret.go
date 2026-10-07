package secret

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
	"github.com/ubyte-source/go-authware/v2/internal/netguard"
)

// errPrefix starts the text of every error the package returns.
const errPrefix = "secret: "

// maxFileBytes bounds the secrets file that File reads.
const maxFileBytes = 1 << 20

// errFileTooLarge reports a secrets file over maxFileBytes.
var errFileTooLarge = errors.New("file too large")

var (
	// ErrNotFound reports a key that the provider does not hold, or holds
	// with an empty value.
	ErrNotFound = errors.New(errPrefix + "not found")
	// ErrInvalidFile reports a secrets file that is not a regular file one can read,
	// or that holds anything but one JSON object of uniquely named string members
	// in 1 MiB.
	ErrInvalidFile = errors.New(errPrefix + "invalid file")
)

// Provider holds secrets by key. Implementations must be safe for concurrent use.
type Provider interface {
	// Secret returns the secret stored under key, or an error wrapping ErrNotFound
	// when the Provider holds none.
	Secret(ctx context.Context, key string) (Value, error)
}

// Resolver chooses the Provider of a tenant. Implementations must be safe for
// concurrent use.
type Resolver interface {
	// For returns the Provider of tenant, never nil.
	For(tenant string) Provider
}

// staticProvider holds non-empty secrets by key.
type staticProvider map[string]Value

// Static returns a Provider serving a copy of m; empty values count as
// absent.
func Static(m map[string]string) Provider {
	out := make(staticProvider, len(m))
	for k, v := range m {
		out.set(k, v)
	}
	return out
}

// Secret fails with an error that wraps ErrNotFound and quotes key when s lacks it.
func (s staticProvider) Secret(_ context.Context, key string) (Value, error) {
	if v, ok := s[key]; ok {
		return v, nil
	}
	return Value{}, fmt.Errorf("%w: %q", ErrNotFound, key)
}

// set stores v under key unless it is empty.
func (s staticProvider) set(key, v string) {
	if v != "" {
		s[key] = New(v)
	}
}

// envProvider reads secrets from environment variables under its prefix.
type envProvider string

// Env returns a Provider that reads key K from the environment variable
// strings.ToUpper(prefix + K); an empty variable counts as absent.
func Env(prefix string) Provider {
	return envProvider(prefix)
}

// Secret reads the variable named by the upper-cased prefix and key.
func (e envProvider) Secret(_ context.Context, key string) (Value, error) {
	name := strings.ToUpper(string(e) + key)
	if v := os.Getenv(name); v != "" {
		return New(v), nil
	}
	return Value{}, fmt.Errorf("%w: env %q", ErrNotFound, name)
}

// File returns a Provider holding the string members of the JSON object in the
// regular file at filepath.Clean(path), read once; empty values count as absent.
// Every failure wraps ErrInvalidFile, and the error of a failed open, read or close.
func File(path string) (Provider, error) {
	path = filepath.Clean(path)
	invalid := fmt.Errorf("%w %q", ErrInvalidFile, path)
	// O_NONBLOCK keeps the open of a FIFO or a device from blocking before the
	// type check; ENXIO is the open of a socket or of a device with no driver.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, syscall.ENXIO):
		return nil, fmt.Errorf("%w: not a regular file: %w", invalid, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrInvalidFile, err)
	}
	info, err := f.Stat()
	switch {
	case err != nil:
		err = fmt.Errorf("%w: check file type: %w", invalid, err)
	case !info.Mode().IsRegular():
		err = fmt.Errorf("%w: not a regular file", invalid)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return decodeFile(f, invalid)
}

// decodeFile reads rc, refusing more than maxFileBytes, closes it and holds the
// string members of the JSON object read; every error wraps invalid.
func decodeFile(rc io.ReadCloser, invalid error) (Provider, error) {
	data, err := netguard.ReadClose(rc, 0, maxFileBytes, errFileTooLarge)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", invalid, err)
	}
	return decodeSecrets(string(data), invalid)
}

// decodeSecrets holds copies of the string members of the JSON object doc, so
// that doc is not retained; every error wraps invalid.
func decodeSecrets(doc string, invalid error) (Provider, error) {
	out := make(staticProvider)
	err := jsonobj.Iterate(doc, jsonobj.Refusal(invalid), func(name, value string) error {
		v, notString := jsonobj.String(name, value, invalid)
		if notString != nil {
			return notString
		}
		out.set(strings.Clone(name), strings.Clone(v))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// mapResolver serves the provider of each tenant, else its fallback.
type mapResolver struct {
	providers map[string]Provider
	fallback  Provider
}

// MapResolver returns a Resolver that picks the Provider of a tenant from a
// copy of m, then fallback; a nil Provider in m counts as absent, and with a
// nil fallback unknown tenants find nothing.
func MapResolver(m map[string]Provider, fallback Provider) Resolver {
	if fallback == nil {
		fallback = staticProvider(nil)
	}
	providers := maps.Clone(m)
	maps.DeleteFunc(providers, func(_ string, p Provider) bool { return p == nil })
	return &mapResolver{providers: providers, fallback: fallback}
}

// For returns the provider of tenant, else the fallback.
func (r *mapResolver) For(tenant string) Provider {
	if p, ok := r.providers[tenant]; ok {
		return p
	}
	return r.fallback
}
