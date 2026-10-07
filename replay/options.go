package replay

import (
	"fmt"
	"time"
)

const (
	defaultWindow    = 5 * time.Minute
	minWindowSeconds = 1
	maxWindowSeconds = 3600
)

type verifierConfig struct {
	window time.Duration
}

// VerifierOption configures [NewVerifier].
type VerifierOption interface {
	applyVerifier(c *verifierConfig)
}

type verifierOption func(c *verifierConfig)

func (o verifierOption) applyVerifier(c *verifierConfig) { o(c) }

// WithWindow sets how far a timestamp may lie from the Verifier's clock: a
// whole number of seconds from 1s to 1h, 5m by default.
func WithWindow(d time.Duration) VerifierOption {
	return verifierOption(func(c *verifierConfig) { c.window = d })
}

// newVerifierConfig applies the non-nil opts to the defaults and validates the result.
func newVerifierConfig(opts []VerifierOption) (verifierConfig, error) {
	c := verifierConfig{window: defaultWindow}
	for _, opt := range opts {
		if opt != nil {
			opt.applyVerifier(&c)
		}
	}
	secs := c.window / time.Second
	if c.window%time.Second != 0 || secs < minWindowSeconds || secs > maxWindowSeconds {
		return verifierConfig{}, fmt.Errorf("%w: window %v", ErrInvalidOption, c.window)
	}
	return c, nil
}
