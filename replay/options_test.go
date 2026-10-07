package replay

import (
	"errors"
	"testing"
	"time"
)

func TestNewVerifierConfigDefaults(t *testing.T) {
	t.Parallel()
	c, err := newVerifierConfig(nil)
	if err != nil || c.window != windowSeconds*time.Second {
		t.Fatalf("newVerifierConfig(nil) = window %v, %v, want 5m", c.window, err)
	}
}

func TestNewVerifierConfigRejects(t *testing.T) {
	t.Parallel()
	for name, opt := range map[string]VerifierOption{
		"zero window":       WithWindow(0),
		"negative window":   WithWindow(-time.Second),
		"sub-second window": WithWindow(999 * time.Millisecond),
		"fractional window": WithWindow(1500 * time.Millisecond),
		"window over 1h":    WithWindow(time.Hour + time.Second),
	} {
		c, err := newVerifierConfig([]VerifierOption{opt})
		if !errors.Is(err, ErrInvalidOption) || c != (verifierConfig{}) {
			t.Errorf("%s: newVerifierConfig = %+v, %v, want ErrInvalidOption", name, c, err)
		}
	}
}

// TestNewVerifierConfigNilOption skips a nil option and applies the others.
func TestNewVerifierConfigNilOption(t *testing.T) {
	t.Parallel()
	c, err := newVerifierConfig([]VerifierOption{nil, WithWindow(time.Minute), nil})
	if err != nil || c.window != time.Minute {
		t.Fatalf("newVerifierConfig(nil, 1m, nil) = window %v, %v, want 1m", c.window, err)
	}
}

func TestWithWindow(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{time.Second, time.Minute, time.Hour} {
		c, err := newVerifierConfig([]VerifierOption{WithWindow(d)})
		if err != nil || c.window != d {
			t.Errorf("WithWindow(%v) = window %v, %v, want the window", d, c.window, err)
		}
	}
}
