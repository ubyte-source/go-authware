package problems

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

// List collects the problems of one validation. New builds it, its zero value is
// not ready, and it is not safe for concurrent use.
type List struct {
	sentinel error
	errs     []error
}

// New returns an empty List whose problems wrap sentinel, which must not be nil.
func New(sentinel error) *List {
	return &List{sentinel: sentinel}
}

// Addf records the problem that format and args describe.
func (l *List) Addf(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf("%w: %s", l.sentinel, fmt.Sprintf(format, args...)))
}

// Wrap records err, not nil, as the problem of subject, keeping err matchable.
func (l *List) Wrap(subject string, err error) {
	l.errs = append(l.errs, fmt.Errorf("%w: %s: %w", l.sentinel, subject, err))
}

// Add records err, a problem that wraps the List's sentinel through a sentinel
// of its own; nil records nothing.
func (l *List) Add(err error) {
	l.errs = append(l.errs, err)
}

// NonNegative records d, the named duration, when it is negative.
func (l *List) NonNegative(name string, d time.Duration) {
	if d < 0 {
		l.Addf("%s is negative", name)
	}
}

// ScopeToken records s, the named value, when it is not a scope token.
func (l *List) ScopeToken(name, s string) {
	if !syntax.IsScope(s) {
		l.Addf("%s %q is not a scope token", name, s)
	}
}

// Scopes records every scope of the list that is not a scope token and
// every repeat of an earlier one.
func (l *List) Scopes(scopes []string) {
	for i, s := range scopes {
		l.ScopeToken("scope", s)
		if slices.Contains(scopes[:i], s) {
			l.Addf("scope %q is repeated", s)
		}
	}
}

// Err returns the recorded problems joined, nil when there is none.
func (l *List) Err() error {
	return errors.Join(l.errs...)
}
