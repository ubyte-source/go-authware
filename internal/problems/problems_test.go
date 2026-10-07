package problems

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

var (
	// errSentinel is the sentinel the tested problems wrap.
	errSentinel = errors.New("pkg: invalid config")
	// errCause is the cause a problem carries.
	errCause = errors.New("cause")
	// errOwn is a problem that wraps the sentinel through a sentinel of its own.
	errOwn = fmt.Errorf("%w: insecure URL", errSentinel)
)

// A length bound of a problem, and the problems Unwrap returns.
const (
	minBytes       = 32
	joinedProblems = 3
)

func TestListAddf(t *testing.T) {
	t.Parallel()
	l := New(errSentinel)
	l.Addf("%s is shorter than %d bytes", "token", minBytes)
	err := l.Err()
	if want := "pkg: invalid config: token is shorter than 32 bytes"; !errors.Is(err, errSentinel) ||
		err.Error() != want {
		t.Fatalf("Err = %v, want %q wrapping the sentinel", err, want)
	}
}

func TestListWrap(t *testing.T) {
	t.Parallel()
	l := New(errSentinel)
	l.Wrap("issuer", errCause)
	err := l.Err()
	if want := "pkg: invalid config: issuer: cause"; !errors.Is(err, errSentinel) || !errors.Is(err, errCause) ||
		err.Error() != want {
		t.Fatalf("Err = %v, want %q wrapping the sentinel and the cause", err, want)
	}
}

func TestListAdd(t *testing.T) {
	t.Parallel()
	l := New(errSentinel)
	l.Add(nil)
	if err := l.Err(); err != nil {
		t.Fatalf("Err after Add(nil) = %v, want nil", err)
	}
	l.Add(errOwn)
	if err := l.Err(); !errors.Is(err, errOwn) || !errors.Is(err, errSentinel) ||
		err.Error() != "pkg: invalid config: insecure URL" {
		t.Fatalf("Err = %v, want %v as it is, wrapping the sentinel", err, errOwn)
	}
}

func TestListScopes(t *testing.T) {
	t.Parallel()
	l := New(errSentinel)
	l.Scopes([]string{"a", "b:c", "a", "", "d e", "a"})
	want := "pkg: invalid config: scope \"a\" is repeated\n" +
		"pkg: invalid config: scope \"\" is not a scope token\n" +
		"pkg: invalid config: scope \"d e\" is not a scope token\n" +
		"pkg: invalid config: scope \"a\" is repeated"
	if err := l.Err(); !errors.Is(err, errSentinel) || err.Error() != want {
		t.Fatalf("Err = %v, want %q", err, want)
	}
	valid := New(errSentinel)
	valid.Scopes([]string{"openid", "api://app/read"})
	if err := valid.Err(); err != nil {
		t.Fatalf("Err of valid scopes = %v, want nil", err)
	}
}

func TestListScopeToken(t *testing.T) {
	t.Parallel()
	l := New(errSentinel)
	l.ScopeToken("scope prefix", "api://app/")
	if err := l.Err(); err != nil {
		t.Fatalf("ScopeToken(api://app/) = %v, want no problem", err)
	}
	l.ScopeToken("scope prefix", `a"b`)
	if want := `pkg: invalid config: scope prefix "a\"b" is not a scope token`; !errors.Is(l.Err(), errSentinel) ||
		l.Err().Error() != want {
		t.Fatalf("ScopeToken(a\"b) = %v, want %q", l.Err(), want)
	}
}

func TestListErr(t *testing.T) {
	t.Parallel()
	l := New(errSentinel)
	if err := l.Err(); err != nil {
		t.Fatalf("Err of an empty List = %v, want nil", err)
	}
	l.Addf("first")
	l.Add(errOwn)
	l.Wrap("third", errCause)
	var joined interface{ Unwrap() []error }
	if !errors.As(l.Err(), &joined) {
		t.Fatalf("Err = %T, want the joined problems", l.Err())
	}
	got := joined.Unwrap()
	if len(got) != joinedProblems || got[0].Error() != "pkg: invalid config: first" || !errors.Is(got[1], errOwn) ||
		!errors.Is(got[2], errCause) {
		t.Fatalf("problems = %v, want the three in the order recorded", got)
	}
}

func TestListNonNegative(t *testing.T) {
	l := New(errSentinel)
	l.NonNegative("zero", 0)
	if err := l.Err(); err != nil {
		t.Fatalf("NonNegative(0) = %v, want no problem", err)
	}
	l.NonNegative("timeout", -time.Nanosecond)
	if err := l.Err(); !errors.Is(err, errSentinel) || err.Error() != errSentinel.Error()+": timeout is negative" {
		t.Fatalf("NonNegative(-1ns) = %v, want the negative timeout", err)
	}
}
