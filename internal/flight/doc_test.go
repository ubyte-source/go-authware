package flight

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Leak check of TestMain: the module whose frames mark a goroutine as ours,
// the bytes of every stack it reads, how often it yields to goroutines that
// are ending, and the blank line between two stacks.
const (
	modulePath = "github.com/ubyte-source/go-authware/v2"
	stackBytes = 1 << 20
	leakRounds = 100
	stackGap   = "\n\n"
)

// TestMain runs the tests, then fails the run when a goroutine running code
// of this module outlives them.
func TestMain(m *testing.M) {
	code := m.Run()
	if stray := strayGoroutines(); code == 0 && stray != "" {
		code = 1
		if _, err := fmt.Fprintf(os.Stderr, "goroutines left by the tests:\n%s\n", stray); err != nil {
			code = 2
		}
	}
	os.Exit(code)
}

// strayGoroutines returns the stacks of the goroutines that run code of this
// module once those ending had leakRounds chances to finish, or "".
func strayGoroutines() string {
	stray := moduleStacks()
	for i := 0; i < leakRounds && stray != ""; i++ {
		runtime.Gosched()
		stray = moduleStacks()
	}
	return stray
}

// moduleStacks returns the stacks of the goroutines but the caller's whose
// frames name this module, or "".
func moduleStacks() string {
	buf := make([]byte, stackBytes)
	_, others, _ := strings.Cut(string(buf[:runtime.Stack(buf, true)]), stackGap)
	var ours []string
	for stack := range strings.SplitSeq(others, stackGap) {
		if strings.Contains(stack, modulePath) {
			ours = append(ours, stack)
		}
	}
	return strings.Join(ours, stackGap)
}
