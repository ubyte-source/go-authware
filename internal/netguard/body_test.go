package netguard

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

// readHint is the most room a declared size makes, 8 KiB, and hugeSize a
// declared size that no memory holds.
const (
	readHint = 8 << 10
	hugeSize = 1 << 50
)

func TestReadRequest(t *testing.T) {
	t.Parallel()
	for _, in := range []string{atLimit, ""} {
		if got, err := ReadRequest(inbound(t, in, -1), testLimit, errTooLarge); err != nil || string(got) != in {
			t.Fatalf("ReadRequest(%q) = %q, %v, want the body", in, got, err)
		}
	}
	got, err := ReadRequest(inbound(t, pastLimit, testLimit+1), testLimit, errTooLarge)
	if got != nil || err == nil || !errors.Is(err, errTooLarge) || err.Error() != errTooLarge.Error() {
		t.Fatalf("over limit = %q, %v, want no data and errTooLarge itself", got, err)
	}
	failing := inbound(t, "", -1)
	failing.Body = io.NopCloser(iotest.ErrReader(errRead))
	if got, err := ReadRequest(failing, testLimit, errTooLarge); got != nil || !errors.Is(err, errRead) {
		t.Fatalf("reader error = %q, %v, want errRead", got, err)
	}
}

func TestReadRequestRoom(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		declared int64
		room     int
	}{
		{testLimit, testLimit + 1}, {-1, bytes.MinRead}, {overHint, readHint + 1}, {math.MaxInt64, bytes.MinRead},
	} {
		got, err := ReadRequest(inbound(t, atLimit, tc.declared), 1<<20, errTooLarge)
		if err != nil || cap(got) != tc.room {
			t.Errorf("ReadRequest(5 bytes, declared %d) = %v in %d bytes, want %d: room for the declared length up "+
				"to 8 KiB when it lies within the limit", tc.declared, err, cap(got), tc.room)
		}
	}
}

// TestReadSizedRoom makes room for a declared size of at most 8 KiB, so a size
// the body never sends allocates little under any limit.
func TestReadSizedRoom(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		size, limit int64
		room        int
	}{
		{testLimit, testLimit, testLimit + 1}, {readHint, math.MaxInt64, readHint + 1},
		{readHint + 1, math.MaxInt64, readHint + 1}, {hugeSize, math.MaxInt64, readHint + 1},
		{math.MaxInt64 - 1, math.MaxInt64, readHint + 1}, {math.MaxInt64, math.MaxInt64, bytes.MinRead},
	} {
		got, err := ReadSized(strings.NewReader(atLimit), tc.size, tc.limit, errTooLarge)
		if err != nil || string(got) != atLimit || cap(got) != tc.room {
			t.Errorf("ReadSized(5 bytes, size %d, limit %d) = %q, %v in %d bytes, want 12345 in %d", tc.size, tc.limit,
				got, err, cap(got), tc.room)
		}
	}
}

// inbound builds a server request carrying body that declares length.
func inbound(tb testing.TB, body string, length int64) *http.Request {
	tb.Helper()
	r, err := http.NewRequestWithContext(tb.Context(), http.MethodPost, "https://example.com/", strings.NewReader(body))
	if err != nil {
		tb.Fatalf("NewRequestWithContext = %v, want a request", err)
	}
	r.ContentLength = length
	return r
}

// TestReadSized reads five bytes into room made for the declared size exactly
// when it lies from 1 to the limit, room that grows past a short declaration.
func TestReadSized(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int64
		sized bool
	}{
		{"declared", testLimit, true},
		{"declared short", 2, true},
		{"one byte declared", 1, true},
		{"unknown", -1, false},
		{"zero", 0, false},
		{"over the limit", testLimit + 1, false},
		{"far over the limit", math.MaxInt64, false},
	} {
		got, err := ReadSized(strings.NewReader(atLimit), tc.size, testLimit, errTooLarge)
		if err != nil || string(got) != atLimit || cap(got) < bytes.MinRead != tc.sized {
			t.Errorf("%s: ReadSized = %q, %v in %d bytes, want 12345 in room made for the size %t", tc.name, got, err,
				cap(got), tc.sized)
		}
	}
	var r strings.Reader
	// One allocation: the room the declared size makes.
	assertAllocs(t, 1, func() {
		r.Reset(atLimit)
		if got, err := ReadSized(&r, testLimit, testLimit, errTooLarge); err != nil || string(got) != atLimit {
			t.Errorf("ReadSized = %q, %v, want 12345", got, err)
		}
	})
	// One allocation, the room an unknown size makes, and none for the refusal.
	assertAllocs(t, 1, func() {
		r.Reset(pastLimit)
		if got, err := ReadSized(&r, 0, testLimit, errTooLarge); got != nil || !errors.Is(err, errTooLarge) {
			t.Errorf("ReadSized(%s) = %q, %v, want no data and errTooLarge", pastLimit, got, err)
		}
	})
}

// TestReadSizedStopsPastLimit refuses an oversized body once the byte past the
// limit arrives, reading no further, and reads a body whole under the largest
// limit, even one that declares that limit as its size.
func TestReadSizedStopsPastLimit(t *testing.T) {
	t.Parallel()
	const unread = "789"
	src := strings.NewReader(pastLimit + unread)
	if got, err := ReadSized(src, 0, testLimit, errTooLarge); got != nil || !errors.Is(err, errTooLarge) ||
		src.Len() != len(unread) {
		t.Fatalf("ReadSized(9 bytes, limit 5) = %q, %v with %d bytes unread, want errTooLarge with 3", got, err,
			src.Len())
	}
	for _, size := range []int64{0, math.MaxInt64} {
		got, err := ReadSized(strings.NewReader(atLimit), size, math.MaxInt64, errTooLarge)
		if err != nil || string(got) != atLimit {
			t.Errorf("ReadSized(size %d, limit MaxInt64) = %q, %v, want 12345", size, got, err)
		}
	}
}

func TestReadClose(t *testing.T) {
	t.Parallel()
	rc := &trackedBody{Reader: strings.NewReader(atLimit)}
	if got, err := ReadClose(rc, 0, testLimit, errTooLarge); err != nil || string(got) != atLimit || rc.closes != 1 {
		t.Fatalf("ReadClose = %q, %v after %d closes, want the body after 1", got, err, rc.closes)
	}
	tests := []struct {
		name string
		rc   *trackedBody
		want []error
	}{
		{"over limit", &trackedBody{Reader: strings.NewReader(pastLimit)}, []error{errTooLarge}},
		{"read failure", &trackedBody{Reader: iotest.ErrReader(errRead)}, []error{errRead}},
		{"close failure", &trackedBody{Reader: strings.NewReader(atLimit), err: errClose}, []error{errClose}},
		{"both", &trackedBody{Reader: iotest.ErrReader(errRead), err: errClose}, []error{errRead, errClose}},
	}
	for _, tc := range tests {
		got, err := ReadClose(tc.rc, 0, testLimit, errTooLarge)
		for _, want := range tc.want {
			if got != nil || !errors.Is(err, want) || tc.rc.closes != 1 {
				t.Errorf("%s: ReadClose = %q, %v after %d closes, want %v after 1", tc.name, got, err, tc.rc.closes,
					want)
			}
		}
	}
}

// TestJoinClose keeps the outcome of a read, building nothing, when the close
// succeeds, and joins the failure of a close that fails.
func TestJoinClose(t *testing.T) {
	if err := joinClose(nil, nil); err != nil {
		t.Fatalf("joinClose(nil, nil) = %v, want nil", err)
	}
	assertAllocs(t, 0, func() {
		if err := joinClose(errTooLarge, nil); !errors.Is(err, errTooLarge) || err.Error() != errTooLarge.Error() {
			t.Fatalf("joinClose(errTooLarge, nil) = %v, want errTooLarge itself", err)
		}
	})
	if err := joinClose(nil, errClose); !errors.Is(err, errClose) || err.Error() != "close body: test: close failed" {
		t.Fatalf("joinClose(nil, errClose) = %v, want errClose behind close body", err)
	}
	if err := joinClose(errRead, errClose); !errors.Is(err, errRead) || !errors.Is(err, errClose) {
		t.Fatalf("joinClose(errRead, errClose) = %v, want errRead and errClose", err)
	}
}

// TestReadFailure wraps a failed read.
func TestReadFailure(t *testing.T) {
	t.Parallel()
	if err := ReadFailure(errRead); !errors.Is(err, errRead) || err.Error() != "read body: test: read failed" {
		t.Fatalf("ReadFailure = %v, want errRead behind read body", err)
	}
}
