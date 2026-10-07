package netguard

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

// errCopy is the failure of a GetBody copy.
var errCopy = errors.New("test: body copy failed")

// digest returns the SHA-256 that Digester.Digest reports for body.
func digest(body string) [sha256.Size]byte { return sha256.Sum256([]byte(body)) }

// largeRepeats makes a 10 KB body of a digit run.
const largeRepeats = 1000

func TestDigesterDigestNone(t *testing.T) {
	t.Parallel()
	var d Digester
	for _, payload := range []io.Reader{nil, http.NoBody} {
		r := outbound(t, payload)
		if got, err := d.Digest(r, testLimit, errTooLarge); got != digest("") || err != nil || r.GetBody != nil {
			t.Fatalf("Digest(%v) = %x, %v, want the empty digest and r untouched", payload, got, err)
		}
	}
}

func TestDigesterDigestBuffers(t *testing.T) {
	t.Parallel()
	var d Digester
	original := &trackedBody{Reader: strings.NewReader(atLimit)}
	r := outbound(t, original)
	got, err := d.Digest(r, testLimit, errTooLarge)
	if err != nil || got != digest(atLimit) || original.closes != 1 || r.ContentLength != testLimit {
		t.Fatalf("Digest = %x, %v after %d closes, length %d, want the digest of 12345 after 1, length 5", got, err,
			original.closes, r.ContentLength)
	}
	for _, read := range []func() (io.ReadCloser, error){
		func() (io.ReadCloser, error) { return r.Body, nil },
		r.GetBody, r.GetBody,
	} {
		rc, err := read()
		if err != nil {
			t.Fatalf("read = %v, want the body", err)
		}
		if again, err := io.ReadAll(rc); err != nil || string(again) != atLimit {
			t.Fatalf("replayed body = %q, %v, want 12345", again, err)
		}
	}
}

func TestDigesterDigestStreams(t *testing.T) {
	t.Parallel()
	var d Digester
	sent := &trackedBody{Reader: strings.NewReader("sent")}
	large := strings.Repeat("0123456789", largeRepeats)
	fresh := &trackedBody{Reader: iotest.HalfReader(strings.NewReader(large))}
	r := outbound(t, sent)
	r.GetBody = func() (io.ReadCloser, error) { return fresh, nil }
	got, err := d.Digest(r, int64(len(large)), errTooLarge)
	if err != nil || got != digest(large) || fresh.closes != 1 || sent.closes != 0 || r.Body != sent {
		t.Fatalf("Digest = %x, %v, want the digest of the GetBody copy, read in full, with r.Body untouched", got, err)
	}
}

// TestDigesterDigestAllocs pins the pooled scratch of a streamed copy: a 10 KB copy
// streams through it and allocates nothing, nor does a request without a body or a
// copy past the limit.
func TestDigesterDigestAllocs(t *testing.T) {
	var d Digester
	var s strings.Reader
	large := strings.Repeat("0123456789", largeRepeats)
	r := outbound(t, strings.NewReader("sent"))
	copied := io.NopCloser(&s)
	r.GetBody = func() (io.ReadCloser, error) { s.Reset(large); return copied, nil }
	bodiless := outbound(t, http.NoBody)
	assertAllocs(t, 0, func() {
		if _, err := d.Digest(r, int64(len(large)), errTooLarge); err != nil {
			t.Fatalf("Digest = %v, want the digest", err)
		}
		if got, err := d.Digest(bodiless, testLimit, errTooLarge); got != sha256.Sum256(nil) || err != nil {
			t.Fatalf("Digest without a body = %x, %v, want the empty digest", got, err)
		}
		if _, err := d.Digest(r, int64(len(large))-1, errTooLarge); !errors.Is(err, errTooLarge) {
			t.Fatalf("Digest past the limit = %v, want errTooLarge", err)
		}
	})
}

func TestDigesterDigestRejects(t *testing.T) {
	t.Parallel()
	var d Digester
	copying := func(rc io.ReadCloser, err error) *http.Request {
		r := outbound(t, strings.NewReader("1"))
		r.GetBody = func() (io.ReadCloser, error) { return rc, err }
		return r
	}
	for name, tc := range map[string]struct {
		r    *http.Request
		want error
	}{
		"oversized body":    {outbound(t, strings.NewReader(pastLimit)), errTooLarge},
		"oversized copy":    {copying(io.NopCloser(strings.NewReader(pastLimit)), nil), errTooLarge},
		"GetBody failure":   {copying(nil, errCopy), errCopy},
		"copy read failure": {copying(io.NopCloser(iotest.ErrReader(errRead)), nil), errRead},
	} {
		body := tc.r.Body
		if got, err := d.Digest(tc.r, testLimit, errTooLarge); got != [sha256.Size]byte{} || !errors.Is(err, tc.want) {
			t.Errorf("%s: Digest = %x, %v, want %v", name, got, err, tc.want)
		}
		if consumed := tc.r.GetBody == nil; consumed && tc.r.Body != http.NoBody || !consumed && tc.r.Body != body {
			t.Errorf("%s: body after Digest = %v, want http.NoBody once read and closed, else untouched", name,
				tc.r.Body)
		}
	}
	exact := copying(io.NopCloser(strings.NewReader(atLimit)), nil)
	if got, err := d.Digest(exact, testLimit, errTooLarge); got != digest(atLimit) || err != nil {
		t.Fatalf("copy at the limit = %x, %v, want its digest", got, err)
	}
}

// TestDigesterDigestLargestLimit digests a buffered body, which declares a size
// no memory holds, and a streamed copy whole under the largest limit.
func TestDigesterDigestLargestLimit(t *testing.T) {
	t.Parallel()
	var d Digester
	buffered := outbound(t, strings.NewReader(atLimit))
	buffered.ContentLength = math.MaxInt64 - 1
	streamed := outbound(t, strings.NewReader(atLimit))
	streamed.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(atLimit)), nil }
	for name, r := range map[string]*http.Request{"buffered": buffered, "streamed": streamed} {
		if got, err := d.Digest(r, math.MaxInt64, errTooLarge); got != digest(atLimit) || err != nil {
			t.Errorf("%s: Digest(limit MaxInt64) = %x, %v, want the digest of 12345", name, got, err)
		}
	}
}

func TestDigesterDigestCloseFailure(t *testing.T) {
	t.Parallel()
	var d Digester
	for name, r := range map[string]*http.Request{
		"body": outbound(t, &trackedBody{Reader: strings.NewReader("1"), err: errClose}),
		"copy": outbound(t, strings.NewReader("1")),
	} {
		if name == "copy" {
			r.GetBody = func() (io.ReadCloser, error) {
				return &trackedBody{Reader: strings.NewReader("1"), err: errClose},
					nil
			}
		}
		if got, err := d.Digest(r, testLimit, errTooLarge); got != [sha256.Size]byte{} || !errors.Is(err, errClose) {
			t.Errorf("%s close failure = %x, %v, want errClose", name, got, err)
		}
	}
}

func TestDigesterDigestReuses(t *testing.T) {
	t.Parallel()
	var d Digester
	for _, in := range []string{"first", "", "third"} {
		r := outbound(t, strings.NewReader("x"))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(in)), nil }
		if got, err := d.Digest(r, testLimit, errTooLarge); got != digest(in) || err != nil {
			t.Fatalf("Digest(%q) after other bodies = %x, %v, want its own digest", in, got, err)
		}
	}
}

// pieces reads data at most size bytes at a time.
type pieces struct {
	data []byte
	size int
}

func (p *pieces) Read(b []byte) (int, error) {
	if len(p.data) == 0 {
		return 0, io.EOF
	}
	n := copy(b[:min(len(b), p.size)], p.data)
	p.data = p.data[n:]
	return n, nil
}

// seedChunk is the piece argument of a FuzzDigesterDigest seed: reads of piece+1 bytes.
const seedChunk = 3

// FuzzDigesterDigest checks Digest against sha256.Sum256 under the limit and
// errTooLarge above it, for a body copy read in pieces of every size and
// for a body buffered without GetBody.
func FuzzDigesterDigest(f *testing.F) {
	f.Add([]byte(atLimit), uint16(testLimit), byte(0), false)
	f.Add([]byte(pastLimit), uint16(testLimit), byte(1), true)
	f.Add([]byte(pastLimit), uint16(testLimit), byte(0), false)
	f.Add(bytes.Repeat([]byte("x"), overHint), uint16(overHint), byte(seedChunk), false)
	f.Fuzz(func(t *testing.T, body []byte, limit uint16, piece byte, buffered bool) {
		var d Digester
		r := outbound(t, bytes.NewReader(body))
		if !buffered {
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(&pieces{data: body, size: int(piece) + 1}), nil
			}
		}
		got, err := d.Digest(r, int64(limit), errTooLarge)
		switch {
		case len(body) > int(limit):
			if got != [sha256.Size]byte{} || !errors.Is(err, errTooLarge) || err.Error() != errTooLarge.Error() {
				t.Fatalf("Digest(%d bytes, limit %d) = %x, %v, want the zero digest and errTooLarge itself", len(body),
					limit, got, err)
			}
		case err != nil || got != sha256.Sum256(body):
			t.Fatalf("Digest(%d bytes, limit %d) = %x, %v, want %x", len(body), limit, got, err, sha256.Sum256(body))
		}
	})
}
