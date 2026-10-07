package netguard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
)

// ReadClose reads the body rc with ReadSized and closes it; a failed close fails the
// read too.
func ReadClose(rc io.ReadCloser, size, limit int64, tooLarge error) ([]byte, error) {
	data, readErr := ReadSized(rc, size, limit, tooLarge)
	if err := joinClose(readErr, rc.Close()); err != nil {
		return nil, err
	}
	return data, nil
}

// joinClose returns err, the outcome of reading a body, joined with the failure
// closeErr of closing the body when the close failed.
func joinClose(err, closeErr error) error {
	if closeErr == nil {
		return err
	}
	return errors.Join(err, fmt.Errorf("close body: %w", closeErr))
}

// ReadFailure wraps err, the failure of reading a body.
func ReadFailure(err error) error {
	return fmt.Errorf("read body: %w", err)
}

// ReadRequest reads the body of the server request r with ReadSized, its
// declared length as the size.
func ReadRequest(r *http.Request, limit int64, tooLarge error) ([]byte, error) {
	return ReadSized(r.Body, r.ContentLength, limit, tooLarge)
}

// maxRoom caps the room made for a declared size, so a size the body never
// sends holds little memory.
const maxRoom = 8 << 10

// ReadSized reads the body r to the end, failing with tooLarge once more than limit
// bytes arrive or with the read failure, into room made before the first read for size
// bytes, up to 8 KiB, when size lies from 1 to limit and below math.MaxInt64.
func ReadSized(r io.Reader, size, limit int64, tooLarge error) ([]byte, error) {
	lr := boundReader(r, limit)
	room := int64(bytes.MinRead)
	if 0 < size && size < lr.N {
		room = min(size, maxRoom) + 1
	}
	data := make([]byte, 0, room)
	for {
		data = slices.Grow(data, 1)
		n, err := lr.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		switch {
		case errors.Is(err, io.EOF) && int64(len(data)) > limit:
			return nil, tooLarge
		case errors.Is(err, io.EOF):
			return data, nil
		case err != nil:
			return nil, ReadFailure(err)
		}
	}
}

// boundReader reads r up to the first byte past limit, the byte that reveals an
// oversized body, and up to limit itself at math.MaxInt64.
func boundReader(r io.Reader, limit int64) io.LimitedReader {
	return io.LimitedReader{R: r, N: max(limit+1, limit)}
}
