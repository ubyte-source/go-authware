package netguard

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"net/http"
	"sync"
)

// Digester hashes the bodies of client requests with SHA-256, reusing its
// scratch across calls. The zero value is ready and safe for concurrent use;
// a Digester must not be copied.
type Digester struct {
	pool sync.Pool
}

// digestState is the scratch of a digest: a SHA-256 state, the reader that
// bounds a body copy, the sum it lands in and the chunk the copy streams
// through.
type digestState struct {
	h       hash.Hash
	limited io.LimitedReader
	sum     [sha256.Size]byte
	chunk   [4 << 10]byte
}

// Digest returns the SHA-256 of the body of r, which has one: it streams a GetBody
// copy, or reads r.Body into a replayable one, setting ContentLength, or http.NoBody on
// failure. It fails with tooLarge past limit bytes or when a copy, read or close fails.
func (d *Digester) Digest(r *http.Request, limit int64, tooLarge error) ([sha256.Size]byte, error) {
	st, ok := d.pool.Get().(*digestState)
	if !ok {
		st = &digestState{h: sha256.New()}
	}
	defer d.pool.Put(st)
	st.h.Reset()
	if err := st.write(r, limit, tooLarge); err != nil {
		return [sha256.Size]byte{}, err
	}
	st.h.Sum(st.sum[:0])
	return st.sum, nil
}

// write hashes the body of r, which has one, as Digest describes.
func (st *digestState) write(r *http.Request, limit int64, tooLarge error) error {
	if r.GetBody == nil {
		data, err := ReadClose(r.Body, r.ContentLength, limit, tooLarge)
		if err != nil {
			r.Body = http.NoBody
			return err
		}
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
		r.Body = io.NopCloser(bytes.NewReader(data))
		r.ContentLength = int64(len(data))
		_, _ = st.h.Write(data)
		return nil
	}
	rc, err := r.GetBody()
	if err != nil {
		return fmt.Errorf("copy body: %w", err)
	}
	return joinClose(st.stream(rc, limit, tooLarge), rc.Close())
}

// stream hashes src to the end through the chunk, failing with tooLarge once
// more than limit bytes arrive.
func (st *digestState) stream(src io.Reader, limit int64, tooLarge error) error {
	st.limited = boundReader(src, limit)
	n, err := io.CopyBuffer(st.h, &st.limited, st.chunk[:])
	st.limited.R = nil
	switch {
	case n > limit:
		return tooLarge
	case err != nil:
		return ReadFailure(err)
	}
	return nil
}
