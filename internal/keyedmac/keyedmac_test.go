package keyedmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strings"
	"sync"
	"testing"
)

// A key, the reuses of one MAC and its concurrent writers.
const (
	testKey = "key"
	reuses  = 3
	writers = 32
)

// reference returns the HMAC of data under key with a fresh state.
func reference(newHash func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func TestNew(t *testing.T) {
	t.Parallel()
	key := []byte(testKey)
	m := New(sha256.New, key)
	key[0] = 'x'
	got, want := m.Sum(nil, []byte("data")), reference(sha256.New, []byte(testKey), []byte("data"))
	if !bytes.Equal(got, want) {
		t.Fatalf("Sum after the caller changed its key = %x, want %x: New keeps a copy", got, want)
	}
}

func TestMACSum(t *testing.T) {
	t.Parallel()
	const vector = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	m := New(sha256.New, []byte(testKey))
	for i := range reuses {
		dst := []byte("prefix")
		got := m.Sum(dst, []byte("The quick brown fox jumps over the lazy dog"))
		if string(got[:len(dst)]) != "prefix" || hex.EncodeToString(got[len(dst):]) != vector {
			t.Fatalf("Sum #%d = %q, want prefix followed by the HMAC-SHA256 test vector", i, got)
		}
	}
	for _, newHash := range []func() hash.Hash{sha512.New384, sha512.New} {
		m := New(newHash, []byte("k"))
		for _, data := range []string{"", "a", "bb"} {
			got, want := m.Sum(nil, []byte(data)), reference(newHash, []byte("k"), []byte(data))
			if !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", data, got, want)
			}
		}
	}
}

// TestMACSumConcurrent sums from many goroutines at once: every sum matches a
// fresh MAC, so no pooled state is shared by two callers.
func TestMACSumConcurrent(t *testing.T) {
	t.Parallel()
	m := New(sha256.New, []byte(testKey))
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			data := []byte(strings.Repeat("d", i))
			want := reference(sha256.New, []byte(testKey), data)
			for range 100 {
				if got := m.Sum(nil, data); !bytes.Equal(got, want) {
					t.Errorf("Sum = %x, want %x", got, want)
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestMACSumAllocs sums into room the caller owns, with the keyed state from
// the pool: nothing is allocated.
func TestMACSumAllocs(t *testing.T) {
	m := New(sha256.New, []byte(testKey))
	data, dst := []byte("data"), make([]byte, 0, sha256.Size)
	assertAllocs(t, 0, func() { m.Sum(dst, data) })
}

func BenchmarkMACSum(b *testing.B) {
	m := New(sha256.New, []byte(testKey))
	data, dst := []byte("The quick brown fox jumps over the lazy dog"), make([]byte, 0, sha256.Size)
	if got, want := m.Sum(dst, data), reference(sha256.New, []byte(testKey), data); !bytes.Equal(got, want) {
		b.Fatalf("Sum = %x, want %x", got, want)
	}
	b.ReportAllocs()
	for b.Loop() {
		dst = m.Sum(dst[:0], data)
	}
}
