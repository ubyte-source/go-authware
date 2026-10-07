package keyedmac

import (
	"crypto/hmac"
	"hash"
	"slices"
	"sync"
)

// MAC is the HMAC of one hash under one key, built by New: its zero value is not
// ready. It is safe for concurrent use and must not be copied.
type MAC struct {
	pool sync.Pool
	hash func() hash.Hash
	key  []byte
}

// New returns the MAC of the hash that newHash, not nil, builds, keyed with a copy
// of key.
func New(newHash func() hash.Hash, key []byte) *MAC {
	return &MAC{hash: newHash, key: slices.Clone(key)}
}

// Sum appends the MAC of data to dst and returns the extended slice; with room
// in dst and a pooled keyed state, it allocates nothing.
func (m *MAC) Sum(dst, data []byte) []byte {
	mac, ok := m.pool.Get().(hash.Hash)
	if !ok {
		mac = hmac.New(m.hash, m.key)
	}
	mac.Reset()
	_, _ = mac.Write(data)
	dst = mac.Sum(dst)
	m.pool.Put(mac)
	return dst
}
