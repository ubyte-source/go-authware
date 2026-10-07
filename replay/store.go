package replay

import (
	"context"
	"sync"
	"time"
)

// NonceStore records nonces until they expire. Implementations must be safe for
// concurrent use.
type NonceStore interface {
	// Seen reports fresh when nonce is not recorded and records it until expires,
	// atomically per nonce.
	Seen(ctx context.Context, nonce string, expires time.Time) (fresh bool, err error)
}

// memoryEntry is a recorded nonce and its position in the expiry heap.
type memoryEntry struct {
	nonce   string
	expires time.Time
	index   int
}

// expiryHeap is a binary min-heap of entries by expiry in which each entry
// records its index; it is typed, where container/heap would need type
// assertions that cannot fail.
type expiryHeap struct {
	entries []*memoryEntry
}

func (h *expiryHeap) push(e *memoryEntry) {
	e.index = len(h.entries)
	h.entries = append(h.entries, e)
	h.up(e.index)
}

// popMin removes and returns the earliest entry of the non-empty heap.
func (h *expiryHeap) popMin() *memoryEntry {
	last := len(h.entries) - 1
	h.swap(0, last)
	e := h.entries[last]
	clear(h.entries[last:])
	h.entries = h.entries[:last]
	h.down(0)
	return e
}

// up moves the entry at i toward the root while it expires before its
// parent.
func (h *expiryHeap) up(i int) {
	for i != 0 {
		parent := (i - 1) >> 1
		if !h.entries[i].expires.Before(h.entries[parent].expires) {
			return
		}
		h.swap(i, parent)
		i = parent
	}
}

// down moves the entry at i toward the leaves while the earlier of its children,
// 2i+1 and 2i+2, expires before it.
func (h *expiryHeap) down(i int) {
	for {
		child := i<<1 + 1
		if child >= len(h.entries) {
			return
		}
		if right := child + 1; right < len(h.entries) && h.entries[right].expires.Before(h.entries[child].expires) {
			child = right
		}
		if !h.entries[child].expires.Before(h.entries[i].expires) {
			return
		}
		h.swap(i, child)
		i = child
	}
}

func (h *expiryHeap) swap(i, j int) {
	h.entries[i], h.entries[j] = h.entries[j], h.entries[i]
	h.entries[i].index = i
	h.entries[j].index = j
}

// memoryStore is a bounded map of nonces with expiry-ordered eviction.
type memoryStore struct {
	mu       sync.RWMutex
	byNonce  map[string]*memoryEntry
	heap     expiryHeap
	capacity int
}

// NewMemoryStore returns an in-process [NonceStore] holding up to capacity live
// nonces, which must be at least 1 (else ErrInvalidCapacity); full, it fails
// closed with [ErrStoreFull]. It expires entries by time.Now.
func NewMemoryStore(capacity int) (NonceStore, error) {
	if capacity <= 0 {
		return nil, ErrInvalidCapacity
	}
	return &memoryStore{byNonce: make(map[string]*memoryEntry), capacity: capacity}, nil
}

// Seen implements [NonceStore]; a repeated nonce keeps the later expiry.
func (m *memoryStore) Seen(_ context.Context, nonce string, expires time.Time) (bool, error) {
	now := time.Now()
	if m.replayed(nonce, expires, now) {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.heap.entries) > 0 && !m.heap.entries[0].expires.After(now) {
		delete(m.byNonce, m.heap.popMin().nonce)
	}
	if e, ok := m.byNonce[nonce]; ok {
		if expires.After(e.expires) {
			e.expires = expires
			m.heap.down(e.index)
		}
		return false, nil
	}
	if len(m.byNonce) >= m.capacity {
		return false, ErrStoreFull
	}
	e := &memoryEntry{nonce: nonce, expires: expires}
	m.heap.push(e)
	m.byNonce[nonce] = e
	return true, nil
}

// replayed reports, under the read lock, whether nonce is live at now and expires
// no earlier than expires, a replay that Seen answers without a change.
func (m *memoryStore) replayed(nonce string, expires, now time.Time) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e, ok := m.byNonce[nonce]; ok {
		return e.expires.After(now) && !expires.After(e.expires)
	}
	return false
}
