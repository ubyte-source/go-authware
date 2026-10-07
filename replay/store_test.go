package replay

import (
	"container/heap"
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestNewMemoryStore(t *testing.T) {
	t.Parallel()
	for _, capacity := range []int{0, -1} {
		if _, err := NewMemoryStore(capacity); !errors.Is(err, ErrInvalidCapacity) {
			t.Errorf("capacity %d: err = %v, want ErrInvalidCapacity", capacity, err)
		}
	}
	store, err := NewMemoryStore(1)
	if err != nil {
		t.Fatalf("NewMemoryStore = %v, want a store", err)
	}
	fresh, err := store.Seen(t.Context(), testNonce, time.Now().Add(time.Hour))
	if err != nil || !fresh {
		t.Fatalf("first Seen = %t, %v, want true, nil", fresh, err)
	}
	if fresh, err = store.Seen(t.Context(), testNonce, time.Now().Add(time.Hour)); err != nil || fresh {
		t.Fatalf("second Seen = %t, %v, want false, nil", fresh, err)
	}
}

func TestMemoryStoreSeenExpiry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := newTestStore(t, smallCapacity)
		expires := time.Unix(testUnix+10, 0)
		seen := func(want bool) {
			t.Helper()
			if fresh, err := m.Seen(t.Context(), testNonce, expires); err != nil || fresh != want {
				t.Fatalf("at %v: Seen = %t, %v; want fresh %t", time.Now(), fresh, err, want)
			}
		}
		seen(true)
		time.Sleep(time.Until(expires.Add(-time.Nanosecond)))
		seen(false)
		time.Sleep(time.Until(expires))
		seen(true)
	})
}

func TestMemoryStoreSeenKeepsLaterExpiry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := newTestStore(t, smallCapacity)
		for _, d := range []time.Duration{shortTTL, time.Minute, time.Second} {
			if _, err := m.Seen(t.Context(), testNonce, time.Unix(testUnix, 0).Add(d)); err != nil {
				t.Fatalf("Seen = %v, want nil", err)
			}
		}
		time.Sleep(59 * time.Second)
		if fresh, err := m.Seen(t.Context(), testNonce, time.Now()); err != nil || fresh {
			t.Fatalf("Seen before the later expiry = %t, %v, want false, nil", fresh, err)
		}
	})
}

func TestMemoryStoreSeenCapacity(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := newTestStore(t, 2)
		long, short := time.Unix(testUnix+3600, 0), time.Unix(testUnix+1, 0)
		for _, n := range []string{"long", "short"} {
			expires := long
			if n == "short" {
				expires = short
			}
			if fresh, err := m.Seen(t.Context(), n, expires); err != nil || !fresh {
				t.Fatalf("Seen(%s) = %t, %v, want true, nil", n, fresh, err)
			}
		}
		if _, err := m.Seen(t.Context(), "third", long); !errors.Is(err, ErrStoreFull) {
			t.Fatalf("full of live nonces: err = %v, want ErrStoreFull", err)
		}
		if fresh, err := m.Seen(t.Context(), "long", long); err != nil || fresh {
			t.Fatalf("Seen(known nonce, full store) = %t, %v, want false, nil", fresh, err)
		}
		time.Sleep(2 * time.Second)
		if fresh, err := m.Seen(t.Context(), "third", long); err != nil || !fresh {
			t.Fatalf("Seen after the short entry expired behind a long one = %t, %v, want true, nil", fresh, err)
		}
	})
}

func TestMemoryStoreSeenModel(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := newTestStore(t, 1<<20)
		model := make(map[string]time.Time)
		src := rand.NewChaCha8([32]byte{1})
		var op [3]byte
		for i := range stressEntries {
			if _, err := src.Read(op[:]); err != nil {
				t.Fatalf("Read = %v, want random bytes", err)
			}
			time.Sleep(time.Duration(op[0]) * 4 * time.Millisecond)
			now := time.Now()
			nonce := strconv.Itoa(int(op[1]))
			expires := now.Add(time.Duration(op[2]) * 250 * time.Millisecond)
			prev, known := model[nonce]
			wantFresh := !known || !prev.After(now)
			if wantFresh || expires.After(prev) {
				model[nonce] = expires
			}
			fresh, err := m.Seen(t.Context(), nonce, expires)
			if err != nil || fresh != wantFresh {
				t.Fatalf("op %d nonce %s: Seen = %t, %v; want fresh %t", i, nonce, fresh, err, wantFresh)
			}
		}
		checkHeap(t, &m.heap)
	})
}

// checkHeap fails unless every entry knows its index and expires no earlier
// than its parent.
func checkHeap(t *testing.T, h *expiryHeap) {
	t.Helper()
	for i, e := range h.entries {
		if e.index != i || (i > 0 && e.expires.Before(h.entries[(i-1)/2].expires)) {
			t.Fatalf("heap entry %d = index %d expiring %v, want index %d after its parent", i, e.index, e.expires, i)
		}
	}
}

// readLockWait bounds the wait for a replay that a reader of the store must
// not hold up.
const readLockWait = 10 * time.Second

// TestMemoryStoreSeenReplayReadLock answers the replay of a live nonce while a
// reader holds the store: a replay flood takes no exclusive lock.
func TestMemoryStoreSeenReplayReadLock(t *testing.T) {
	t.Parallel()
	m := newTestStore(t, smallCapacity)
	expires := time.Now().Add(time.Hour)
	if fresh, err := m.Seen(t.Context(), testNonce, expires); !fresh || err != nil {
		t.Fatalf("first Seen = %t, %v, want true, nil", fresh, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	type answer struct {
		err   error
		fresh bool
	}
	replayed := make(chan answer, 1)
	go func() {
		fresh, err := m.Seen(t.Context(), testNonce, expires)
		replayed <- answer{err: err, fresh: fresh}
	}()
	select {
	case got := <-replayed:
		if got.fresh || got.err != nil {
			t.Fatalf("Seen(replay) under a reader = %t, %v, want false, nil", got.fresh, got.err)
		}
	case <-time.After(readLockWait):
		t.Fatalf("Seen(replay) waited %v behind a reader, want it answered under the read lock", readLockWait)
	}
}

func TestMemoryStoreSeenConcurrent(t *testing.T) {
	t.Parallel()
	m, err := NewMemoryStore(churnCapacity)
	if err != nil {
		t.Fatalf("NewMemoryStore = %v, want a store", err)
	}
	var fresh atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range churnCapacity {
		wg.Go(func() {
			<-start
			ok, err := m.Seen(t.Context(), "same", time.Now().Add(time.Minute))
			if err != nil {
				t.Errorf("Seen = %v, want nil", err)
			}
			if ok {
				fresh.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if fresh.Load() != 1 {
		t.Fatalf("%d goroutines saw the nonce as fresh, want 1", fresh.Load())
	}
}

// The capacities and sizes of the store tests, the nonce they reuse and a TTL
// shorter than a minute.
const (
	smallCapacity = 4
	churnCapacity = 64
	stressEntries = 20000
	testNonce     = "n"
	shortTTL      = 10 * time.Second
	// heapEntries, and the benchHeapEntries of BenchmarkExpiryHeap, enter the
	// heap in the order of a stride coprime with their count, so the pushes are
	// out of order.
	heapEntries      = 10
	benchHeapEntries = 1 << 10
	heapStride       = 3
)

func TestExpiryHeap(t *testing.T) {
	t.Parallel()
	base := time.Unix(testUnix, 0)
	var h expiryHeap
	entries := make(map[string]*memoryEntry)
	for i := range heapEntries {
		sec := i * heapStride % heapEntries
		e := &memoryEntry{nonce: strconv.Itoa(sec), expires: base.Add(time.Duration(sec) * time.Second)}
		entries[e.nonce] = e
		h.push(e)
		checkHeap(t, &h)
	}
	for nonce, later := range map[string]time.Duration{"9": time.Hour, "0": time.Hour / 2} {
		e, ok := entries[nonce]
		if !ok {
			t.Fatalf("entry %s = none, want one", nonce)
		}
		e.expires = base.Add(later)
		h.down(e.index)
		checkHeap(t, &h)
	}
	var order []string
	for len(h.entries) > 0 {
		n := len(h.entries)
		e := h.popMin()
		if h.entries[:n][n-1] != nil {
			t.Fatal("entry past the end after popMin = kept, want nil")
		}
		checkHeap(t, &h)
		order = append(order, e.nonce)
	}
	if got := strings.Join(order, " "); got != "1 2 3 4 5 6 7 8 0 9" {
		t.Fatalf("pop order = %s, want expiry order", got)
	}
}

// stdHeap orders entries through container/heap, the reference of
// BenchmarkExpiryHeap; popped is the entry Pop removed last.
type stdHeap struct {
	expiryHeap

	popped *memoryEntry
}

func (h *stdHeap) Len() int { return len(h.entries) }

func (h *stdHeap) Less(i, j int) bool { return h.entries[i].expires.Before(h.entries[j].expires) }

func (h *stdHeap) Swap(i, j int) { h.swap(i, j) }

// Push appends x, an entry.
func (h *stdHeap) Push(x any) {
	if e, ok := x.(*memoryEntry); ok {
		e.index = len(h.entries)
		h.entries = append(h.entries, e)
	}
}

// Pop removes the last entry and keeps it in popped.
func (h *stdHeap) Pop() any {
	last := len(h.entries) - 1
	h.popped = h.entries[last]
	clear(h.entries[last:])
	h.entries = h.entries[:last]
	return h.popped
}

// BenchmarkExpiryHeap pushes entries out of expiry order and pops them all,
// through expiryHeap and through container/heap.
func BenchmarkExpiryHeap(b *testing.B) {
	base := time.Unix(testUnix, 0)
	entries := make([]*memoryEntry, benchHeapEntries)
	for i := range entries {
		entries[i] = &memoryEntry{expires: base.Add(time.Duration(i*heapStride%benchHeapEntries) * time.Second)}
	}
	var own expiryHeap
	var std stdHeap
	for _, bc := range []struct {
		name string
		push func(e *memoryEntry)
		pop  func() *memoryEntry
	}{
		{"expiryHeap", own.push, own.popMin},
		{"container/heap", func(e *memoryEntry) { heap.Push(&std, e) }, func() *memoryEntry {
			heap.Pop(&std)
			return std.popped
		}},
	} {
		// cycle reports whether the entries leave the heap in expiry order.
		cycle := func() bool {
			for _, e := range entries {
				bc.push(e)
			}
			var last time.Time
			sorted := true
			for range entries {
				e := bc.pop()
				sorted = sorted && !e.expires.Before(last)
				last = e.expires
			}
			return sorted
		}
		b.Run(bc.name, func(b *testing.B) {
			if !cycle() {
				b.Fatalf("%s pops out of expiry order, want the earliest entry first", bc.name)
			}
			b.ReportAllocs()
			for b.Loop() {
				cycle()
			}
		})
	}
}

func BenchmarkMemoryStoreSeen(b *testing.B) {
	m := newTestStore(b, 1<<16)
	nonces := make([]string, 1<<12)
	for i := range nonces {
		nonces[i] = strconv.Itoa(i)
	}
	i := 0
	seen := func() (bool, error) {
		i++
		return m.Seen(b.Context(), nonces[i%len(nonces)], time.Now())
	}
	if fresh, err := seen(); !fresh || err != nil {
		b.Fatalf("Seen = %v, %v, want a fresh nonce: each expires as it is recorded", fresh, err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := seen(); err != nil {
			b.Fatalf("Seen = %v, want nil", err)
		}
	}
}

// BenchmarkMemoryStoreSeenFreshParallel records, on every goroutine, nonces
// that expire as they are recorded.
func BenchmarkMemoryStoreSeenFreshParallel(b *testing.B) {
	m := newTestStore(b, 1<<16)
	nonces := make([]string, 1<<12)
	for i := range nonces {
		nonces[i] = strconv.Itoa(i)
	}
	if fresh, err := m.Seen(b.Context(), nonces[0], time.Now()); !fresh || err != nil {
		b.Fatalf("Seen = %v, %v, want a fresh nonce", fresh, err)
	}
	var next atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := m.Seen(b.Context(), nonces[next.Add(1)%int64(len(nonces))], time.Now()); err != nil {
				b.Errorf("Seen = %v, want nil", err)
				return
			}
		}
	})
}

// BenchmarkMemoryStoreSeenReplayedParallel replays one live nonce on every
// goroutine, each answered under the read lock.
func BenchmarkMemoryStoreSeenReplayedParallel(b *testing.B) {
	m := newTestStore(b, smallCapacity)
	live := time.Now().Add(time.Hour)
	if fresh, err := m.Seen(b.Context(), testNonce, live); !fresh || err != nil {
		b.Fatalf("Seen = %v, %v, want a fresh nonce", fresh, err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if fresh, err := m.Seen(b.Context(), testNonce, live); fresh || err != nil {
				b.Errorf("Seen(replay) = %v, %v, want false, nil", fresh, err)
				return
			}
		}
	})
}
