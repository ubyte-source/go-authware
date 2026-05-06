package replay_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/ubyte-source/go-authware/replay"
)

func ExampleSigner_Sign() {
	key := bytes.Repeat([]byte{0x42}, 32)
	s := &replay.Signer{
		Key: key,
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/items", http.NoBody)
	if err := s.Sign(context.Background(), r); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(r.Header.Get(replay.HeaderTimestamp))
	// Output: 1700000000
}

func ExampleMiddleware() {
	key := bytes.Repeat([]byte{0x42}, 32)
	signer := &replay.Signer{Key: key}
	store, err := replay.Memory(64)
	if err != nil {
		fmt.Println(err)
		return
	}
	verifier := &replay.Verifier{Key: key, Window: 5 * time.Minute, NonceStore: store}

	mw := replay.Middleware(verifier)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", http.NoBody)
	if err := signer.Sign(context.Background(), r); err != nil {
		fmt.Println(err)
		return
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	fmt.Println(rec.Code)
	// Output: 204
}
