package cred_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/ubyte-source/go-authware/cred"
)

func ExampleToken_Apply() {
	tok := &cred.Token{Value: "abc"}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	tok.Apply(r)
	fmt.Println(r.Header.Get("Authorization"))
	// Output: Bearer abc
}

func ExampleCache() {
	src := cred.TokenSourceFunc(func(_ context.Context) (*cred.Token, error) {
		return &cred.Token{Value: "tok", Expires: time.Now().Add(time.Hour)}, nil
	})
	cached := cred.Cache(src)
	tok, err := cached.Token(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tok.Value)
	// Output: tok
}

func ExampleRoundTripper() {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	signer := cred.AsSigner(cred.TokenSourceFunc(func(_ context.Context) (*cred.Token, error) {
		return &cred.Token{Value: "client-tok"}, nil
	}))
	client := &http.Client{Transport: cred.RoundTripper(nil, signer)}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL, http.NoBody)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		fmt.Println(closeErr)
	}
	// Output: Bearer client-tok
}
