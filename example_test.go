package authware_test

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/ubyte-source/go-authware"
)

func ExampleNew_bearer() {
	auth, err := authware.New(&authware.Config{
		Mode:        authware.ModeBearer,
		BearerToken: "my-secret-token",
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("Authorization", "Bearer my-secret-token")

	id, err := auth.Authenticate(r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(id.Method)
	// Output: bearer
}

func ExampleNew_apiKey() {
	auth, err := authware.New(&authware.Config{
		Mode:   authware.ModeAPIKey,
		APIKey: "secret-key",
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-API-Key", "secret-key")

	id, err := auth.Authenticate(r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(id.Method)
	// Output: apikey
}

func ExampleNew_none() {
	auth, err := authware.New(&authware.Config{
		Mode: authware.ModeNone,
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	id, err := auth.Authenticate(r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(id.Method)
	// Output: none
}

func ExampleMiddleware() {
	auth, err := authware.New(&authware.Config{
		Mode:        authware.ModeBearer,
		BearerToken: "tok",
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	handler := authware.Middleware(auth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := authware.IdentityFromContext(r.Context())
		w.Header().Set("X-Subject", id.Subject)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	fmt.Println(w.Code)
	// Output: 200
}

func ExampleIdentityFromContext() {
	auth, err := authware.New(&authware.Config{
		Mode:        authware.ModeBearer,
		BearerToken: "tok",
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	handler := authware.Middleware(auth)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id, ok := authware.IdentityFromContext(r.Context())
		fmt.Println(ok, id.Method)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("Authorization", "Bearer tok")
	handler.ServeHTTP(httptest.NewRecorder(), r)
	// Output: true bearer
}

func ExampleConfigFromEnv() {
	cfg := authware.ConfigFromEnv()
	auth, err := authware.New(cfg, nil)
	if err != nil {
		log.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	id, err := auth.Authenticate(r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(id.Method)
	// Output: none
}

func ExampleNewOAuthProxy() {
	proxy := authware.NewOAuthProxy(&authware.Config{
		OAuthAuthorizationServers: []string{"https://login.microsoftonline.com/tenant/v2.0"},
		OAuthClientID:             "my-client-id",
	}, slog.Default())

	if proxy != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/oauth-authorization-server", proxy.ASMetadataHandler())
		mux.HandleFunc("/oauth/register", proxy.RegisterHandler())
		mux.HandleFunc("/oauth/token", proxy.TokenHandler())

		// Test the DCR shim returns the pre-configured client_id.
		r := httptest.NewRequest(http.MethodPost, "/oauth/register", http.NoBody)
		w := httptest.NewRecorder()
		proxy.RegisterHandler().ServeHTTP(w, r)
		fmt.Println(w.Code)
	}
	// Output: 201
}

func ExampleAuthCheckHandler() {
	auth, err := authware.New(&authware.Config{
		Mode:        authware.ModeBearer,
		BearerToken: "secret",
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	handler := authware.AuthCheckHandler(auth)

	r := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	fmt.Println(w.Code)
	fmt.Println(w.Header().Get("X-Auth-Method"))
	// Output:
	// 200
	// bearer
}
