package authware_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Api-Key", "secret-key")
	id, err := auth.Authenticate(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id.Method)
	// Output: apikey
}

func ExampleNew_none() {
	auth, err := authware.New(&authware.Config{Mode: authware.ModeNone}, nil)
	if err != nil {
		log.Fatal(err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	id, err := auth.Authenticate(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id.Method)
	// Output: none
}

func ExampleNew_mTLS() {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "client.example"}}
	auth, err := authware.New(&authware.Config{
		Mode:                authware.ModeMTLS,
		MTLSAllowedSubjects: []string{"client.example"},
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	id, err := auth.Authenticate(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id.Method, id.Subject)
	// Output: mtls client.example
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	fmt.Println(w.Code)
	// Output: 200
}

func ExampleRequireCapability() {
	gate := authware.RequireCapability(
		authware.HasMethod(authware.ModeOAuth),
		authware.HasAllScopes("read", "write"),
	)
	handler := gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	r = r.WithContext(authware.WithIdentity(r.Context(), &authware.Identity{
		Subject: "u", Method: authware.ModeOAuth,
		Scopes: []string{"read", "write", "admin"},
	}))
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
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
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", proxy.ASMetadataHandler())
		mux.HandleFunc("GET /authorize", proxy.AuthorizeHandler())
		mux.HandleFunc("POST /register", proxy.RegisterHandler())
		mux.HandleFunc("POST /token", proxy.TokenHandler())
		_ = mux

		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", http.NoBody)
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/check", http.NoBody)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	fmt.Println(w.Code)
	fmt.Println(w.Header().Get("X-Auth-Method"))
	// Output:
	// 200
	// bearer
}

func ExampleSecurityHeaders() {
	mw := authware.SecurityHeaders(&authware.SecureHeadersConfig{
		HSTSMaxAge:         31536000,
		ContentTypeNosniff: true,
		FrameOptions:       "DENY",
	})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))
	fmt.Println(w.Header().Get("X-Frame-Options"))
	// Output: DENY
}

func ExampleNewRedactor() {
	h := authware.NewRedactor(slog.NewTextHandler(httptest.NewRecorder(), nil), authware.SensitiveHeaders()...)
	logger := slog.New(h)
	logger.Info("req", "Authorization", "Bearer secret-value")
	fmt.Println("ok")
	// Output: ok
}
