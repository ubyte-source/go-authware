package authware

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signHS256Token(t *testing.T, header, claims map[string]any, secret string) string {
	t.Helper()

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		t.Fatalf("mac.Write: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil))
}

func signRSAToken(
	t *testing.T, key *rsa.PrivateKey, kid string,
	claims map[string]any,
) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("RSA sign: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

func rsaJWKSHandler(t *testing.T, key *rsa.PublicKey, kid string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		set := jwkSet{Keys: []jwk{{
			Kty: "RSA",
			Kid: kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	}
}

func TestOAuthHMACAuthenticator(t *testing.T) {
	now := time.Now()
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub":   "user-123",
			"iss":   "https://issuer.example.com",
			"aud":   []string{"mcp-server"},
			"scope": "mcp:read mcp:write",
			"iat":   now.Unix(),
			"nbf":   now.Add(-time.Minute).Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		},
		"top-secret",
	)

	a, err := New(&Config{
		Mode:                      ModeOAuth,
		OAuthIssuer:               "https://issuer.example.com",
		OAuthAudience:             "mcp-server",
		OAuthHMACSecret:           "top-secret",
		OAuthRequiredScopes:       []string{"mcp:read"},
		OAuthResourceName:         "MCP Server",
		OAuthAuthorizationServers: []string{"https://issuer.example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/jsonrpc", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "user-123" {
		t.Fatalf("Subject = %q", id.Subject)
	}

	md := a.Metadata("https://mcp.example.com/jsonrpc")
	if md == nil {
		t.Fatal("expected metadata")
	}
	if md.Resource != "https://mcp.example.com/jsonrpc" {
		t.Fatalf("Resource = %q", md.Resource)
	}
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != "https://issuer.example.com" {
		t.Fatalf("AuthorizationServers = %#v", md.AuthorizationServers)
	}
}

func TestNewOAuth_MissingIssuer(t *testing.T) {
	if _, err := New(&Config{Mode: ModeOAuth, OAuthHMACSecret: "s"}, nil); err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestNewOAuth_OIDCDiscoveryFallback(t *testing.T) {
	// Without HMAC secret or JWKS URL, the authenticator should be created
	// successfully (OIDC discovery resolves the JWKS URL lazily at runtime).
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestOAuthMetadata_OverrideResource(t *testing.T) {
	a, err := New(&Config{
		Mode:            ModeOAuth,
		OAuthIssuer:     "https://issuer.example.com",
		OAuthHMACSecret: "secret",
		OAuthResource:   "https://override.example.com/api",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := a.Metadata("https://ignored.example.com")
	if md == nil {
		t.Fatal("expected metadata")
	}
	if md.Resource != "https://override.example.com/api" {
		t.Fatalf("Resource = %q", md.Resource)
	}
}

func TestOAuthMetadata_EmptyResource(t *testing.T) {
	a, err := New(&Config{
		Mode:            ModeOAuth,
		OAuthIssuer:     "https://issuer.example.com",
		OAuthHMACSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if md := a.Metadata(""); md != nil {
		t.Fatalf("expected nil for empty resource, got %+v", md)
	}
}

func TestOAuthMetadata_ProxyMode_OmitsAuthorizationServers(t *testing.T) {
	a, err := New(&Config{
		Mode:                      ModeOAuth,
		OAuthIssuer:               "https://issuer.example.com",
		OAuthHMACSecret:           "secret",
		OAuthResource:             "https://api.example.com",
		OAuthClientID:             "my-client-id", // triggers proxy mode
		OAuthAuthorizationServers: []string{"https://upstream.example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := a.Metadata("https://api.example.com")
	if md == nil {
		t.Fatal("expected metadata")
	}
	if md.AuthorizationServers != nil {
		t.Fatalf("expected nil AuthorizationServers in proxy mode, got %v", md.AuthorizationServers)
	}
}

func TestOAuthMetadata_NonProxyMode_IncludesAuthorizationServers(t *testing.T) {
	a, err := New(&Config{
		Mode:                      ModeOAuth,
		OAuthIssuer:               "https://issuer.example.com",
		OAuthHMACSecret:           "secret",
		OAuthResource:             "https://api.example.com",
		OAuthAuthorizationServers: []string{"https://upstream.example.com"},
		// OAuthClientID is empty → no proxy mode
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := a.Metadata("https://api.example.com")
	if md == nil {
		t.Fatal("expected metadata")
	}
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != "https://upstream.example.com" {
		t.Fatalf("AuthorizationServers = %v, want [https://upstream.example.com]", md.AuthorizationServers)
	}
}

func TestOAuth_MalformedJWT(t *testing.T) {
	a, err := New(&Config{
		Mode:            ModeOAuth,
		OAuthIssuer:     "https://issuer.example.com",
		OAuthHMACSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "foobar"},
		{"one dot", "foo.bar"},
		{"bad header b64", "!!!.YQ.YQ"},
		{"bad sig b64", "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ4In0.!!!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			if _, err := a.Authenticate(req); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestOAuth_MissingBearerToken(t *testing.T) {
	a, err := New(&Config{
		Mode:            ModeOAuth,
		OAuthIssuer:     "https://issuer.example.com",
		OAuthHMACSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestOAuth_ExpiredToken(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": time.Now().Add(-time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected token expired error")
	}
}

func TestOAuth_WrongIssuer(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://wrong.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected issuer error")
	}
}

func TestOAuth_WrongAudience(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com", "aud": "other",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
		"secret",
	)
	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com",
		OAuthAudience: "mcp-server", OAuthHMACSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected audience error")
	}
}

func TestOAuth_WrongSignature(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
		"wrong-secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected signature error")
	}
}

func TestOAuth_UnsupportedHMACAlg(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS999", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected unsupported alg error")
	}
}

func TestOAuth_HMACAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		hasher func() hash.Hash
		alg    string
	}{
		{sha512.New384, "HS384"},
		{sha512.New, "HS512"},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			now := time.Now()
			header := map[string]any{"alg": tc.alg, "typ": "JWT"}
			claims := map[string]any{
				"sub": "user", "iss": "https://issuer.example.com",
				"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
			}
			headerJSON, hErr := json.Marshal(header)
			if hErr != nil {
				t.Fatalf("marshal header: %v", hErr)
			}
			claimsJSON, cErr := json.Marshal(claims)
			if cErr != nil {
				t.Fatalf("marshal claims: %v", cErr)
			}
			enc := base64.RawURLEncoding
			signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
			mac := hmac.New(tc.hasher, []byte("secret"))
			_, _ = mac.Write([]byte(signingInput))
			token := signingInput + "." + enc.EncodeToString(mac.Sum(nil))

			a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+token)
			id, err := a.Authenticate(req)
			if err != nil {
				t.Fatalf("Authenticate %s: %v", tc.alg, err)
			}
			if id.Subject != "user" {
				t.Fatalf("Subject = %q", id.Subject)
			}
		})
	}
}

func TestOAuth_TokenNotBeforeViolation(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"nbf": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected nbf error")
	}
}

func TestOAuth_TokenIssuedInFuture(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": time.Now().Add(2 * time.Hour).Unix(),
			"iat": time.Now().Add(time.Hour).Unix(),
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected iat-in-future error")
	}
}

func TestOAuth_ScopeFromSCPClaim(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
			"scp": "read write",
		},
		"secret",
	)
	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com",
		OAuthHMACSecret: "secret", OAuthRequiredScopes: []string{"read"},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Scopes == "" {
		t.Fatal("expected scopes")
	}
}

func TestOAuth_SubjectFallbacks(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"client_id", map[string]any{"client_id": "my-client"}, "my-client"},
		{"azp", map[string]any{"azp": "my-azp-client"}, "my-azp-client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.claims["iss"] = "https://issuer.example.com"
			tc.claims["exp"] = time.Now().Add(time.Hour).Unix()
			tc.claims["iat"] = time.Now().Unix()
			token := signHS256Token(t,
				map[string]any{"alg": "HS256", "typ": "JWT"}, tc.claims, "secret")
			a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+token)
			id, authErr := a.Authenticate(req)
			if authErr != nil {
				t.Fatalf("Authenticate: %v", authErr)
			}
			if id.Subject != tc.want {
				t.Fatalf("Subject = %q, want %q", id.Subject, tc.want)
			}
		})
	}
}

func TestOAuth_Challenge(t *testing.T) {
	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := unauthorizedError("bad token")
	status, header, msg := a.Challenge(aErr, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(header, "Bearer") {
		t.Fatalf("header = %q", header)
	}
	if msg != "bad token" {
		t.Fatalf("msg = %q", msg)
	}
}

func TestOAuthAuthenticator_RejectsMissingScope(t *testing.T) {
	now := time.Now()
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub":   "user-123",
			"iss":   "https://issuer.example.com",
			"aud":   "mcp-server",
			"scope": "mcp:read",
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		},
		"top-secret",
	)

	a, err := New(&Config{
		Mode:                ModeOAuth,
		OAuthIssuer:         "https://issuer.example.com",
		OAuthAudience:       "mcp-server",
		OAuthHMACSecret:     "top-secret",
		OAuthRequiredScopes: []string{"mcp:admin"},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/jsonrpc", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = a.Authenticate(req)
	if err == nil {
		t.Fatal("expected scope validation error")
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Fatalf("expected scope error, got %v", err)
	}
}

// ── JWKS RSA tests ───────────────────────────────────────────

func TestOAuth_JWKS_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	jwksServer := httptest.NewServer(rsaJWKSHandler(t, &key.PublicKey, "test-kid"))
	defer jwksServer.Close()

	now := time.Now()
	token := signRSAToken(t, key, "test-kid", map[string]any{
		"sub": "rsa-user", "iss": "https://issuer.example.com",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})

	a, err := New(&Config{
		Mode:         ModeOAuth,
		OAuthIssuer:  "https://issuer.example.com",
		OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "rsa-user" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

func TestOAuth_JWKS_RSA_WrongKey(t *testing.T) {
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	jwksServer := httptest.NewServer(rsaJWKSHandler(t, &otherKey.PublicKey, "wrong-kid"))
	defer jwksServer.Close()

	now := time.Now()
	token := signRSAToken(t, signKey, "wrong-kid", map[string]any{
		"sub": "user", "iss": "https://issuer.example.com",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})

	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected verification error with wrong key")
	}
}

// ── JWKS EC test ─────────────────────────────────────────────

func TestOAuth_JWKS_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	kid := "ec-kid"
	enc := base64.RawURLEncoding
	set := jwkSet{Keys: []jwk{{
		Kty: "EC", Crv: "P-256", Kid: kid, Alg: "ES256",
		X: enc.EncodeToString(key.X.Bytes()),
		Y: enc.EncodeToString(key.Y.Bytes()),
	}}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(set); encErr != nil {
			t.Errorf("encode JWKS: %v", encErr)
		}
	}))
	defer jwksServer.Close()

	now := time.Now()
	header := map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid}
	claims := map[string]any{
		"sub": "ec-user", "iss": "https://issuer.example.com",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("EC sign: %v", err)
	}
	token := signingInput + "." + enc.EncodeToString(sig)

	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "ec-user" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

func TestOAuth_JWKS_ServerError(t *testing.T) {
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer jwksServer.Close()

	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	token := signHS256Token(t,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": "x"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": now.Add(time.Hour).Unix(),
		},
		"irrelevant",
	)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected error from JWKS server failure")
	}
}

func TestOAuth_JWKS_UnsupportedKeyType(t *testing.T) {
	set := jwkSet{Keys: []jwk{{Kty: "OKP", Kid: "ed-key"}}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if encErr := json.NewEncoder(w).Encode(set); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	}))
	defer jwksServer.Close()

	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	token := signHS256Token(t,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": "ed-key"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": now.Add(time.Hour).Unix(),
		},
		"irrelevant",
	)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected unsupported key type error")
	}
}

func TestOAuth_JWKS_NoMatchingKey(t *testing.T) {
	set := jwkSet{Keys: []jwk{}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if encErr := json.NewEncoder(w).Encode(set); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	}))
	defer jwksServer.Close()

	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	token := signHS256Token(t,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": "nope"},
		map[string]any{
			"sub": "user", "iss": "https://issuer.example.com",
			"exp": now.Add(time.Hour).Unix(),
		},
		"irrelevant",
	)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected no key found error")
	}
}

func TestOAuth_JWKS_PSS_FullFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "pss-kid"
	set := jwkSet{Keys: []jwk{{
		Kty: "RSA", Kid: kid, Alg: "PS256",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if encErr := json.NewEncoder(w).Encode(set); encErr != nil {
			t.Errorf("encode JWKS: %v", encErr)
		}
	}))
	defer srv.Close()

	now := time.Now()
	header := map[string]any{"alg": "PS256", "typ": "JWT", "kid": kid}
	claims := map[string]any{
		"sub": "pss-user", "iss": "https://issuer.example.com",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("PSS sign: %v", err)
	}
	token := signingInput + "." + enc.EncodeToString(sig)

	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthJWKSURL: srv.URL,
	}, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate PSS: %v", err)
	}
	if id.Subject != "pss-user" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

// ── Internal JWT helper tests ────────────────────────────────

func TestContainsAudienceRaw(t *testing.T) {
	if !containsAudienceRaw([]byte(`"single"`), "single") {
		t.Fatal("string audience mismatch")
	}
	if containsAudienceRaw([]byte(`"single"`), "other") {
		t.Fatal("should not match other")
	}
	if !containsAudienceRaw([]byte(`["a","b"]`), "b") {
		t.Fatal("array audience mismatch")
	}
	if containsAudienceRaw([]byte(`["a","b"]`), "c") {
		t.Fatal("should not match c in array")
	}
	if containsAudienceRaw([]byte(`42`), "anything") {
		t.Fatal("int is not a valid audience")
	}
	if containsAudienceRaw(nil, "x") {
		t.Fatal("nil should not match")
	}
}

func TestEllipticCurve_Unsupported(t *testing.T) {
	if _, err := ellipticCurve("P-999"); err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

func TestEqualQuotedBytes(t *testing.T) {
	if !equalQuotedBytes([]byte(`"hello"`), "hello") {
		t.Fatal("should match")
	}
	if equalQuotedBytes([]byte(`"hello"`), "world") {
		t.Fatal("should not match")
	}
	if equalQuotedBytes([]byte(`"hi"`), "hello") {
		t.Fatal("different length should not match")
	}
	if equalQuotedBytes([]byte(`hello`), "hello") {
		t.Fatal("missing quotes should not match")
	}
	if equalQuotedBytes(nil, "") {
		t.Fatal("nil should not match")
	}
}

func TestParseJSONNumber(t *testing.T) {
	if v, ok := parseJSONNumber([]byte("1713052800")); !ok || v != 1713052800 {
		t.Fatalf("integer: %d, %v", v, ok)
	}
	if v, ok := parseJSONNumber([]byte("42.0")); !ok || v != 42 {
		t.Fatalf("float: %d, %v", v, ok)
	}
	if _, ok := parseJSONNumber([]byte("notnum")); ok {
		t.Fatal("notnum should fail")
	}
	if _, ok := parseJSONNumber(nil); ok {
		t.Fatal("nil should fail")
	}
}

func TestAlgFromBytes(t *testing.T) {
	algs := []string{
		"HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
	}
	for _, alg := range algs {
		raw := []byte(`{"alg":"` + alg + `"}`)
		got := algFromBytes(raw, jwtKeyAlg)
		if got != alg {
			t.Fatalf("algFromBytes(%s) = %q", alg, got)
		}
	}
	// Unknown algorithm falls back to string conversion.
	raw := []byte(`{"alg":"EdDSA"}`)
	if got := algFromBytes(raw, jwtKeyAlg); got != "EdDSA" {
		t.Fatalf("unknown alg = %q", got)
	}
	// Missing key.
	if got := algFromBytes([]byte(`{}`), jwtKeyAlg); got != "" {
		t.Fatalf("missing key = %q", got)
	}
}

func TestEllipticCurve_AllSupported(t *testing.T) {
	for _, crv := range []string{"P-256", "P-384", "P-521"} {
		if _, err := ellipticCurve(crv); err != nil {
			t.Fatalf("curve %s: %v", crv, err)
		}
	}
}

func TestHashJWT_Unsupported(t *testing.T) {
	var buf [64]byte
	if _, _, err := hashJWT("XX999", []byte("input"), buf[:]); err == nil {
		t.Fatal("expected error for unsupported alg")
	}
}

func TestHashJWT_AllSupported(t *testing.T) {
	algs := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
	for _, alg := range algs {
		var buf [64]byte
		if _, _, err := hashJWT(alg, []byte("input"), buf[:]); err != nil {
			t.Fatalf("alg %s: %v", alg, err)
		}
	}
}

func TestFindKey_NoKidFallback(t *testing.T) {
	keys := map[string]jwkPublicKey{"k1": {key: "dummy", alg: "RS256"}}
	key, ok := findKey(keys, "", "RS256")
	if !ok || key != "dummy" {
		t.Fatalf("findKey fallback: ok=%v, key=%v", ok, key)
	}
}

func TestFindKey_WrongAlg(t *testing.T) {
	keys := map[string]jwkPublicKey{"k1": {key: "dummy", alg: "ES256"}}
	_, ok := findKey(keys, "k1", "RS256")
	if ok {
		t.Fatal("expected no match for wrong alg")
	}
}

func TestVerifyRSASignature_PSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	digest := sha256.Sum256([]byte("header.payload"))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	if err := verifyRSASignature("PS256", &key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("PS256 verify: %v", err)
	}
}

func TestVerifyJWKS_UnsupportedPublicKeyType(t *testing.T) {
	a := &oauthAuthenticator{
		keys:       map[string]jwkPublicKey{"bad": {key: "not-a-public-key", alg: "RS256"}},
		keysExpiry: time.Now().Add(5 * time.Minute),
	}

	err := a.verifyJWKS(context.Background(), "RS256", "bad", []byte("h.p"), []byte("sig"), make([]byte, 64))
	if err == nil || !strings.Contains(err.Error(), "unsupported JWT public key type") {
		t.Fatalf("expected unsupported key type error, got %v", err)
	}
}

func TestVerifyJWKS_HashJWTError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	a := &oauthAuthenticator{
		keys:       map[string]jwkPublicKey{"kid": {key: &key.PublicKey, alg: ""}},
		keysExpiry: time.Now().Add(5 * time.Minute),
	}
	err = a.verifyJWKS(context.Background(), "XX999", "kid", []byte("h.p"), []byte("sig"), make([]byte, 64))
	if err == nil || !strings.Contains(err.Error(), "unsupported JWT algorithm") {
		t.Fatalf("expected unsupported alg error, got %v", err)
	}
}

func TestVerifyJWKS_ECVerifyFailure(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	a := &oauthAuthenticator{
		keys:       map[string]jwkPublicKey{"ec-kid": {key: &ecKey.PublicKey, alg: "ES256"}},
		keysExpiry: time.Now().Add(5 * time.Minute),
	}
	err = a.verifyJWKS(context.Background(), "ES256", "ec-kid", []byte("h.p"), []byte("bad-sig"), make([]byte, 64))
	if err == nil || !strings.Contains(err.Error(), "invalid JWT signature") {
		t.Fatalf("expected signature verify error, got %v", err)
	}
}

func TestParseRSAKey_InvalidN(t *testing.T) {
	if _, err := parseRSAKey(&jwk{N: "!!!", E: "AQAB"}); err == nil {
		t.Fatal("expected error for invalid N")
	}
}

func TestParseRSAKey_InvalidE(t *testing.T) {
	if _, err := parseRSAKey(&jwk{N: "AQAB", E: "!!!"}); err == nil {
		t.Fatal("expected error for invalid E")
	}
}

func TestParseECKey_InvalidCurve(t *testing.T) {
	if _, err := parseECKey(&jwk{Crv: "P-999", X: "AQAB", Y: "AQAB"}); err == nil {
		t.Fatal("expected error for invalid curve")
	}
}

func TestParseECKey_InvalidX(t *testing.T) {
	if _, err := parseECKey(&jwk{Crv: "P-256", X: "!!!", Y: "AQAB"}); err == nil {
		t.Fatal("expected error for invalid X")
	}
}

func TestParseECKey_InvalidY(t *testing.T) {
	if _, err := parseECKey(&jwk{Crv: "P-256", X: "AQAB", Y: "!!!"}); err == nil {
		t.Fatal("expected error for invalid Y")
	}
}

func TestDecodeBase64Int_Invalid(t *testing.T) {
	if _, err := decodeBase64Int("!!!invalid!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseJWTHeaderDirect_LargePayload(t *testing.T) {
	hdr := map[string]any{"alg": "RS256", "kid": "big", "extra": strings.Repeat("x", 200)}
	hdrJSON, mErr := json.Marshal(hdr)
	if mErr != nil {
		t.Fatalf("marshal: %v", mErr)
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(hdrJSON))
	h, err := parseJWTHeaderDirect(encoded)
	if err != nil {
		t.Fatalf("parseJWTHeaderDirect: %v", err)
	}
	if h.Alg != "RS256" {
		t.Fatalf("expected RS256, got %q", h.Alg)
	}
}

func TestValidateToken_ExtraDotInSignature(t *testing.T) {
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer header.payload.sig.extra")
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected error for extra dot")
	}
}

func TestValidateToken_InvalidClaimsJSON(t *testing.T) {
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{not json"))
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	signingInput := header + "." + invalidJSON
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected error for invalid claims JSON")
	}
}

func TestRefreshKeys_DoubleCheck(t *testing.T) {
	key, genErr := rsa.GenerateKey(rand.Reader, 2048)
	if genErr != nil {
		t.Fatalf("generate key: %v", genErr)
	}
	a := &oauthAuthenticator{
		httpClient: http.DefaultClient,
		keys:       map[string]jwkPublicKey{"kid": {key: &key.PublicKey, alg: "RS256"}},
		keysExpiry: time.Now().Add(5 * time.Minute),
	}
	keys, err := a.refreshKeys(context.Background())
	if err != nil {
		t.Fatalf("refreshKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestRefreshKeys_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	a := &oauthAuthenticator{httpClient: srv.Client(), jwksURL: srv.URL}
	if _, err := a.refreshKeys(context.Background()); err == nil {
		t.Fatal("expected non-200 error")
	}
}

func TestRefreshKeys_JSONDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, fErr := fmt.Fprint(w, "not json{{{"); fErr != nil {
			t.Errorf("fprint: %v", fErr)
		}
	}))
	defer srv.Close()
	a := &oauthAuthenticator{httpClient: srv.Client(), jwksURL: srv.URL}
	if _, err := a.refreshKeys(context.Background()); err == nil {
		t.Fatal("expected JSON decode error")
	}
}

func TestRefreshKeys_ParseJWKSError(t *testing.T) {
	set := jwkSet{Keys: []jwk{{Kty: "UNSUPPORTED"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if encErr := json.NewEncoder(w).Encode(set); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	}))
	defer srv.Close()
	a := &oauthAuthenticator{httpClient: srv.Client(), jwksURL: srv.URL}
	if _, err := a.refreshKeys(context.Background()); err == nil {
		t.Fatal("expected parseJWKS error")
	}
}

func TestRefreshKeys_NewRequestError(t *testing.T) {
	a := &oauthAuthenticator{httpClient: http.DefaultClient, jwksURL: "http://\x01"}
	if _, err := a.refreshKeys(context.Background()); err == nil {
		t.Fatal("expected NewRequestWithContext error")
	}
}

func TestRefreshKeys_DoError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &oauthAuthenticator{httpClient: http.DefaultClient, jwksURL: "http://localhost:1/jwks"}
	if _, err := a.refreshKeys(ctx); err == nil {
		t.Fatal("expected Do error from canceled context")
	}
}

func TestRefreshKeys_OIDCDiscovery(t *testing.T) {
	// When jwksURL is empty, refreshKeys should discover via OIDC.
	key, genErr := rsa.GenerateKey(rand.Reader, 2048)
	if genErr != nil {
		t.Fatalf("generate key: %v", genErr)
	}
	kid := "disc-kid"

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if encErr := json.NewEncoder(w).Encode(map[string]any{
			"issuer":   "https://issuer.example.com",
			"jwks_uri": "http://" + r.Host + "/jwks",
		}); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	})
	mux.HandleFunc("/jwks", rsaJWKSHandler(t, &key.PublicKey, kid))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := &oauthAuthenticator{
		httpClient: srv.Client(),
		issuer:     srv.URL,
	}
	keys, err := a.refreshKeys(context.Background())
	if err != nil {
		t.Fatalf("refreshKeys with OIDC: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestRefreshKeys_OIDCDiscoveryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := &oauthAuthenticator{httpClient: srv.Client(), issuer: srv.URL}
	if _, err := a.refreshKeys(context.Background()); err == nil {
		t.Fatal("expected OIDC discovery failure")
	}
}

func TestCurrentKeys_CacheHit(t *testing.T) {
	key, genErr := rsa.GenerateKey(rand.Reader, 2048)
	if genErr != nil {
		t.Fatalf("generate key: %v", genErr)
	}
	a := &oauthAuthenticator{
		httpClient: http.DefaultClient,
		keys:       map[string]jwkPublicKey{"kid": {key: &key.PublicKey, alg: "RS256"}},
		keysExpiry: time.Now().Add(5 * time.Minute),
	}
	keys, err := a.currentKeys(context.Background())
	if err != nil {
		t.Fatalf("currentKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 cached key, got %d", len(keys))
	}
}

func TestParseJWKS_NamelessKey(t *testing.T) {
	set := jwkSet{Keys: []jwk{{
		Kty: "RSA", Kid: "", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(big.NewInt(12345).Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
	}}}
	keys, err := parseJWKS(set)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if _, ok := keys["key-0"]; !ok {
		t.Fatalf("expected key 'key-0', got keys %v", keys)
	}
}

func TestParseJWKS_InnerJWKError(t *testing.T) {
	set := jwkSet{Keys: []jwk{
		{Kty: "RSA", Kid: "ok", N: "AQAB", E: "AQAB"},
		{Kty: "UNKNOWN", Kid: "bad"},
	}}
	if _, err := parseJWKS(set); err == nil {
		t.Fatal("expected error from bad JWK")
	}
}

func TestLookupKey_RefreshFailsAfterCacheMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	a := &oauthAuthenticator{
		httpClient: srv.Client(),
		jwksURL:    srv.URL,
		keys:       map[string]jwkPublicKey{"kid": {key: "dummy", alg: "ES256"}},
		keysExpiry: time.Now().Add(5 * time.Minute),
	}
	if _, err := a.lookupKey(context.Background(), "kid", "RS256"); err == nil {
		t.Fatal("expected lookup error after refresh failure")
	}
}

func TestParseJWK_UnsupportedKty(t *testing.T) {
	if _, err := parseJWK(&jwk{Kty: "OKP"}); err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// ── OIDC full integration test ───────────────────────────────

func TestOAuth_OIDC_AutoDiscovery(t *testing.T) {
	// Full end-to-end: issuer only, no JWKS URL → OIDC discovery → JWKS fetch → token validation.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "oidc-kid"

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if encErr := json.NewEncoder(w).Encode(map[string]any{
			"issuer":   "https://issuer.example.com",
			"jwks_uri": "http://" + r.Host + "/jwks",
		}); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	})
	mux.HandleFunc("/jwks", rsaJWKSHandler(t, &key.PublicKey, kid))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	now := time.Now()
	token := signRSAToken(t, key, kid, map[string]any{
		"sub": "oidc-user", "iss": "https://issuer.example.com",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})

	a, err := New(&Config{
		Mode:        ModeOAuth,
		OAuthIssuer: "https://issuer.example.com",
	}, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Override issuer URL for test server (the authenticator uses issuer for OIDC discovery).
	oa, ok := a.(*oauthAuthenticator)
	if !ok {
		t.Fatal("expected *oauthAuthenticator")
	}
	oa.issuer = srv.URL
	// Keep the expected issuer for claim validation.
	origIssuer := "https://issuer.example.com"
	_ = origIssuer

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	// The token's issuer claim is "https://issuer.example.com" but the authenticator
	// validates against its own issuer field. We need them to match for validation.
	oa.issuer = "https://issuer.example.com"

	// Force the JWKS URL to resolve through OIDC discovery via the test server.
	// We set jwksURL empty so refreshKeys triggers OIDC discovery.
	oa.jwksURL = ""
	// Point to the test server for OIDC discovery.
	oa.issuer = srv.URL

	// Create a token with srv.URL as issuer so it matches.
	token2 := signRSAToken(t, key, kid, map[string]any{
		"sub": "oidc-user", "iss": srv.URL,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})
	req2 := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req2.Header.Set("Authorization", "Bearer "+token2)
	id, err := a.Authenticate(req2)
	if err != nil {
		t.Fatalf("Authenticate via OIDC discovery: %v", err)
	}
	if id.Subject != "oidc-user" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

func TestValidateToken_OversizedToken(t *testing.T) {
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	oversized := "Bearer " + strings.Repeat("A", maxJWTSize+1)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", oversized)
	_, err = a.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for oversized token")
	}
}

func TestOAuth_ScopeFromSCPArray(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user-1", "iss": "https://issuer.example.com",
			"scp": []string{"read", "write"},
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Scopes != "read write" {
		t.Fatalf("Scopes = %q, want %q", id.Scopes, "read write")
	}
}

func TestOAuth_NoSubjectNoScopes(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"iss": "https://issuer.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "" {
		t.Fatalf("Subject = %q, want empty", id.Subject)
	}
	if id.Scopes != "" {
		t.Fatalf("Scopes = %q, want empty", id.Scopes)
	}
}

func TestBearerToken_WrongScheme(t *testing.T) {
	_, ok := bearerToken("Xearer my-token")
	if ok {
		t.Fatal("expected false for wrong scheme")
	}
}

func TestApiKeyToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"valid", "ApiKey my-key", "my-key", true},
		{"valid_lowercase", "apikey my-key", "my-key", true},
		{"valid_uppercase", "APIKEY my-key", "my-key", true},
		{"too_short", "Api", "", false},
		{"no_space", "ApiKeyX", "", false},
		{"wrong_scheme", "NotKey token", "", false},
		{"empty", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := apiKeyToken(tc.header)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("apiKeyToken(%q) = (%q, %v), want (%q, %v)", tc.header, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestContainsScope_EmptyScopes(t *testing.T) {
	if containsScope("", "read") {
		t.Fatal("expected false for empty scopes")
	}
}

func TestParseJWTHeaderDirect_WhitespaceJSON(t *testing.T) {
	// Header with spaces around colon — algFromBytes won't match, falls back to parseJWTHeaderSlow.
	raw := []byte(`{"alg" : "HS256", "typ":"JWT"}`)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	h, err := parseJWTHeaderDirect([]byte(encoded))
	if err != nil {
		t.Fatalf("parseJWTHeaderDirect: %v", err)
	}
	if h.Alg != "HS256" {
		t.Fatalf("Alg = %q, want %q", h.Alg, "HS256")
	}
}

func TestParseJWTHeaderSlow_InvalidBase64(t *testing.T) {
	// Create encoded data that decodes to >128 bytes (forces slow path)
	// but is invalid base64.
	large := strings.Repeat("A", 200) + "!!!"
	_, err := parseJWTHeaderSlow([]byte(large))
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseJWTHeaderSlow_InvalidJSON(t *testing.T) {
	raw := make([]byte, 200)
	for i := range raw {
		raw[i] = 'x'
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	_, err := parseJWTHeaderSlow([]byte(encoded))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestAlgFromBytes_Truncated(t *testing.T) {
	// Key "alg":" at end of data with no value after.
	alg := algFromBytes([]byte(`{"alg":"`), jwtKeyAlg)
	if alg != "" {
		t.Fatalf("algFromBytes truncated = %q, want empty", alg)
	}
}

func TestAlgFromBytes_NoClosingQuote(t *testing.T) {
	alg := algFromBytes([]byte(`{"alg":"RS256`), jwtKeyAlg)
	if alg != "" {
		t.Fatalf("algFromBytes no closing quote = %q, want empty", alg)
	}
}

func TestJsonStringValue_Truncated(t *testing.T) {
	v := jsonStringValue([]byte(`{"kid":"`), jwtKeyKid)
	if v != "" {
		t.Fatalf("jsonStringValue truncated = %q, want empty", v)
	}
}

func TestJsonStringValue_NoClosingQuote(t *testing.T) {
	v := jsonStringValue([]byte(`{"kid":"test`), jwtKeyKid)
	if v != "" {
		t.Fatalf("jsonStringValue no closing quote = %q, want empty", v)
	}
}

func TestJsonStringValue_WithEscape(t *testing.T) {
	v := jsonStringValue([]byte(`{"kid":"test\\kid"}`), jwtKeyKid)
	if v != "" {
		t.Fatalf("jsonStringValue with escape = %q, want empty", v)
	}
}

func TestValidateToken_InvalidBase64Payload(t *testing.T) {
	// Token with valid HMAC signature but invalid base64 payload.
	// Exercises the base64 payload decode error path in validateToken.
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	invalidPayload := "!!!"
	signingInput := header + "." + invalidPayload
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(signingInput))
	token := signingInput + "." + enc.EncodeToString(mac.Sum(nil))

	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, authErr := a.Authenticate(req); authErr == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestOAuth_ScopeFromSCPArray_EmptyElements(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub": "user-1",
			"iss": "https://issuer.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
			"scp": []string{"read", "", "write"},
		},
		"secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: "https://issuer.example.com", OAuthHMACSecret: "secret"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, authErr := a.Authenticate(req)
	if authErr != nil {
		t.Fatalf("Authenticate: %v", authErr)
	}
	if id.Scopes != "read write" {
		t.Fatalf("Scopes = %q, want %q", id.Scopes, "read write")
	}
}

// closeErrBody wraps an io.Reader with a Close that always errors.
// Used to test the defer { resp.Body.Close() } error propagation.
type closeErrBody struct{ io.Reader }

func (b *closeErrBody) Close() error { return errors.New("close error") }

// closeErrTransport returns a fixed HTTP response with an erroring Body.Close.
type closeErrTransport struct {
	body       string
	statusCode int
}

func (t *closeErrTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.statusCode,
		Body:       &closeErrBody{Reader: strings.NewReader(t.body)},
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func TestFetchAndParseJWKS_CloseError(t *testing.T) {
	a := &oauthAuthenticator{
		jwksURL: "https://example.com/jwks",
		httpClient: &http.Client{Transport: &closeErrTransport{
			body:       `{"keys":[]}`,
			statusCode: http.StatusOK,
		}},
	}
	_, err := a.fetchAndParseJWKS(context.Background())
	if err == nil {
		t.Fatal("expected error from Body.Close")
	}
	if !strings.Contains(err.Error(), "close error") {
		t.Fatalf("unexpected error: %v", err)
	}
}
