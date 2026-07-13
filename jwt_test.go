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

func signHS256Token(tb testing.TB, header, claims map[string]any, secret string) string {
	tb.Helper()

	headerJSON, err := json.Marshal(header)
	if err != nil {
		tb.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		tb.Fatalf("marshal claims: %v", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		tb.Fatalf("mac.Write: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil))
}

func signRSAToken(
	t *testing.T, key *rsa.PrivateKey, kid string,
	claims map[string]any,
) string {
	t.Helper()
	header := map[string]any{testClaimAlg: algRS256, testClaimTyp: testHeaderJWT, testClaimKid: kid}
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
			Kty: jwkTypeRSA,
			Kid: kid,
			Alg: algRS256,
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}}
		w.Header().Set("Content-Type", testTypeJSON)
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	}
}

func TestOAuthHMACAuthenticator(t *testing.T) {
	now := time.Now()
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: "user-123",
			testClaimIss: testIssuerURL,
			testClaimAud: []string{testMCPServer},
			"scope":      "mcp:read mcp:write",
			testClaimIat: now.Unix(),
			"nbf":        now.Add(-time.Minute).Unix(),
			testClaimExp: now.Add(time.Hour).Unix(),
		},
		"top-secret",
	)

	a, err := New(&Config{
		Mode:                      ModeOAuth,
		OAuthIssuer:               testIssuerURL,
		OAuthAudience:             testMCPServer,
		OAuthHMACSecret:           "top-secret",
		OAuthRequiredScopes:       []string{testScopeMCPRead},
		OAuthResourceName:         "MCP Server",
		OAuthAuthorizationServers: []string{testIssuerURL},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := newReq(t, http.MethodGet, "https://mcp.example.com/jsonrpc", http.NoBody)
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
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != testIssuerURL {
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
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL}, nil)
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
		OAuthIssuer:     testIssuerURL,
		OAuthHMACSecret: testSecret,
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
		OAuthIssuer:     testIssuerURL,
		OAuthHMACSecret: testSecret,
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
		OAuthIssuer:               testIssuerURL,
		OAuthHMACSecret:           testSecret,
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
		OAuthIssuer:               testIssuerURL,
		OAuthHMACSecret:           testSecret,
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
		OAuthIssuer:     testIssuerURL,
		OAuthHMACSecret: testSecret,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tests := []struct {
		name  string
		token string
	}{
		{testEmpty, ""},
		{"no dots", "foobar"},
		{"one dot", "foo.bar"},
		{"bad header b64", "!!!.YQ.YQ"},
		{"bad sig b64", "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ4In0.!!!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		OAuthIssuer:     testIssuerURL,
		OAuthHMACSecret: testSecret,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestOAuth_ExpiredToken(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(-time.Hour).Unix(),
			testClaimIat: time.Now().Add(-2 * time.Hour).Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected token expired error")
	}
}

func TestOAuth_WrongIssuer(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: "https://wrong.example.com",
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected issuer error")
	}
}

func TestOAuth_WrongAudience(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL, testClaimAud: "other",
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL,
		OAuthAudience: testMCPServer, OAuthHMACSecret: testSecret,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected audience error")
	}
}

func TestOAuth_WrongSignature(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
		},
		"wrong-secret",
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected signature error")
	}
}

func TestOAuth_UnsupportedHMACAlg(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: "HS999", testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(time.Hour).Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		{sha512.New384, algHS384},
		{sha512.New, algHS512},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			now := time.Now()
			header := map[string]any{testClaimAlg: tc.alg, testClaimTyp: testHeaderJWT}
			claims := map[string]any{
				testClaimSub: testUser, testClaimIss: testIssuerURL,
				testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
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
			mac := hmac.New(tc.hasher, []byte(testSecret))
			_, _ = mac.Write([]byte(signingInput))
			token := signingInput + "." + enc.EncodeToString(mac.Sum(nil))

			a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := newReq(t, http.MethodGet, "/", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+token)
			id, err := a.Authenticate(req)
			if err != nil {
				t.Fatalf("Authenticate %s: %v", tc.alg, err)
			}
			if id.Subject != testUser {
				t.Fatalf("Subject = %q", id.Subject)
			}
		})
	}
}

func TestOAuth_TokenNotBeforeViolation(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			"nbf":        time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected nbf error")
	}
}

func TestOAuth_TokenIssuedInFuture(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(2 * time.Hour).Unix(),
			testClaimIat: time.Now().Add(time.Hour).Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected iat-in-future error")
	}
}

func TestOAuth_ScopeFromSCPClaim(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
			"scp":        testReadW,
		},
		testSecret,
	)
	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL,
		OAuthHMACSecret: testSecret, OAuthRequiredScopes: []string{testRead},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(id.Scopes) == 0 {
		t.Fatal("expected scopes")
	}
}

func TestOAuth_SubjectFallbacks(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"client_id", map[string]any{"client_id": testClient}, testClient},
		{"azp", map[string]any{"azp": "my-azp-client"}, "my-azp-client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.claims[testClaimIss] = testIssuerURL
			tc.claims[testClaimExp] = time.Now().Add(time.Hour).Unix()
			tc.claims[testClaimIat] = time.Now().Unix()
			token := signHS256Token(t,
				map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT}, tc.claims, testSecret)
			a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aErr := unauthorisedError("bad token")
	status, header, msg := a.Challenge(aErr, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(header, schemeBearer) {
		t.Fatalf("header = %q", header)
	}
	if msg != "bad token" {
		t.Fatalf("msg = %q", msg)
	}
}

func TestOAuthAuthenticator_RejectsMissingScope(t *testing.T) {
	now := time.Now()
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: "user-123",
			testClaimIss: testIssuerURL,
			testClaimAud: testMCPServer,
			"scope":      testScopeMCPRead,
			testClaimIat: now.Unix(),
			testClaimExp: now.Add(time.Hour).Unix(),
		},
		"top-secret",
	)

	a, err := New(&Config{
		Mode:                ModeOAuth,
		OAuthIssuer:         testIssuerURL,
		OAuthAudience:       testMCPServer,
		OAuthHMACSecret:     "top-secret",
		OAuthRequiredScopes: []string{"mcp:admin"},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := newReq(t, http.MethodGet, "https://mcp.example.com/jsonrpc", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = a.Authenticate(req)
	if err == nil {
		t.Fatal("expected scope validation error")
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Fatalf("expected scope error, got %v", err)
	}
}

func TestOAuth_JWKS_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	jwksServer := httptest.NewServer(rsaJWKSHandler(t, &key.PublicKey, "test-kid"))
	defer jwksServer.Close()

	now := time.Now()
	token := signRSAToken(t, key, "test-kid", map[string]any{
		testClaimSub: "rsa-user", testClaimIss: testIssuerURL,
		testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
	})

	a, err := New(&Config{
		Mode:         ModeOAuth,
		OAuthIssuer:  testIssuerURL,
		OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		testClaimSub: testUser, testClaimIss: testIssuerURL,
		testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
	})

	a, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected verification error with wrong key")
	}
}

func TestOAuth_JWKS_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	kid := "ec-kid"
	enc := base64.RawURLEncoding
	set := jwkSet{Keys: []jwk{{
		Kty: jwkTypeEC, Crv: "P-256", Kid: kid, Alg: algES256,
		X: enc.EncodeToString(key.X.Bytes()),
		Y: enc.EncodeToString(key.Y.Bytes()),
	}}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testTypeJSON)
		if encErr := json.NewEncoder(w).Encode(set); encErr != nil {
			t.Errorf("encode JWKS: %v", encErr)
		}
	}))
	defer jwksServer.Close()

	now := time.Now()
	header := map[string]any{testClaimAlg: algES256, testClaimTyp: testHeaderJWT, testClaimKid: kid}
	claims := map[string]any{
		testClaimSub: "ec-user", testClaimIss: testIssuerURL,
		testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
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
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algRS256, testClaimTyp: testHeaderJWT, testClaimKid: "x"},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: now.Add(time.Hour).Unix(),
		},
		"irrelevant",
	)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algRS256, testClaimTyp: testHeaderJWT, testClaimKid: "ed-key"},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: now.Add(time.Hour).Unix(),
		},
		"irrelevant",
	)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algRS256, testClaimTyp: testHeaderJWT, testClaimKid: "nope"},
		map[string]any{
			testClaimSub: testUser, testClaimIss: testIssuerURL,
			testClaimExp: now.Add(time.Hour).Unix(),
		},
		"irrelevant",
	)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
		Kty: jwkTypeRSA, Kid: kid, Alg: algPS256,
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
	header := map[string]any{testClaimAlg: algPS256, testClaimTyp: testHeaderJWT, testClaimKid: kid}
	claims := map[string]any{
		testClaimSub: "pss-user", testClaimIss: testIssuerURL,
		testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
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
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthJWKSURL: srv.URL,
	}, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate PSS: %v", err)
	}
	if id.Subject != "pss-user" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

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

func TestValidateTimeBound_PastIsAccepted(t *testing.T) {
	if err := validateTimeBound([]byte("1"), 1_000_000_000, jwtClockSkewSec, errTokenNotYetValid); err != nil {
		t.Fatalf("past timestamp must be accepted: %v", err)
	}
}

func TestValidateTimeBound_FutureBeyondSkew(t *testing.T) {
	now := int64(1_000_000_000)
	if err := validateTimeBound([]byte("1000000060"), now, jwtClockSkewSec, errTokenNotYetValid); err == nil {
		t.Fatal("future > skew must fail")
	}
}

func TestValidateTimeBound_FutureFloat(t *testing.T) {
	now := int64(1_000_000_000)
	if err := validateTimeBound([]byte("1000000060.0"), now, jwtClockSkewSec, errTokenNotYetValid); err == nil {
		t.Fatal("future float > skew must fail")
	}
}

// TestValidateTimeBound_Malformed pins the new strict semantics: a present
// but unparseable JWT time claim is rejected.
func TestValidateTimeBound_Malformed(t *testing.T) {
	if err := validateTimeBound([]byte("notnum"), 1, jwtClockSkewSec, errTokenNotYetValid); err == nil {
		t.Fatal("malformed timestamp must be rejected")
	}
}

func TestDecodeAlg(t *testing.T) {
	algs := []string{
		algHS256, algHS384, algHS512,
		algRS256, algRS384, algRS512,
		algES256, algES384, algES512,
		algPS256, algPS384, algPS512,
	}
	for _, alg := range algs {
		raw := []byte(`"` + alg + `"`)
		if got := decodeAlg(raw); got != alg {
			t.Fatalf("decodeAlg(%s) = %q", alg, got)
		}
	}
	if got := decodeAlg([]byte(`"EdDSA"`)); got != "EdDSA" {
		t.Fatalf("unknown alg = %q", got)
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
	algs := []string{algRS256, algRS384, algRS512, algPS256, algPS384, algPS512, algES256, algES384, algES512}
	for _, alg := range algs {
		var buf [64]byte
		if _, _, err := hashJWT(alg, []byte("input"), buf[:]); err != nil {
			t.Fatalf("alg %s: %v", alg, err)
		}
	}
}

func TestFindKey_NoKidFallback(t *testing.T) {
	keys := map[string]jwkPublicKey{"k1": {key: testDummy, alg: algRS256}}
	key, ok := findKey(keys, "", algRS256)
	if !ok || key != testDummy {
		t.Fatalf("findKey fallback: ok=%v, key=%v", ok, key)
	}
}

func TestFindKey_WrongAlg(t *testing.T) {
	keys := map[string]jwkPublicKey{"k1": {key: testDummy, alg: algES256}}
	_, ok := findKey(keys, "k1", algRS256)
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
	if err := verifyRSASignature(algPS256, &key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("PS256 verify: %v", err)
	}
}

func TestVerifyJWKS_UnsupportedPublicKeyType(t *testing.T) {
	a := &oauthAuthenticator{}
	a.seedKeysForTest(map[string]jwkPublicKey{"bad": {key: "not-a-public-key", alg: algRS256}})

	err := a.verifyJWKS(context.Background(), algRS256, "bad", []byte("h.p"), []byte("sig"), make([]byte, 64))
	if err == nil || !strings.Contains(err.Error(), "unsupported JWT public key type") {
		t.Fatalf("expected unsupported key type error, got %v", err)
	}
}

func TestVerifyJWKS_HashJWTError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	a := &oauthAuthenticator{}
	a.seedKeysForTest(map[string]jwkPublicKey{testClaimKid: {key: &key.PublicKey, alg: ""}})
	err = a.verifyJWKS(context.Background(), "XX999", testClaimKid, []byte("h.p"), []byte("sig"), make([]byte, 64))
	if err == nil || !strings.Contains(err.Error(), "unsupported JWT algorithm") {
		t.Fatalf("expected unsupported alg error, got %v", err)
	}
}

func TestVerifyJWKS_ECVerifyFailure(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	a := &oauthAuthenticator{}
	a.seedKeysForTest(map[string]jwkPublicKey{"ec-kid": {key: &ecKey.PublicKey, alg: algES256}})
	err = a.verifyJWKS(context.Background(), algES256, "ec-kid", []byte("h.p"), []byte("bad-sig"), make([]byte, 64))
	if err == nil || !strings.Contains(err.Error(), "invalid JWT signature") {
		t.Fatalf("expected signature verify error, got %v", err)
	}
}

func TestParseRSAKey_InvalidN(t *testing.T) {
	if _, err := parseRSAKey("!!!", "AQAB"); err == nil {
		t.Fatal("expected error for invalid N")
	}
}

func TestParseRSAKey_InvalidE(t *testing.T) {
	if _, err := parseRSAKey("AQAB", "!!!"); err == nil {
		t.Fatal("expected error for invalid E")
	}
}

func TestParseRSAKey_WeakExponent(t *testing.T) {
	if _, err := parseRSAKey("AQAB", "AQ"); err == nil {
		t.Fatal("expected weak-exponent rejection")
	}
}

func TestParseECKey_InvalidCurve(t *testing.T) {
	if _, err := parseECKey("P-999", "AQAB", "AQAB"); err == nil {
		t.Fatal("expected error for invalid curve")
	}
}

func TestParseECKey_InvalidX(t *testing.T) {
	if _, err := parseECKey("P-256", "!!!", "AQAB"); err == nil {
		t.Fatal("expected error for invalid X")
	}
}

func TestParseECKey_InvalidY(t *testing.T) {
	if _, err := parseECKey("P-256", "AQAB", "!!!"); err == nil {
		t.Fatal("expected error for invalid Y")
	}
}

func TestDecodeBase64Int_Invalid(t *testing.T) {
	if _, err := decodeBase64Int("!!!invalid!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseJWTHeaderDirect_LargePayload(t *testing.T) {
	hdr := map[string]any{testClaimAlg: algRS256, testClaimKid: "big", "extra": strings.Repeat("x", 200)}
	hdrJSON, mErr := json.Marshal(hdr)
	if mErr != nil {
		t.Fatalf("marshal: %v", mErr)
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(hdrJSON))
	h, err := parseJWTHeader(encoded)
	if err != nil {
		t.Fatalf("parseJWTHeader: %v", err)
	}
	if h.Alg != algRS256 {
		t.Fatalf("expected RS256, got %q", h.Alg)
	}
}

func TestValidateToken_ExtraDotInSignature(t *testing.T) {
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer header.payload.sig.extra")
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected error for extra dot")
	}
}

func TestValidateToken_InvalidClaimsJSON(t *testing.T) {
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{not json"))
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	signingInput := header + "." + invalidJSON
	mac := hmac.New(sha256.New, []byte(testSecret))
	_, _ = mac.Write([]byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
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
	}
	a.seedKeysForTest(map[string]jwkPublicKey{testClaimKid: {key: &key.PublicKey, alg: algRS256}})
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
		w.Header().Set("Content-Type", testTypeJSON)
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
			testIssuerField:  testIssuerURL,
			testJWKSURIField: "http://" + r.Host + "/jwks",
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
	}
	a.seedKeysForTest(map[string]jwkPublicKey{testClaimKid: {key: &key.PublicKey, alg: algRS256}})
	keys, err := a.currentKeys(context.Background())
	if err != nil {
		t.Fatalf("currentKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 cached key, got %d", len(keys))
	}
}

func TestParseJWKS_NamelessKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set := jwkSet{Keys: []jwk{{
		Kty: jwkTypeRSA, Kid: "", Alg: algRS256,
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys, err := parseJWKSBytes(data)
	if err != nil {
		t.Fatalf("parseJWKSBytes: %v", err)
	}
	if _, ok := keys["key-0"]; !ok {
		t.Fatalf("expected key 'key-0', got keys %v", keys)
	}
}

func TestParseRSAKey_RejectsWeakModulus(t *testing.T) {
	if _, err := parseRSAKey("AQAB", "AQAB"); !errors.Is(err, errRSAModulusWeak) {
		t.Fatalf("expected errRSAModulusWeak, got %v", err)
	}
}

func TestParseJWKS_InnerJWKError(t *testing.T) {
	set := jwkSet{Keys: []jwk{
		{Kty: jwkTypeRSA, Kid: "ok", N: "AQAB", E: "AQAB"},
		{Kty: "UNKNOWN", Kid: "bad"},
	}}
	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseJWKSBytes(data); err == nil {
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
	}
	a.seedKeysForTest(map[string]jwkPublicKey{testClaimKid: {key: testDummy, alg: algES256}})
	if _, err := a.lookupKey(context.Background(), testClaimKid, algRS256); err == nil {
		t.Fatal("expected lookup error after refresh failure")
	}
}

func TestParseJWK_UnsupportedKty(t *testing.T) {
	if _, _, _, err := parseJWKObject([]byte(`{"kty":"OKP","kid":"x"}`), 0); err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestOAuth_OIDC_AutoDiscovery(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "oidc-kid"

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if encErr := json.NewEncoder(w).Encode(map[string]any{
			testIssuerField:  testIssuerURL,
			testJWKSURIField: "http://" + r.Host + "/jwks",
		}); encErr != nil {
			t.Errorf("encode: %v", encErr)
		}
	})
	mux.HandleFunc("/jwks", rsaJWKSHandler(t, &key.PublicKey, kid))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL}, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	oa, ok := a.(*oauthAuthenticator)
	if !ok {
		t.Fatal("expected *oauthAuthenticator")
	}
	oa.jwksURL = ""
	oa.issuer = srv.URL

	now := time.Now()
	token := signRSAToken(t, key, kid, map[string]any{
		testClaimSub: "oidc-user", testClaimIss: srv.URL,
		testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
	})
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate via OIDC discovery: %v", err)
	}
	if id.Subject != "oidc-user" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

func TestValidateToken_OversizedToken(t *testing.T) {
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	oversized := "Bearer " + strings.Repeat("A", maxJWTSize+1)
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", oversized)
	_, err = a.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for oversized token")
	}
}

func TestOAuth_ScopeFromSCPArray(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser1, testClaimIss: testIssuerURL,
			"scp":        []string{testRead, testWrite},
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := strings.Join(id.Scopes, " "); got != testReadW {
		t.Fatalf("Scopes = %q, want %q", got, testReadW)
	}
}

func TestOAuth_NoSubjectNoScopes(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "" {
		t.Fatalf("Subject = %q, want empty", id.Subject)
	}
	if len(id.Scopes) != 0 {
		t.Fatalf("Scopes = %v, want empty", id.Scopes)
	}
}

func TestBearerToken_WrongScheme(t *testing.T) {
	_, ok := parseAuthScheme("Xearer my-token", "bearer")
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
		{"valid", "ApiKey my-key", testMyKey, true},
		{"valid_lowercase", "apikey my-key", testMyKey, true},
		{"valid_uppercase", "APIKEY my-key", testMyKey, true},
		{"too_short", "Api", "", false},
		{"no_space", "ApiKeyX", "", false},
		{"wrong_scheme", "NotKey token", "", false},
		{testEmpty, "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseAuthScheme(tc.header, "apikey")
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseAuthScheme(%q, %q) = (%q, %v), want (%q, %v)", tc.header, "apikey", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestParseJWTHeaderDirect_WhitespaceJSON(t *testing.T) {
	raw := []byte(`{"alg" : "HS256", "typ":"JWT"}`)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	h, err := parseJWTHeader([]byte(encoded))
	if err != nil {
		t.Fatalf("parseJWTHeader: %v", err)
	}
	if h.Alg != algHS256 {
		t.Fatalf("Alg = %q, want %q", h.Alg, algHS256)
	}
}

func TestParseJWTHeaderHeap_InvalidBase64(t *testing.T) {
	large := strings.Repeat("A", 200) + "!!!"
	if _, err := parseJWTHeader([]byte(large)); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseJWTHeaderHeap_InvalidJSON(t *testing.T) {
	raw := make([]byte, 200)
	for i := range raw {
		raw[i] = 'x'
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := parseJWTHeader([]byte(encoded)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDecodeAlg_TruncatedHeader(t *testing.T) {
	// Truncated quote – jsonfast.FindField cannot locate the value, so we
	// must report empty.
	if got := decodeAlg([]byte(`"RS256`)); got == algRS256 {
		t.Fatalf("expected fallback empty/literal, got %q", got)
	}
}

func TestValidateToken_InvalidBase64Payload(t *testing.T) {
	// Token with valid HMAC signature but invalid base64 payload.
	// Exercises the base64 payload decode error path in validateToken.
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	invalidPayload := "!!!"
	signingInput := header + "." + invalidPayload
	mac := hmac.New(sha256.New, []byte(testSecret))
	_, _ = mac.Write([]byte(signingInput))
	token := signingInput + "." + enc.EncodeToString(mac.Sum(nil))

	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, authErr := a.Authenticate(req); authErr == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestOAuth_ScopeFromSCPArray_EmptyElements(t *testing.T) {
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: testUser1,
			testClaimIss: testIssuerURL,
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
			"scp":        []string{testRead, "", testWrite},
		},
		testSecret,
	)
	a, err := New(&Config{Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthHMACSecret: testSecret}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	id, authErr := a.Authenticate(req)
	if authErr != nil {
		t.Fatalf("Authenticate: %v", authErr)
	}
	if got := strings.Join(id.Scopes, " "); got != testReadW {
		t.Fatalf("Scopes = %q, want %q", got, testReadW)
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
		Header:     http.Header{"Content-Type": []string{testTypeJSON}},
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
	_, err := a.fetchAndParseJWKS(context.Background(), a.jwksURL)
	if err == nil {
		t.Fatal("expected error from Body.Close")
	}
	if !strings.Contains(err.Error(), "close error") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSplitJWT_Valid covers the happy paths of splitJWT.
func TestSplitJWT_Valid(t *testing.T) {
	h, p, s, si, ok := splitJWT([]byte("aaa.bbb.ccc"))
	if !ok || string(h) != "aaa" || string(p) != "bbb" || string(s) != "ccc" || string(si) != "aaa.bbb" {
		t.Fatalf("splitJWT: ok=%v h=%s p=%s s=%s si=%s", ok, h, p, s, si)
	}
	// Empty signature part is a valid three-segment JWT.
	h2, p2, s2, _, ok2 := splitJWT([]byte("aaa.bbb."))
	if !ok2 || string(h2) != "aaa" || string(p2) != "bbb" || len(s2) != 0 {
		t.Fatalf("empty sig: ok=%v h=%s p=%s sigLen=%d", ok2, h2, p2, len(s2))
	}
}

// TestSplitJWT_Invalid covers rejection of malformed tokens.
func TestSplitJWT_Invalid(t *testing.T) {
	invalid := []struct {
		name  string
		token string
	}{
		{"no dots", "aaabbbccc"},
		{"one dot", "aaa.bbb"},
		{"four segments", "a.b.c.d"},
		{testEmpty, ""},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, ok := splitJWT([]byte(tc.token))
			if ok {
				t.Fatalf("splitJWT(%q): expected ok=false", tc.token)
			}
		})
	}
}

// BenchmarkOAuthHMAC_HS256 measures the JWT HMAC validation hot path.
func BenchmarkOAuthHMAC_HS256(b *testing.B) {
	const issuer = testIssuerURL
	const secret = "bench-secret-key"
	now := time.Now()
	token := signHS256Token(b,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimSub: "bench-user",
			testClaimIss: issuer,
			testClaimAud: "bench",
			"scope":      testReadW,
			testClaimIat: now.Unix(),
			"nbf":        now.Add(-time.Minute).Unix(),
			testClaimExp: now.Add(time.Hour).Unix(),
		},
		secret,
	)
	auth, err := New(&Config{
		Mode:            ModeOAuth,
		OAuthIssuer:     issuer,
		OAuthAudience:   "bench",
		OAuthHMACSecret: secret,
	}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	req := newReq(b, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := auth.Authenticate(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHasRequiredScopes measures the slice-based scope check.
func BenchmarkHasRequiredScopes(b *testing.B) {
	have := []string{testAdmin, testScopeMCPRead, "mcp:write", testRead, testWrite}
	required := []string{testScopeMCPRead, testRead}
	b.ReportAllocs()

	for b.Loop() {
		if !hasRequiredScopes(have, required) {
			b.Fatal("unexpected false")
		}
	}
}

// hasRequiredScopes operates on []string after the scope split.
func TestHasRequiredScopes(t *testing.T) {
	if !hasRequiredScopes([]string{testRead, testWrite}, nil) {
		t.Error("nil required → always true")
	}
	if !hasRequiredScopes(nil, nil) {
		t.Error("empty have + nil required → true")
	}
	if !hasRequiredScopes([]string{testRead, testWrite}, []string{}) {
		t.Error("empty required slice → true")
	}
	if hasRequiredScopes(nil, []string{testRead}) {
		t.Error("empty have + non-empty required → false")
	}
	if !hasRequiredScopes([]string{testRead, testWrite, testAdmin}, []string{testRead, testAdmin}) {
		t.Error("all required present → true")
	}
	if hasRequiredScopes([]string{testRead, testWrite}, []string{testRead, testAdmin}) {
		t.Error("some required missing → false")
	}
	if !hasRequiredScopes([]string{testRead}, []string{testRead}) {
		t.Error("single required, present → true")
	}
	if hasRequiredScopes([]string{"readonly"}, []string{testRead}) {
		t.Error("scope is prefix of have but not exact match → false")
	}
}

func TestClaimStringView(t *testing.T) {
	// Valid quoted string.
	if got := claimStringView([]byte(`"hello"`)); got != "hello" {
		t.Fatalf("quoted: got %q, want %q", got, "hello")
	}
	// Empty quoted string.
	if got := claimStringView([]byte(`""`)); got != "" {
		t.Fatalf("empty quoted: got %q, want empty", got)
	}
	// Unquoted value (JSON number).
	if got := claimStringView([]byte(`42`)); got != "" {
		t.Fatalf("unquoted number: got %q, want empty", got)
	}
	// JSON array — not a string.
	if got := claimStringView([]byte(`["a"]`)); got != "" {
		t.Fatalf("array: got %q, want empty", got)
	}
	// Too short (< 3 bytes).
	if got := claimStringView([]byte(`"a`)); got != "" {
		t.Fatalf("too short: got %q, want empty", got)
	}
	// nil / empty.
	if got := claimStringView(nil); got != "" {
		t.Fatalf("nil: got %q, want empty", got)
	}
}

// detachScopes priorities: scope > scp string > scp array.
func TestDetachScopes_Priorities(t *testing.T) {
	c1 := jwtClaims{scope: []byte(`"read admin"`), scp: []byte(`"write"`)}
	if got := strings.Join(detachScopes(&c1), " "); got != "read admin" {
		t.Fatalf("scope priority: got %q, want %q", got, "read admin")
	}

	c2 := jwtClaims{scp: []byte(`"read write"`)}
	if got := strings.Join(detachScopes(&c2), " "); got != testReadW {
		t.Fatalf("scp string: got %q, want %q", got, testReadW)
	}

	c3 := jwtClaims{scp: []byte(`["read","write"]`)}
	if got := strings.Join(detachScopes(&c3), " "); got != testReadW {
		t.Fatalf("scp array: got %q, want %q", got, testReadW)
	}

	if got := detachScopes(&jwtClaims{}); len(got) != 0 {
		t.Fatalf("no scopes: got %v, want empty", got)
	}
}

func TestOAuth_IssuerTrailingSlashInConfig(t *testing.T) {
	// JWT issued with canonical URL (no trailing slash).
	// Config has trailing slash — normaliseConfig must strip it.
	const issuer = testIssuerURL
	token := signHS256Token(t,
		map[string]any{testClaimAlg: algHS256, testClaimTyp: testHeaderJWT},
		map[string]any{
			testClaimIss: issuer,
			testClaimSub: "u1",
			testClaimExp: time.Now().Add(time.Hour).Unix(),
			testClaimIat: time.Now().Unix(),
		},
		testSecret,
	)
	auth, err := New(&Config{
		Mode:            ModeOAuth,
		OAuthIssuer:     issuer + "/", // trailing slash in config
		OAuthHMACSecret: testSecret,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq(t, http.MethodGet, "/", http.NoBody)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, authErr := auth.Authenticate(r); authErr != nil {
		t.Fatalf("expected success despite trailing slash in config: %v", authErr)
	}
}

func TestRequireHTTPS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "https public", raw: "https://example.com", wantErr: false},
		{name: "https with port", raw: "https://example.com:8443", wantErr: false},
		{name: "https with path", raw: "https://example.com/.well-known/jwks", wantErr: false},
		{name: "http public reject", raw: "http://example.com", wantErr: true},
		{name: "http with port reject", raw: "http://example.com:80", wantErr: true},
		{name: "http localhost allow", raw: "http://localhost:8080", wantErr: false},
		{name: "http 127.0.0.1 allow", raw: "http://127.0.0.1:9090", wantErr: false},
		{name: "http ::1 allow", raw: "http://[::1]:8080", wantErr: false},
		{name: "ftp reject", raw: "ftp://example.com", wantErr: true},
		{name: "javascript reject", raw: "javascript:alert(1)", wantErr: true},
		{name: "file reject", raw: "file:///etc/passwd", wantErr: true},
		{name: "empty reject", raw: "", wantErr: true},
		{name: "no scheme reject", raw: "example.com", wantErr: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := requireHTTPS(tt.raw)
			gotErr := err != nil
			if gotErr != tt.wantErr {
				t.Fatalf("requireHTTPS(%q) err = %v, wantErr = %v", tt.raw, err, tt.wantErr)
			}
			if gotErr && !errors.Is(err, errInsecureURLScheme) {
				t.Fatalf("expected errInsecureURLScheme, got %v", err)
			}
		})
	}
}

// The scp source buffer is pooled and recycled after validation.
func TestScopesFromSCPArrayDetachesFromBuffer(t *testing.T) {
	t.Parallel()
	raw := []byte(`["read","write"]`)
	scopes := scopesFromSCPArray(raw)
	for i := range raw {
		raw[i] = 'X'
	}
	if got := strings.Join(scopes, " "); got != testReadW {
		t.Fatalf("scopes alias recycled buffer: got %q, want %q", got, testReadW)
	}
}

// A kid absent from a fresh cache forces one rate-limited JWKS refetch.
func TestOAuth_JWKS_UnknownKidForcesRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	hits := 0
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		rsaJWKSHandler(t, &key.PublicKey, "rotated-kid")(w, r)
	}))
	defer jwksServer.Close()

	auth, err := New(&Config{
		Mode: ModeOAuth, OAuthIssuer: testIssuerURL, OAuthJWKSURL: jwksServer.URL,
	}, jwksServer.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a, ok := auth.(*oauthAuthenticator)
	if !ok {
		t.Fatalf("expected *oauthAuthenticator, got %T", auth)
	}
	a.seedKeysForTest(map[string]jwkPublicKey{"stale-kid": {key: &key.PublicKey, alg: algRS256}})

	now := time.Now()
	token := signRSAToken(t, key, "rotated-kid", map[string]any{
		testClaimSub: testUser, testClaimIss: testIssuerURL,
		testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
	})
	req := newReq(t, http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := a.Authenticate(req); err != nil {
		t.Fatalf("Authenticate after rotation: %v", err)
	}
	if hits != 1 {
		t.Fatalf("JWKS hits = %d, want 1", hits)
	}

	a.seedKeysForTest(map[string]jwkPublicKey{"stale-kid": {key: &key.PublicKey, alg: algRS256}})
	token2 := signRSAToken(t, key, "rotated-2", map[string]any{
		testClaimSub: testUser, testClaimIss: testIssuerURL,
		testClaimExp: now.Add(time.Hour).Unix(), testClaimIat: now.Unix(),
	})
	req2 := newReq(t, http.MethodGet, "/", http.NoBody)
	req2.Header.Set("Authorization", "Bearer "+token2)
	if _, err := a.Authenticate(req2); err == nil {
		t.Fatal("expected error while forced refresh is rate-limited")
	}
	if hits != 1 {
		t.Fatalf("JWKS hits = %d, want 1 (forced refresh must be rate-limited)", hits)
	}
}

func TestEqualQuotedBytes_Escapes(t *testing.T) {
	t.Parallel()
	if !equalQuotedBytes([]byte(`"https:\/\/idp.example"`), "https://idp.example") {
		t.Fatal("escaped issuer must match its decoded form")
	}
	if equalQuotedBytes([]byte(`"https:\/\/idp.example"`), "https://other.example") {
		t.Fatal("escaped issuer must not match a different value")
	}
	if !equalQuotedBytes([]byte(`"plain"`), "plain") {
		t.Fatal("unescaped fast path broken")
	}
	if equalQuotedBytes([]byte(`"broken\`), "broken") {
		t.Fatal("malformed quoted value must not match")
	}
}

func TestContainsAudienceRaw_EscapedArray(t *testing.T) {
	t.Parallel()
	raw := []byte(`["https:\/\/api.example","other"]`)
	if !containsAudienceRaw(raw, "https://api.example") {
		t.Fatal("escaped audience entry must match its decoded form")
	}
	if !containsAudienceRaw(raw, "other") {
		t.Fatal("plain audience entry must match")
	}
	if containsAudienceRaw(raw, "missing") {
		t.Fatal("absent audience must not match")
	}
}
