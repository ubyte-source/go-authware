package authware

// Shared fixture constants used across test files. Centralized here so
// goconst is satisfied and tests do not drift between files.
//
//nolint:gosec // G101: literal fixture values used by tests, not real secrets.
const (
	testTok      = "tok"
	testKey      = "key"
	testSecret   = "secret"
	testUser     = "user"
	testUser1    = "user-1"
	testAdmin    = "admin"
	testRead     = "read"
	testWrite    = "write"
	testReadW    = "read write"
	testMyKey    = "my-key"
	testMyTok    = "mytoken"
	testID       = "id"
	testClient   = "my-client"
	testClientID = "client-id"
	testDummy    = "dummy"
	testEmpty    = "empty"

	testIssuerURL = "https://issuer.example.com"
	testJWKSURL   = "https://issuer.example.com/jwks"
	testHTTPS     = "https://example.com"
	testTokenURL  = "https://example.com/token"
	testClientCN  = "client.example"

	testHeaderJWT     = "JWT"
	testTypeJSON      = "application/json"
	testFrameDeny     = "DENY"
	testReferrerNone  = "no-referrer"
	testJWKSURIField  = "jwks_uri"
	testIssuerField   = "issuer"
	testScopeOpenID   = "openid"
	testScopeMCPRead  = "mcp:read"
	testResourceMyAPI = "myapi"
	testResourceAPI   = "api://abc"

	testClaimSub = "sub"
	testClaimIss = "iss"
	testClaimAud = "aud"
	testClaimExp = "exp"
	testClaimIat = "iat"
	testClaimAlg = "alg"
	testClaimKid = "kid"
	testClaimTyp = "typ"

	testFail      = "fail"
	testMCPServer = "mcp-server"
)
