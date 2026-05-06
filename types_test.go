package authware

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"slices"
	"testing"
)

func TestAuthError_Error(t *testing.T) {
	e := &authError{message: "test error", code: "test_code", status: 401}
	if e.Error() != "test error" {
		t.Fatalf("Error() = %q", e.Error())
	}
}

func TestConfig_ZeroValue(t *testing.T) {
	var cfg Config
	if cfg.Mode != "" {
		t.Fatalf("Mode = %q", cfg.Mode)
	}
	if cfg.Realm != "" {
		t.Fatalf("Realm = %q", cfg.Realm)
	}
}

func TestIdentity_Fields(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: testClientCN}}
	id := &Identity{
		Subject:   testClaimSub,
		Method:    ModeOAuth,
		Scopes:    []string{testRead, testWrite},
		claimsRaw: `{"iss":"https://issuer"}`,
		PeerCert:  cert,
	}
	if id.Subject != testClaimSub {
		t.Fatalf("Subject = %q", id.Subject)
	}
	if id.Method != ModeOAuth {
		t.Fatalf("Method = %q", id.Method)
	}
	if !slices.Equal(id.Scopes, []string{testRead, testWrite}) {
		t.Fatalf("Scopes = %v", id.Scopes)
	}
	v, ok := id.Claim(testClaimIss)
	if !ok || v != "https://issuer" {
		t.Fatalf("Claim(iss) = %v, ok=%v", v, ok)
	}
	if id.PeerCert != cert {
		t.Fatalf("PeerCert = %p, want %p", id.PeerCert, cert)
	}
}

func TestIdentity_RangeClaims(t *testing.T) {
	id := &Identity{claimsRaw: `{"sub":"alice","admin":true,"lvl":7}`}
	got := map[string]any{}
	id.RangeClaims(func(name string, value any) bool {
		got[name] = value
		return true
	})
	adminTrue, ok := got[testAdmin].(bool)
	if !ok || got[testClaimSub] != "alice" || !adminTrue || got["lvl"] != int64(7) {
		t.Fatalf("RangeClaims = %v", got)
	}
}

func TestIdentity_NilClaim(t *testing.T) {
	var id *Identity
	if v, ok := id.Claim("anything"); ok || v != nil {
		t.Fatalf("Claim on nil = (%v,%v)", v, ok)
	}
}

func TestMode_AllConstants(t *testing.T) {
	all := []Mode{ModeNone, ModeBearer, ModeAPIKey, ModeOAuth, ModeMTLS}
	for _, m := range all {
		if m == "" {
			t.Fatalf("mode constant is empty")
		}
	}
}

func TestIdentity_RangeClaimsAbort(t *testing.T) {
	t.Parallel()
	id := &Identity{claimsRaw: `{"a":"1","b":"2","c":"3"}`}
	count := 0
	id.RangeClaims(func(_ string, _ any) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Fatalf("expected callback called twice, got %d", count)
	}
}

func TestIdentity_RangeClaimsEmpty(t *testing.T) {
	t.Parallel()
	id := &Identity{}
	called := false
	ok := id.RangeClaims(func(_ string, _ any) bool {
		called = true
		return true
	})
	if !ok {
		t.Fatal("expected ok=true on empty payload")
	}
	if called {
		t.Fatal("expected callback not invoked on empty payload")
	}
}
