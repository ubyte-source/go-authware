package authware

import "testing"

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
	id := Identity{Subject: "sub", Method: ModeOAuth, Scopes: "read"}
	if id.Subject != "sub" {
		t.Fatalf("Subject = %q", id.Subject)
	}
	if id.Method != ModeOAuth {
		t.Fatalf("Method = %q", id.Method)
	}
	if id.Scopes != "read" {
		t.Fatalf("Scopes = %q", id.Scopes)
	}
}
