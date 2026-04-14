package authware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestBearerChallenge_Format(t *testing.T) {
	err := &authError{
		status:  http.StatusForbidden,
		code:    "insufficient_scope",
		message: "missing required scope",
		scheme:  "Bearer",
		scope:   "mcp:read mcp:write",
	}
	status, header, _ := challengeFromError("mcp", err, "https://example.com/.well-known/oauth-protected-resource")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(header, "Bearer") {
		t.Fatalf("header missing Bearer: %q", header)
	}
	if !strings.Contains(header, "resource_metadata") {
		t.Fatalf("header missing resource_metadata: %q", header)
	}
	if !strings.Contains(header, "insufficient_scope") {
		t.Fatalf("header missing error code: %q", header)
	}
	if !strings.Contains(header, "mcp:read mcp:write") {
		t.Fatalf("header missing scope: %q", header)
	}
}

func TestChallengeFromError_NonBearerScheme(t *testing.T) {
	err := &authError{status: http.StatusUnauthorized, message: "bad key", scheme: "ApiKey", code: "invalid"}
	status, header, msg := challengeFromError("mcp", err, "https://example.com/meta")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if header != "" {
		t.Fatalf("expected empty header for non-Bearer scheme, got %q", header)
	}
	if msg != "bad key" {
		t.Fatalf("msg = %q", msg)
	}
}

func TestChallengeFromError_PlainError(t *testing.T) {
	status, header, msg := challengeFromError("mcp", fmt.Errorf("oops"), "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if header != "" {
		t.Fatalf("header = %q", header)
	}
	if msg != "unauthorized" {
		t.Fatalf("msg = %q", msg)
	}
}

func TestEscapeHeaderValue(t *testing.T) {
	var b strings.Builder
	escapeHeaderValue(&b, "foo\\bar\"baz\nqux\r")
	got := b.String()
	if !strings.Contains(got, `\\`) {
		t.Fatalf("missing escaped backslash: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("newline not escaped: %q", got)
	}
}

func TestInsufficientScopeError(t *testing.T) {
	err := insufficientScopeError([]string{"admin", "write"})
	var ae *authError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *authError, got %T", err)
	}
	if ae.status != http.StatusForbidden {
		t.Fatalf("status = %d", ae.status)
	}
	if ae.code != "insufficient_scope" {
		t.Fatalf("code = %q", ae.code)
	}
	if !strings.Contains(ae.scope, "admin") {
		t.Fatalf("scope = %q", ae.scope)
	}
}

func TestUnauthorizedError(t *testing.T) {
	err := unauthorizedError("bad token")
	var ae *authError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *authError, got %T", err)
	}
	if ae.status != http.StatusUnauthorized {
		t.Fatalf("status = %d", ae.status)
	}
	if ae.message != "bad token" {
		t.Fatalf("message = %q", ae.message)
	}
	if ae.scheme != "Bearer" {
		t.Fatalf("scheme = %q", ae.scheme)
	}
}
