package authware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestRedactor_RedactsTopLevelAttr(t *testing.T) {
	var buf bytes.Buffer
	h := NewRedactor(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}), "Authorization")
	logger := slog.New(h)
	logger.Info("req", "method", "GET", "Authorization", "Bearer secret")
	out := buf.String()
	if strings.Contains(out, testSecret) {
		t.Fatalf("secret leaked: %s", out)
	}
	if !strings.Contains(out, "***") {
		t.Fatalf("expected redacted marker, got %s", out)
	}
}

func TestRedactor_CaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	h := NewRedactor(slog.NewTextHandler(&buf, nil), "authorization")
	slog.New(h).Info("req", "Authorization", testSecret)
	if strings.Contains(buf.String(), testSecret) {
		t.Fatalf("secret leaked: %s", buf.String())
	}
}

func TestRedactor_NestedGroup(t *testing.T) {
	var buf bytes.Buffer
	h := NewRedactor(slog.NewTextHandler(&buf, nil), "Cookie")
	logger := slog.New(h)
	logger.Info("req", slog.Group("headers",
		slog.String("Cookie", "sessid=abcd"),
		slog.String("User-Agent", "test/1"),
	))
	out := buf.String()
	if strings.Contains(out, "sessid=abcd") {
		t.Fatalf("nested cookie leaked: %s", out)
	}
	if !strings.Contains(out, "test/1") {
		t.Fatalf("non-sensitive lost: %s", out)
	}
}

func TestRedactor_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := NewRedactor(slog.NewTextHandler(&buf, nil), "Cookie").WithAttrs([]slog.Attr{
		slog.String("Cookie", "leak"),
		slog.String("rid", "1"),
	})
	logger := slog.New(h)
	logger.Info("event")
	out := buf.String()
	if strings.Contains(out, "leak") {
		t.Fatalf("WithAttrs cookie leaked: %s", out)
	}
	if !strings.Contains(out, "rid=1") {
		t.Fatalf("non-sensitive lost: %s", out)
	}
}

func TestRedactor_NoKeysReturnsInner(t *testing.T) {
	inner := slog.NewTextHandler(&bytes.Buffer{}, nil)
	if got := NewRedactor(inner); got != inner {
		t.Fatal("expected inner returned unchanged when no keys supplied")
	}
}

func TestRedactor_Enabled(t *testing.T) {
	inner := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewRedactor(inner, "x")
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("expected level filter to propagate from inner")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("expected error level to pass")
	}
}

func TestRedactHeader_Default(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer secret")
	h.Set("Cookie", "sessid=abcd")
	h.Set("X-Trace", "ok")
	out := RedactHeader(h)
	if got := out.Get("Authorization"); got != redactedValue {
		t.Fatalf("Authorization = %q", got)
	}
	if got := out.Get("Cookie"); got != redactedValue {
		t.Fatalf("Cookie = %q", got)
	}
	if got := out.Get("X-Trace"); got != "ok" {
		t.Fatalf("X-Trace mutated: %q", got)
	}
}

func TestRedactHeader_CustomKeys(t *testing.T) {
	h := http.Header{}
	h.Set("X-Tenant", testSecret)
	out := RedactHeader(h, "x-tenant")
	if got := out.Get("X-Tenant"); got != redactedValue {
		t.Fatalf("X-Tenant = %q", got)
	}
}

func TestRedactHeader_NilSafe(t *testing.T) {
	if got := RedactHeader(nil); got != nil {
		t.Fatalf("nil header should remain nil")
	}
}

// BenchmarkRedactor_Hit measures redaction when an attribute matches.
func BenchmarkRedactor_Hit(b *testing.B) {
	h := NewRedactor(slog.NewTextHandler(&discardWriter{}, nil), "Authorization")
	logger := slog.New(h)
	b.ReportAllocs()

	for b.Loop() {
		logger.Info("req", "method", "GET", "Authorization", "Bearer secret")
	}
}

// BenchmarkRedactor_Miss measures the overhead when no attribute matches.
func BenchmarkRedactor_Miss(b *testing.B) {
	h := NewRedactor(slog.NewTextHandler(&discardWriter{}, nil), "Authorization")
	logger := slog.New(h)
	b.ReportAllocs()

	for b.Loop() {
		logger.Info("req", "method", "GET", "path", "/x")
	}
}

// BenchmarkRedactHeader measures in-place header redaction.
func BenchmarkRedactHeader(b *testing.B) {
	build := func() http.Header {
		h := http.Header{}
		h.Set("Authorization", "Bearer secret")
		h.Set("X-Api-Key", testKey)
		h.Set("Cookie", "sessid=x")
		return h
	}
	b.ReportAllocs()

	for b.Loop() {
		RedactHeader(build())
	}
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
