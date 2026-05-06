package secret

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStatic_Hit(t *testing.T) {
	p := Static(map[string]string{"db_password": testPassword})
	got, err := p.Secret(context.Background(), "db_password")
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if got != testPassword {
		t.Fatalf("got %q", got)
	}
}

func TestStatic_Miss(t *testing.T) {
	p := Static(map[string]string{"a": "1"})
	if _, err := p.Secret(context.Background(), "b"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestStatic_NilMap(t *testing.T) {
	p := Static(nil)
	if _, err := p.Secret(context.Background(), "x"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestStatic_DefensiveCopy(t *testing.T) {
	src := map[string]string{"k": "v"}
	p := Static(src)
	src["k"] = "mutated"
	got, err := p.Secret(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v" {
		t.Fatalf("Static was not isolated from caller mutation: got %q", got)
	}
}

func TestEnv_HitWithPrefix(t *testing.T) {
	t.Setenv("MYAPP_DB_PASSWORD", testPassword)
	p := Env("MYAPP_")
	got, err := p.Secret(context.Background(), "db_password")
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if got != testPassword {
		t.Fatalf("got %q", got)
	}
}

func TestEnv_HitNoPrefix(t *testing.T) {
	t.Setenv("RAW_KEY", "value")
	p := Env("")
	got, err := p.Secret(context.Background(), "raw_key")
	if err != nil {
		t.Fatal(err)
	}
	if got != "value" {
		t.Fatalf("got %q", got)
	}
}

func TestEnv_Miss(t *testing.T) {
	p := Env("ABSENT_PREFIX_")
	_, err := p.Secret(context.Background(), "nope")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestFile_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "s.json", `{"db": "p4ss", "api": "key123"}`)
	p, err := File(path)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	got, err := p.Secret(context.Background(), "db")
	if err != nil {
		t.Fatal(err)
	}
	if got != testPassword {
		t.Fatalf("got %q", got)
	}
}

func TestFile_MissingFile(t *testing.T) {
	if _, err := File("/no/such/file.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFile_RejectsNonObject(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "s.json", `["a", "b"]`)
	if _, err := File(path); err == nil {
		t.Fatal("expected error for non-object root")
	}
}

func TestFile_RejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "s.json", ``)
	if _, err := File(path); err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestFile_RejectsNonStringValue(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "s.json", `{"k": 42}`)
	if _, err := File(path); err == nil {
		t.Fatal("expected error for non-string value")
	}
}

func TestMapResolver_KnownTenant(t *testing.T) {
	a := Static(map[string]string{"x": "tenant-a"})
	b := Static(map[string]string{"x": "tenant-b"})
	r := MapResolver(map[string]Provider{"a": a, "b": b}, nil)

	got, err := r.For("a").Secret(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if got != "tenant-a" {
		t.Fatalf("got %q", got)
	}
}

func TestMapResolver_FallbackUsed(t *testing.T) {
	fallback := Static(map[string]string{"x": "default"})
	r := MapResolver(map[string]Provider{"a": Static(nil)}, fallback)

	got, err := r.For("unknown").Secret(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if got != "default" {
		t.Fatalf("got %q", got)
	}
}

func TestMapResolver_NoFallbackReturnsNotFound(t *testing.T) {
	r := MapResolver(map[string]Provider{"a": Static(map[string]string{"x": "y"})}, nil)
	_, err := r.For("unknown").Secret(context.Background(), "x")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMapResolver_DefensiveCopy(t *testing.T) {
	a := Static(map[string]string{"x": "1"})
	src := map[string]Provider{"tenant": a}
	r := MapResolver(src, nil)
	delete(src, "tenant")
	got, err := r.For("tenant").Secret(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if got != "1" {
		t.Fatalf("MapResolver was not isolated from caller mutation: got %q", got)
	}
}

func TestDecodeFlatJSON_Valid(t *testing.T) {
	got, err := decodeFlatJSON([]byte(` {"a":"1","b":"2"} `))
	if err != nil {
		t.Fatal(err)
	}
	if got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("got %v", got)
	}
}

func TestDecodeFlatJSON_Empty(t *testing.T) {
	if _, err := decodeFlatJSON(nil); err == nil {
		t.Fatal("expected error")
	}
	if _, err := decodeFlatJSON([]byte("   ")); err == nil {
		t.Fatal("expected error")
	}
}

func TestTrimJSONWhitespace(t *testing.T) {
	got := trimJSONWhitespace([]byte("  \n\t {} \r\n"))
	if string(got) != "{}" {
		t.Fatalf("got %q", got)
	}
}

// BenchmarkStatic_Hit measures the in-memory lookup hot path.
func BenchmarkStatic_Hit(b *testing.B) {
	p := Static(map[string]string{"key": "value"})
	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		v, err := p.Secret(ctx, "key")
		if err != nil || v == "" {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnv_Hit measures the envvar lookup hot path.
func BenchmarkEnv_Hit(b *testing.B) {
	b.Setenv("BENCH_KEY", "value")
	p := Env("BENCH_")
	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		if _, err := p.Secret(ctx, "key"); err != nil {
			b.Fatal(err)
		}
	}
}
