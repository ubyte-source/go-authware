package cred

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pemCertName/pemKeyName are the file names used inside the test temp dir
// by every pemKeyPair call site.
const (
	pemCertName = "c.pem"
	pemKeyName  = "k.pem"
)

// pemKeyPair generates a self-signed certificate + key in PEM form and
// writes them to {dir}/c.pem and {dir}/k.pem.
func pemKeyPair(tb testing.TB, dir string) (certPath, keyPath string) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		tb.Fatalf("marshalkey: %v", err)
	}

	certPath = filepath.Join(dir, pemCertName)
	keyPath = filepath.Join(dir, pemKeyName)

	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		tb.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		tb.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// pemCABundle writes a PEM bundle containing the cert at certPath into a
// new file in dir and returns the path.
func pemCABundle(tb testing.TB, dir, certPath string) string {
	tb.Helper()
	data, err := os.ReadFile(certPath) //nolint:gosec // path confined to t.TempDir()
	if err != nil {
		tb.Fatalf("read cert: %v", err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, data, 0o600); err != nil { //nolint:gosec // path confined to t.TempDir()
		tb.Fatalf("write ca: %v", err)
	}
	return caPath
}

func TestLoadClientTLS_LoadsKeypair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := pemKeyPair(t, dir)
	cfg, err := LoadClientTLS(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("LoadClientTLS: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d", len(cfg.Certificates))
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d", cfg.MinVersion)
	}
}

func TestLoadClientTLS_WithCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := pemKeyPair(t, dir)
	caPath := pemCABundle(t, dir, certPath)
	cfg, err := LoadClientTLS(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("LoadClientTLS: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil")
	}
}

func TestLoadClientTLS_RejectsBadKeypair(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientTLS(bad, bad, ""); err == nil {
		t.Fatal("expected error for malformed keypair")
	}
}

func TestLoadClientTLS_RejectsEmptyCAFile(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := pemKeyPair(t, dir)
	emptyCA := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(emptyCA, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientTLS(certPath, keyPath, emptyCA); !errors.Is(err, ErrEmptyCAFile) {
		t.Fatalf("err = %v, want ErrEmptyCAFile", err)
	}
}

func TestReloadingClientTLS_ServesCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := pemKeyPair(t, dir)
	cfg, err := ReloadingClientTLS(certPath, keyPath, "", time.Hour)
	if err != nil {
		t.Fatalf("ReloadingClientTLS: %v", err)
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is nil")
	}
	cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("returned cert is empty")
	}
}

func TestReloadingClientTLS_ReloadsAfterInterval(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := pemKeyPair(t, dir)
	cfg, err := ReloadingClientTLS(certPath, keyPath, "", time.Millisecond)
	if err != nil {
		t.Fatalf("ReloadingClientTLS: %v", err)
	}
	first, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	// Replace the on-disk pair with a fresh one, then wait past the interval.
	pemKeyPair(t, dir)
	time.Sleep(5 * time.Millisecond)
	second, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if &first.Certificate[0][0] == &second.Certificate[0][0] {
		t.Fatal("certificate not reloaded: same backing slice")
	}
}

func TestReloadingClientTLS_RejectsBadInterval(t *testing.T) {
	if _, err := ReloadingClientTLS("/x", "/y", "", 0); err == nil {
		t.Fatal("expected error for non-positive interval")
	}
}

func TestReloadingClientTLS_FailsOnInitialLoadError(t *testing.T) {
	if _, err := ReloadingClientTLS("/no/such/cert", "/no/such/key", "", time.Second); err == nil {
		t.Fatal("expected error when initial load fails")
	}
}

func TestReloadingClientTLS_FallsBackOnReloadError(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := pemKeyPair(t, dir)
	cfg, err := ReloadingClientTLS(certPath, keyPath, "", time.Millisecond)
	if err != nil {
		t.Fatalf("ReloadingClientTLS: %v", err)
	}
	// Prime the cache.
	if _, primeErr := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); primeErr != nil {
		t.Fatal(primeErr)
	}
	// Corrupt the on-disk cert and wait past the reload interval.
	if writeErr := os.WriteFile(certPath, []byte("garbage"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	time.Sleep(5 * time.Millisecond)
	cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("expected fallback to cached cert, got error: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("fallback returned empty cert")
	}
}
