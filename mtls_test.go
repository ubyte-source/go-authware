package authware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// generateTestCert returns a self-signed certificate with the given CN
// and the SHA-256 SPKI pin for that certificate.
func generateTestCert(tb testing.TB, cn string) (cert *x509.Certificate, spkiPin [sha256.Size]byte) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create cert: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse cert: %v", err)
	}
	return cert, sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

func mtlsRequest(tb testing.TB, cert *x509.Certificate) *http.Request {
	tb.Helper()
	r := mtlsUnverifiedRequest(tb, cert)
	r.TLS.VerifiedChains = [][]*x509.Certificate{{cert}}
	return r
}

func mtlsUnverifiedRequest(tb testing.TB, cert *x509.Certificate) *http.Request {
	tb.Helper()
	r := newReq(tb, http.MethodGet, "/", http.NoBody)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

func TestMTLS_RequiresAllowlist(t *testing.T) {
	if _, err := New(&Config{Mode: ModeMTLS}, nil); err == nil {
		t.Fatal("expected error for empty allowlist")
	}
}

func TestMTLS_RejectsBadPinSize(t *testing.T) {
	if _, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSPKIPins: [][]byte{{0x01, 0x02}}}, nil); err == nil {
		t.Fatal("expected error for short pin")
	}
}

func TestMTLS_AcceptsBySubject(t *testing.T) {
	cert, _ := generateTestCert(t, testClientCN)
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{testClientCN}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := a.Authenticate(mtlsRequest(t, cert))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != ModeMTLS {
		t.Fatalf("Method = %q", id.Method)
	}
	if id.Subject != testClientCN {
		t.Fatalf("Subject = %q", id.Subject)
	}
	if id.PeerCert != cert {
		t.Fatalf("PeerCert mismatch")
	}
}

func TestMTLS_AcceptsBySPKIPin(t *testing.T) {
	cert, pin := generateTestCert(t, "pinned.example")
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSPKIPins: [][]byte{pin[:]}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := a.Authenticate(mtlsRequest(t, cert))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "pinned.example" {
		t.Fatalf("Subject = %q", id.Subject)
	}
}

func TestMTLS_RejectsSubjectWithoutVerifiedChain(t *testing.T) {
	cert, _ := generateTestCert(t, testClientCN)
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{testClientCN}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := mtlsUnverifiedRequest(t, cert)
	if _, err := a.Authenticate(r); !errors.Is(err, errMTLSRejected) {
		t.Fatalf("err = %v, want errMTLSRejected", err)
	}
}

func TestMTLS_AcceptsPinWithoutVerifiedChain(t *testing.T) {
	cert, pin := generateTestCert(t, "pinned.example")
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSPKIPins: [][]byte{pin[:]}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := mtlsUnverifiedRequest(t, cert)
	if _, err := a.Authenticate(r); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestMTLS_RejectsUnlistedSubject(t *testing.T) {
	cert, _ := generateTestCert(t, "rogue.example")
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{testClientCN}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Authenticate(mtlsRequest(t, cert)); !errors.Is(err, errMTLSRejected) {
		t.Fatalf("err = %v, want errMTLSRejected", err)
	}
}

func TestMTLS_RejectsWhenNoTLS(t *testing.T) {
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{testClientCN}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq(t, http.MethodGet, "/", http.NoBody)
	if _, err := a.Authenticate(r); !errors.Is(err, errMTLSNoTLS) {
		t.Fatalf("err = %v, want errMTLSNoTLS", err)
	}
}

func TestMTLS_RejectsWhenNoPeerCert(t *testing.T) {
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{testClientCN}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newReq(t, http.MethodGet, "/", http.NoBody)
	r.TLS = &tls.ConnectionState{}
	if _, err := a.Authenticate(r); !errors.Is(err, errMTLSNoCert) {
		t.Fatalf("err = %v, want errMTLSNoCert", err)
	}
}

func TestMTLS_Challenge_NoWWWAuthenticate(t *testing.T) {
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{testClientCN}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	status, header, msg := a.Challenge(errMTLSRejected, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d", status)
	}
	if header != "" {
		t.Fatalf("expected empty WWW-Authenticate, got %q", header)
	}
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestMTLS_Metadata_Nil(t *testing.T) {
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{"x"}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if md := a.Metadata(testHTTPS); md != nil {
		t.Fatalf("expected nil metadata, got %+v", md)
	}
}

// BenchmarkMTLS_AcceptSubject measures the subject-allowlist accept path.
func BenchmarkMTLS_AcceptSubject(b *testing.B) {
	cert, _ := generateTestCert(b, testClientCN)
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSubjects: []string{testClientCN}}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	r := mtlsRequest(b, cert)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := a.Authenticate(r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMTLS_AcceptPin measures the SPKI-pin accept path.
func BenchmarkMTLS_AcceptPin(b *testing.B) {
	cert, pin := generateTestCert(b, "pinned.example")
	a, err := New(&Config{Mode: ModeMTLS, MTLSAllowedSPKIPins: [][]byte{pin[:]}}, nil)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	r := mtlsRequest(b, cert)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := a.Authenticate(r); err != nil {
			b.Fatal(err)
		}
	}
}
