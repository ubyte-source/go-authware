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
	"io"
	"io/fs"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// The common names of the key pairs the tests write.
const (
	certA = "a"
	certB = "b"
)

// writeKeyPair writes a fresh self-signed client certificate named cn and
// its key into dir and returns their paths.
func writeKeyPair(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey = %v, want a key", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate = %v, want a certificate", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey = %v, want DER", err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeFile(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certFile, keyFile
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) = %v, want nil", path, err)
	}
}

func commonName(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate = %v, want the leaf", err)
	}
	return leaf.Subject.CommonName
}

func TestLoadClientTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	cfg, err := LoadClientTLS(&ClientTLSConfig{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("LoadClientTLS = %v, want a config", err)
	}
	if len(cfg.Certificates) != 1 || cfg.RootCAs != nil || cfg.MinVersion != tls.VersionTLS12 ||
		cfg.GetClientCertificate != nil {
		t.Fatalf("config = %+v, want the pair, the system roots and TLS 1.2 without reloads", cfg)
	}
	cfg, err = LoadClientTLS(&ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: certFile})
	if err != nil || cfg.RootCAs == nil || !cfg.RootCAs.Equal(mustRoots(t, certFile)) {
		t.Fatalf("with CA: %+v, %v, want the CA file as the only root", cfg, err)
	}
}

func TestLoadClientTLSCleansCAFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	data, err := fs.ReadFile(os.DirFS(dir), filepath.Base(certFile))
	want := x509.NewCertPool()
	if err != nil || !want.AppendCertsFromPEM(data) {
		t.Fatalf("ReadFile(%s) = %v, want PEM certificates", certFile, err)
	}
	cfg, err := LoadClientTLS(&ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: certFile + "/"})
	if err != nil || cfg.RootCAs == nil || !cfg.RootCAs.Equal(want) {
		t.Fatalf("CAFile %s/: %+v, %v; want the roots of the file at filepath.Clean(CAFile)", certFile, cfg, err)
	}
	missing := dir + "/./none"
	_, err = LoadClientTLS(&ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: missing})
	if name := "open " + filepath.Clean(missing) + ":"; !errors.Is(err, fs.ErrNotExist) ||
		!strings.Contains(err.Error(), name) {
		t.Fatalf("CAFile %s: %v; want fs.ErrNotExist after %q", missing, err, name)
	}
}

// mustRoots returns the pool of the PEM certificates in file.
func mustRoots(t *testing.T, file string) *x509.CertPool {
	t.Helper()
	pool, err := loadRoots(file)
	if err != nil {
		t.Fatalf("loadRoots = %v, want a pool", err)
	}
	return pool
}

func TestClientTLSConfigValidate(t *testing.T) {
	if err := (*ClientTLSConfig)(nil).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Validate() = %v, want ErrInvalidConfig", err)
	}
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	if err := (&ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: certFile}).Validate(); err != nil {
		t.Fatalf("valid Validate() = %v, want nil", err)
	}
	missing := filepath.Join(dir, "none")
	err := (&ClientTLSConfig{CertFile: missing, KeyFile: keyFile, CAFile: missing, Interval: -time.Second}).Validate()
	for _, want := range []error{ErrInvalidConfig, ErrInvalidKeyPair, fs.ErrNotExist} {
		if !errors.Is(err, want) {
			t.Errorf("Validate() = %v, want %v among the problems", err, want)
		}
	}
	if n := strings.Count(err.Error(), "\n"); n != 2 {
		t.Fatalf("Validate() = %q, want three joined problems", err)
	}
}

// TestClientTLSConfigLoadFails returns nothing loaded with the problems, also
// for a key pair that loads beside a refused setting.
func TestClientTLSConfigLoadFails(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	for _, cfg := range []*ClientTLSConfig{
		{CertFile: certFile, KeyFile: keyFile, CAFile: filepath.Join(dir, "none")},
		{CertFile: certFile, KeyFile: keyFile, CAFile: certFile, Interval: -time.Second},
	} {
		cert, roots, err := cfg.load()
		if !errors.Is(err, ErrInvalidConfig) || cert.Certificate != nil || cert.PrivateKey != nil || roots != nil {
			t.Errorf("load(%+v) = %d certificates, roots %t, %v; want nothing loaded and ErrInvalidConfig", cfg,
				len(cert.Certificate), roots != nil, err)
		}
	}
}

func TestLoadClientTLSErrors(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	missing := filepath.Join(dir, "none")
	for _, tc := range []struct {
		name      string
		tlsConfig *ClientTLSConfig
		want      []error
	}{
		{"nil config", nil, []error{ErrInvalidConfig}},
		{"negative interval", &ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, Interval: -time.Second},
			[]error{ErrInvalidConfig}},
		{"mismatched key", &ClientTLSConfig{CertFile: certFile, KeyFile: certFile},
			[]error{ErrInvalidKeyPair, ErrInvalidConfig}},
		{"missing pair", &ClientTLSConfig{CertFile: missing, KeyFile: keyFile},
			[]error{ErrInvalidKeyPair, ErrInvalidConfig, fs.ErrNotExist}},
		{"CA without certificates", &ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: keyFile},
			[]error{ErrEmptyCAFile, ErrInvalidConfig}},
		{"missing CA", &ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: missing},
			[]error{ErrInvalidConfig, fs.ErrNotExist}},
	} {
		cfg, err := LoadClientTLS(tc.tlsConfig)
		for _, want := range tc.want {
			if cfg != nil || !errors.Is(err, want) {
				t.Errorf("%s: LoadClientTLS = %v, %v; want %v", tc.name, cfg, err, want)
			}
		}
	}
}

func TestLoadClientTLSReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	cfg, err := LoadClientTLS(&ClientTLSConfig{CertFile: certFile, KeyFile: keyFile, Interval: time.Hour})
	if err != nil {
		t.Fatalf("LoadClientTLS = %v, want a config", err)
	}
	writeKeyPair(t, dir, certB)
	cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || commonName(t, cert) != certA || cfg.Certificates != nil {
		t.Fatalf("within the interval served %v, %v with %d static pairs, want a alone", cert, err,
			len(cfg.Certificates))
	}
}

func TestLoadClientTLSReloadFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		certFile, keyFile := writeKeyPair(t, dir, certA)
		var logs strings.Builder
		for _, errorLog := range []*slog.Logger{nil, slog.New(slog.NewTextHandler(&logs, nil))} {
			cfg, err := LoadClientTLS(&ClientTLSConfig{
				ErrorLog: errorLog, CertFile: certFile, KeyFile: keyFile, Interval: time.Minute,
			})
			if err != nil {
				t.Fatalf("LoadClientTLS = %v, want a config", err)
			}
			writeFile(t, keyFile, []byte("garbage"))
			time.Sleep(time.Minute)
			if cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil || commonName(t,
				cert) != certA {
				t.Fatalf("after a failed reload served %v, %v, want a", cert, err)
			}
			writeKeyPair(t, dir, certB)
			if cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil || commonName(t,
				cert) != certA {
				t.Fatalf("within the interval after a failed reload served %v, %v, want a", cert, err)
			}
			certFile, keyFile = writeKeyPair(t, dir, certA)
		}
		if !strings.Contains(logs.String(), `level=WARN msg="cred: key pair reload failed"`) {
			t.Fatalf("logged %q, want the failed reload warned", logs.String())
		}
	})
}

func TestNewCertReloader(t *testing.T) {
	cert := &tls.Certificate{}
	var logs strings.Builder
	for name, tc := range map[string]struct {
		log     *slog.Logger
		enabled bool
	}{"without ErrorLog": {nil, false}, "with ErrorLog": {slog.New(slog.NewTextHandler(&logs, nil)), true}} {
		cfg := &ClientTLSConfig{ErrorLog: tc.log, CertFile: "c.pem", KeyFile: "k.pem", Interval: time.Hour}
		before := time.Now()
		r := newCertReloader(cfg, cert)
		cur := r.pair.Load()
		if r.log.Enabled(t.Context(), slog.LevelError) != tc.enabled || r.certFile != cfg.CertFile ||
			r.keyFile != cfg.KeyFile || r.interval != time.Hour || cur.cert != cert ||
			cur.due.Before(before.Add(time.Hour)) || cur.due.After(time.Now().Add(time.Hour)) {
			t.Errorf("%s: newCertReloader = %+v serving %+v, want the files and interval of cfg, logging %t, and cert "+
				"due an interval from now", name, r, cur, tc.enabled)
		}
	}
}

func TestCertReloaderClientCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	cert, err := loadKeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("loadKeyPair = %v, want the pair", err)
	}
	r := &certReloader{log: slog.New(slog.DiscardHandler), certFile: certFile, keyFile: keyFile, interval: time.Hour}
	r.pair.Store(&loadedCert{cert: &cert, due: time.Now().Add(-time.Hour)})
	writeKeyPair(t, dir, certB)
	info := &tls.CertificateRequestInfo{}
	if got, err := r.clientCertificate(info); err != nil || commonName(t, got) != certB {
		t.Fatalf("after the interval served %v, %v, want b", got, err)
	}
	writeKeyPair(t, dir, "c")
	if got, err := r.clientCertificate(info); err != nil || commonName(t, got) != certB {
		t.Fatalf("within the next interval served %v, %v, want b", got, err)
	}
}

// TestCertReloaderServeInterleaved pauses a due handshake after its load while
// another reloads and publishes: a paused reload that reads b publishes it, and
// one that fails serves the published pair and leaves it due as it is.
func TestCertReloaderServeInterleaved(t *testing.T) {
	renew := func(t *testing.T, dir, _ string) {
		t.Helper()
		writeKeyPair(t, dir, certB)
	}
	spoil := func(t *testing.T, _, keyFile string) {
		t.Helper()
		writeFile(t, keyFile, []byte("garbage"))
	}
	for _, tc := range []struct {
		other, paused         func(t *testing.T, dir, keyFile string)
		wantOther, wantPaused string
		wantDue               time.Duration
	}{{renew, spoil, certB, certB, time.Hour - time.Second}, {spoil, renew, certA, certB, time.Hour}} {
		synctest.Test(t, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := writeKeyPair(t, dir, certA)
			cert, err := loadKeyPair(certFile, keyFile)
			if err != nil {
				t.Fatalf("loadKeyPair = %v, want the pair", err)
			}
			r := &certReloader{log: slog.New(slog.DiscardHandler), certFile: certFile, keyFile: keyFile,
				interval: time.Hour}
			r.pair.Store(&loadedCert{cert: &cert, due: time.Now()})
			resume := pauseAfter(r.pair.Load, func(cur *loadedCert) *tls.Certificate {
				return r.serve(t.Context(), cur)
			})
			tc.other(t, dir, keyFile)
			other, err := r.clientCertificate(&tls.CertificateRequestInfo{})
			time.Sleep(time.Second)
			tc.paused(t, dir, keyFile)
			paused := resume()
			if err != nil || commonName(t, other) != tc.wantOther || commonName(t, paused) != tc.wantPaused {
				t.Fatalf("other reload served %v, %v and the paused one %v; want %s and %s", other, err, paused,
					tc.wantOther, tc.wantPaused)
			}
			if cur := r.pair.Load(); cur.cert != paused || !cur.due.Equal(time.Now().Add(tc.wantDue)) {
				t.Fatalf("published %+v, want the pair the paused one served, due in %v", cur, tc.wantDue)
			}
		})
	}
}

// TestCertReloaderReloadLogsUnderTheContext warns of a failed reload under the
// context reload gets, which a handshake takes from its dial.
func TestCertReloaderReloadLogsUnderTheContext(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, certA)
	var logged atomic.Int32
	cfg, err := LoadClientTLS(&ClientTLSConfig{ErrorLog: slog.New(markHandler{marked: &logged}), CertFile: certFile,
		KeyFile: keyFile, Interval: time.Nanosecond})
	if err != nil {
		t.Fatalf("LoadClientTLS = %v, want a config", err)
	}
	writeFile(t, keyFile, []byte("garbage"))
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	// The server may still read the handshake when the client hangs up.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	transport, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test server transport = %T, want *http.Transport", srv.Client().Transport)
	}
	cfg.RootCAs = transport.TLSClientConfig.RootCAs
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(marked(t), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext = %v, want a connection", err)
	}
	if err := conn.Close(); err != nil || logged.Load() != 1 {
		t.Fatalf("Close = %v after %d warnings under the dial's context, want nil after 1", err, logged.Load())
	}
}

func TestCertReloaderReload(t *testing.T) {
	certFile, keyFile := writeKeyPair(t, t.TempDir(), certB)
	var logs strings.Builder
	r := &certReloader{log: slog.New(slog.NewTextHandler(&logs, nil)), certFile: certFile, keyFile: keyFile}
	if got := r.reload(t.Context()); got == nil || commonName(t, got) != certB || logs.Len() != 0 {
		t.Fatalf("reload = %v with %q logged, want the pair b and no log", got, logs.String())
	}
	writeFile(t, keyFile, []byte("garbage"))
	if got := r.reload(t.Context()); got != nil ||
		!strings.Contains(logs.String(),
			`level=WARN msg="cred: key pair reload failed" error="cred: invalid config: invalid key pair: `) {
		t.Fatalf("failed reload = %v with %q logged, want nil and a warning", got, logs.String())
	}
}
