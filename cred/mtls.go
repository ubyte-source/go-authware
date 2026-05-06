package cred

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// ErrEmptyCAFile is returned when the CA file contains no PEM
// certificates.
var ErrEmptyCAFile = errors.New("cred/mtls: CA file contains no certificates")

// LoadClientTLS reads the certificate, key and optional CA bundle and
// returns a *tls.Config for outbound mTLS. An empty caFile leaves the
// system roots in place.
func LoadClientTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if caFile != "" {
		pool, err := loadCAPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// ReloadingClientTLS returns a *tls.Config that re-reads certFile and
// keyFile every interval on demand. The first read is lazy. caFile,
// when non-empty, is read once at construction time. No background
// goroutine is created.
func ReloadingClientTLS(certFile, keyFile, caFile string, interval time.Duration) (*tls.Config, error) {
	if interval <= 0 {
		return nil, errors.New("cred/mtls: reload interval must be > 0")
	}
	r := &certReloader{certFile: certFile, keyFile: keyFile, interval: interval}
	if _, err := r.load(); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:           tls.VersionTLS12,
		GetClientCertificate: r.getClientCertificate,
	}
	if caFile != "" {
		pool, err := loadCAPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// loadCAPool reads a PEM bundle into a *x509.CertPool. Returns
// ErrEmptyCAFile when no certificates are found.
func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, ErrEmptyCAFile
	}
	return pool, nil
}

// certReloader holds the most-recently-loaded certificate and its
// load time. Reads are lock-free via atomic.Pointer; concurrent
// refreshes are tolerated (last write wins).
type certReloader struct {
	current  atomic.Pointer[reloaderEntry]
	certFile string
	keyFile  string
	interval time.Duration
}

type reloaderEntry struct {
	loadedAt time.Time
	cert     tls.Certificate
}

func (r *certReloader) load() (*reloaderEntry, error) {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("reload keypair: %w", err)
	}
	entry := &reloaderEntry{cert: cert, loadedAt: time.Now()}
	r.current.Store(entry)
	return entry, nil
}

func (r *certReloader) getClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	entry := r.current.Load()
	if entry == nil || time.Since(entry.loadedAt) >= r.interval {
		fresh, err := r.load()
		if err != nil {
			if entry != nil {
				return &entry.cert, nil
			}
			return nil, err
		}
		entry = fresh
	}
	return &entry.cert, nil
}
