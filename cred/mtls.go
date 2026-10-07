package cred

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
)

// ClientTLSConfig configures LoadClientTLS.
type ClientTLSConfig struct {
	// ErrorLog receives, at warn level, every failed reload of the key pair;
	// nil logs nothing.
	ErrorLog *slog.Logger
	// CertFile holds the PEM certificate chain the client presents; required.
	CertFile string
	// KeyFile holds the PEM private key of CertFile; required.
	KeyFile string
	// CAFile, when not empty, holds the PEM certificates that alone are
	// trusted as roots; it is read at filepath.Clean(CAFile).
	CAFile string
	// Interval, when positive, reads the key pair again during the first
	// handshake after each interval; zero loads it once.
	Interval time.Duration
}

// Validate reports, joined, every problem LoadClientTLS refuses c for, reading
// the files to find them; each wraps ErrInvalidConfig, a key pair that cannot be
// loaded also ErrInvalidKeyPair and a CA file without a certificate ErrEmptyCAFile.
func (c *ClientTLSConfig) Validate() error {
	if c == nil {
		return errNilConfig
	}
	_, _, err := c.load()
	return err
}

// load reads the key pair and, when a CA file is set, the roots of c, or
// reports every problem Validate reports.
func (c *ClientTLSConfig) load() (tls.Certificate, *x509.CertPool, error) {
	p := problems.New(ErrInvalidConfig)
	p.NonNegative("reload interval", c.Interval)
	cert, err := loadKeyPair(c.CertFile, c.KeyFile)
	p.Add(err)
	var roots *x509.CertPool
	if c.CAFile != "" {
		roots, err = loadRoots(c.CAFile)
		p.Add(err)
	}
	if err := p.Err(); err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, roots, nil
}

// loadedCert is a key pair and the instant it is due for reload.
type loadedCert struct {
	cert *tls.Certificate
	due  time.Time
}

// certReloader serves the published pair: a reload publishes the pair it reads,
// and a failed one publishes the pair it found again only while that pair is
// still the published one.
type certReloader struct {
	log      *slog.Logger
	certFile string
	keyFile  string
	interval time.Duration
	pair     atomic.Pointer[loadedCert]
}

// clientCertificate serves the current pair, reloaded first once it is due;
// the next interval starts when the reload ends.
func (r *certReloader) clientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.serve(info.Context(), r.pair.Load()), nil
}

// serve returns the pair of loaded, the one clientCertificate found, until it
// is due, and then the pair a reload reads, or after a failed reload the
// published one.
func (r *certReloader) serve(ctx context.Context, loaded *loadedCert) *tls.Certificate {
	if time.Now().Before(loaded.due) {
		return loaded.cert
	}
	if cert := r.reload(ctx); cert != nil {
		r.pair.Store(&loadedCert{cert: cert, due: time.Now().Add(r.interval)})
		return cert
	}
	r.pair.CompareAndSwap(loaded, &loadedCert{cert: loaded.cert, due: time.Now().Add(r.interval)})
	return r.pair.Load().cert
}

// reload reads the key pair again, or logs why it cannot and returns nil.
func (r *certReloader) reload(ctx context.Context) *tls.Certificate {
	cert, err := loadKeyPair(r.certFile, r.keyFile)
	if err != nil {
		r.log.LogAttrs(ctx, slog.LevelWarn, errPrefix+"key pair reload failed", slog.Any("error", err))
		return nil
	}
	return &cert
}

// LoadClientTLS returns a client TLS config presenting the key pair of cfg, loaded
// before it returns, or an error wrapping ErrInvalidConfig; with an Interval, a
// failed reload keeps the previous pair for another interval.
func LoadClientTLS(cfg *ClientTLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, errNilConfig
	}
	cert, roots, err := cfg.load()
	if err != nil {
		return nil, err
	}
	out := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if cfg.Interval == 0 {
		out.Certificates = []tls.Certificate{cert}
		return out, nil
	}
	out.GetClientCertificate = newCertReloader(cfg, &cert).clientCertificate
	return out, nil
}

// newCertReloader returns the reloader of cfg serving cert for a first
// interval; failed reloads go to cfg.ErrorLog, or nowhere without one.
func newCertReloader(cfg *ClientTLSConfig, cert *tls.Certificate) *certReloader {
	r := &certReloader{
		log:      cmp.Or(cfg.ErrorLog, slog.New(slog.DiscardHandler)),
		certFile: cfg.CertFile,
		keyFile:  cfg.KeyFile,
		interval: cfg.Interval,
	}
	r.pair.Store(&loadedCert{cert: cert, due: time.Now().Add(cfg.Interval)})
	return r
}

// loadKeyPair loads the PEM key pair of certFile and keyFile; a failure wraps
// ErrInvalidKeyPair.
func loadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %w", ErrInvalidKeyPair, err)
	}
	return cert, nil
}

// loadRoots reads the PEM certificates of caFile into a pool.
func loadRoots(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, fmt.Errorf("%w: read CA file: %w", ErrInvalidConfig, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, ErrEmptyCAFile
	}
	return roots, nil
}
