package authware

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"net/http"
)

var _ Authenticator = (*mtlsAuthenticator)(nil)

var (
	errMTLSNoTLS    = unauthorisedError("mTLS: no TLS connection")
	errMTLSNoCert   = unauthorisedError("mTLS: no client certificate")
	errMTLSRejected = unauthorisedError("mTLS: client certificate rejected")
)

// mtlsAuthenticator matches the peer certificate against subject CNs
// and/or SHA-256 SPKI pins. Subject matching requires a TLS-verified
// chain (any key holder can self-sign an arbitrary subject); pins bind
// the key itself and stand alone. Pin comparisons are constant-time.
type mtlsAuthenticator struct {
	realm    string
	subjects map[string]struct{}
	pins     [][]byte
}

func newMTLSAuthenticator(cfg *Config) (Authenticator, error) {
	if len(cfg.MTLSAllowedSubjects) == 0 && len(cfg.MTLSAllowedSPKIPins) == 0 {
		return nil, errMTLSConfigRequired
	}
	for _, pin := range cfg.MTLSAllowedSPKIPins {
		if len(pin) != sha256.Size {
			return nil, errMTLSPinSize
		}
	}
	a := &mtlsAuthenticator{realm: cfg.Realm}
	if n := len(cfg.MTLSAllowedSubjects); n > 0 {
		a.subjects = make(map[string]struct{}, n)
		for _, s := range cfg.MTLSAllowedSubjects {
			a.subjects[s] = struct{}{}
		}
	}
	if n := len(cfg.MTLSAllowedSPKIPins); n > 0 {
		a.pins = make([][]byte, n)
		for i, pin := range cfg.MTLSAllowedSPKIPins {
			cp := make([]byte, sha256.Size)
			copy(cp, pin)
			a.pins[i] = cp
		}
	}
	return a, nil
}

func (a *mtlsAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	if r.TLS == nil {
		return nil, errMTLSNoTLS
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, errMTLSNoCert
	}
	cert := r.TLS.PeerCertificates[0]
	if !a.accept(cert, len(r.TLS.VerifiedChains) > 0) {
		return nil, errMTLSRejected
	}
	return &Identity{Method: ModeMTLS, Subject: cert.Subject.CommonName, PeerCert: cert}, nil
}

func (a *mtlsAuthenticator) accept(cert *x509.Certificate, chainVerified bool) bool {
	if chainVerified && len(a.subjects) > 0 {
		if _, ok := a.subjects[cert.Subject.CommonName]; ok {
			return true
		}
		if _, ok := a.subjects[cert.Subject.String()]; ok {
			return true
		}
	}
	if len(a.pins) > 0 {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		for _, pin := range a.pins {
			if subtle.ConstantTimeCompare(pin, sum[:]) == 1 {
				return true
			}
		}
	}
	return false
}

// Challenge returns 401 with no WWW-Authenticate: mTLS authentication is
// concluded at the TLS handshake and there is no in-band re-prompt scheme.
func (a *mtlsAuthenticator) Challenge(err error, _ string) (status int, header, message string) {
	status, _, message = challengeFromError(a.realm, err, "")
	return status, "", message
}

func (*mtlsAuthenticator) Metadata(_ string) *ProtectedResourceMetadata { return nil }
