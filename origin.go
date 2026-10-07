package authware

import (
	"net/http"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/netguard"
	"github.com/ubyte-source/go-authware/v2/internal/oauthwire"
)

// originResolver derives the external origin of the service.
type originResolver struct {
	public     string
	trustProto bool
}

// origin returns PublicURL when set, else the scheme of the connection, or
// of X-Forwarded-Proto when trusted, joined with the request host.
func (o originResolver) origin(r *http.Request) string {
	return o.url(r, "", "")
}

// url returns the origin of r followed by prefix and path, built at once.
func (o originResolver) url(r *http.Request, prefix, path string) string {
	if o.public != "" {
		return o.public + prefix + path
	}
	scheme := netguard.SchemeHTTP
	switch {
	case r.TLS != nil:
		scheme = netguard.SchemeHTTPS
	case o.trustProto:
		if p := forwardedProto(r.Header); p != "" {
			scheme = p
		}
	}
	return scheme + "://" + r.Host + prefix + path
}

// forwardedProto returns http or https when the first X-Forwarded-Proto
// element spells it in any ASCII case, else "".
func forwardedProto(h http.Header) string {
	first, _, _ := strings.Cut(h.Get("X-Forwarded-Proto"), ",")
	first = strings.TrimSpace(first)
	for _, scheme := range [...]string{netguard.SchemeHTTP, netguard.SchemeHTTPS} {
		if len(first) == len(scheme) && strings.EqualFold(first, scheme) {
			return scheme
		}
	}
	return ""
}

// writeDocument sends a JSON metadata document. Documents derived from the
// request vary by host and scheme, so only a fixed origin allows shared caches.
func (o originResolver) writeDocument(w http.ResponseWriter, body []byte) {
	h := w.Header()
	h.Set("Content-Type", oauthwire.JSONContentType)
	if o.public != "" {
		h.Set("Cache-Control", "public, max-age=300")
	} else {
		h.Set("Cache-Control", "private, max-age=300")
		h.Set("Vary", "Host, X-Forwarded-Proto")
	}
	oauthwire.WriteBody(w, http.StatusOK, body)
}
