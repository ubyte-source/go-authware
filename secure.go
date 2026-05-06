package authware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// MaxBytes limits inbound request body size to maxBytes via
// http.MaxBytesReader. A non-positive limit installs a passthrough.
func MaxBytes(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		return passthrough
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders writes a fixed set of response headers derived from
// cfg. Header values are pre-computed once; the per-request path is
// allocation-free.
func SecurityHeaders(cfg *SecureHeadersConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		return passthrough
	}
	pre := buildSecurityHeaders(cfg)
	if len(pre) == 0 {
		return passthrough
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			for i := range pre {
				h[pre[i].name] = pre[i].values
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFOptions configures the [CSRF] middleware.
type CSRFOptions struct {
	DenyHandler    http.Handler
	TrustedOrigins []string
	BypassPaths    []string
}

// CSRF wraps net/http.CrossOriginProtection. A malformed entry in
// TrustedOrigins is reported as an error.
func CSRF(opts CSRFOptions) (func(http.Handler) http.Handler, error) {
	cop := http.NewCrossOriginProtection()
	for _, origin := range opts.TrustedOrigins {
		if err := cop.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("CSRF trusted origin %q: %w", origin, err)
		}
	}
	for _, path := range opts.BypassPaths {
		cop.AddInsecureBypassPattern(path)
	}
	if opts.DenyHandler != nil {
		cop.SetDenyHandler(opts.DenyHandler)
	}
	return cop.Handler, nil
}

// headerKV is a precomputed canonical header name and a single-element
// values slice (len == cap == 1) suitable for direct map assignment.
type headerKV struct {
	name   string
	values []string
}

func newHeaderKV(name, value string) headerKV {
	return headerKV{name: http.CanonicalHeaderKey(name), values: []string{value}}
}

func buildSecurityHeaders(cfg *SecureHeadersConfig) []headerKV {
	pre := make([]headerKV, 0, 8)
	if cfg.HSTSMaxAge > 0 {
		pre = append(pre, newHeaderKV("Strict-Transport-Security", buildHSTS(cfg)))
	}
	if cfg.CSP != "" {
		pre = append(pre, newHeaderKV("Content-Security-Policy", cfg.CSP))
	}
	if cfg.FrameOptions != "" {
		pre = append(pre, newHeaderKV("X-Frame-Options", cfg.FrameOptions))
	}
	if cfg.ContentTypeNosniff {
		pre = append(pre, newHeaderKV("X-Content-Type-Options", "nosniff"))
	}
	if cfg.ReferrerPolicy != "" {
		pre = append(pre, newHeaderKV("Referrer-Policy", cfg.ReferrerPolicy))
	}
	if cfg.PermissionsPolicy != "" {
		pre = append(pre, newHeaderKV("Permissions-Policy", cfg.PermissionsPolicy))
	}
	if cfg.XSSProtection != "" {
		pre = append(pre, newHeaderKV("X-XSS-Protection", cfg.XSSProtection))
	}
	return pre
}

func buildHSTS(cfg *SecureHeadersConfig) string {
	var b strings.Builder
	b.Grow(48)
	b.WriteString("max-age=")
	b.WriteString(strconv.Itoa(cfg.HSTSMaxAge))
	if cfg.HSTSIncludeSubs {
		b.WriteString("; includeSubDomains")
	}
	if cfg.HSTSPreload {
		b.WriteString("; preload")
	}
	return b.String()
}

func passthrough(next http.Handler) http.Handler { return next }
