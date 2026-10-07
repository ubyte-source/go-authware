package authware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/syntax"
)

// SecurityHeadersConfig selects the headers written by SecurityHeaders; zero
// fields write nothing.
type SecurityHeadersConfig struct {
	// HSTSMaxAge is the Strict-Transport-Security max-age in seconds; a
	// non-positive value writes no Strict-Transport-Security.
	HSTSMaxAge int
	// CSP is the Content-Security-Policy value.
	CSP string
	// FrameOptions is the X-Frame-Options value.
	FrameOptions string
	// ReferrerPolicy is the Referrer-Policy value.
	ReferrerPolicy string
	// PermissionsPolicy is the Permissions-Policy value.
	PermissionsPolicy string
	// HSTSIncludeSubDomains adds includeSubDomains to Strict-Transport-Security.
	HSTSIncludeSubDomains bool
	// HSTSPreload adds preload to Strict-Transport-Security.
	HSTSPreload bool
	// ContentTypeNosniff writes X-Content-Type-Options: nosniff.
	ContentTypeNosniff bool
}

// SecurityHeaders writes the response headers selected by cfg, computed once;
// a nil cfg writes nothing.
func SecurityHeaders(cfg *SecurityHeadersConfig) func(http.Handler) http.Handler {
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
			values := make([]string, len(pre))
			for i, kv := range pre {
				values[i] = kv.text
				h[kv.name] = values[i : i+1 : i+1]
			}
			next.ServeHTTP(w, r)
		})
	}
}

func passthrough(next http.Handler) http.Handler { return next }

// headerKV is a header, its name in canonical form, and its value.
type headerKV struct {
	name string
	text string
}

// buildSecurityHeaders lists the headers that cfg selects.
func buildSecurityHeaders(cfg *SecurityHeadersConfig) []headerKV {
	var pre []headerKV
	if cfg.HSTSMaxAge > 0 {
		pre = append(pre, headerKV{"Strict-Transport-Security", buildHSTS(cfg)})
	}
	if cfg.CSP != "" {
		pre = append(pre, headerKV{"Content-Security-Policy", cfg.CSP})
	}
	if cfg.FrameOptions != "" {
		pre = append(pre, headerKV{"X-Frame-Options", cfg.FrameOptions})
	}
	if cfg.ContentTypeNosniff {
		pre = append(pre, headerKV{"X-Content-Type-Options", "nosniff"})
	}
	if cfg.ReferrerPolicy != "" {
		pre = append(pre, headerKV{"Referrer-Policy", cfg.ReferrerPolicy})
	}
	if cfg.PermissionsPolicy != "" {
		pre = append(pre, headerKV{"Permissions-Policy", cfg.PermissionsPolicy})
	}
	return pre
}

// buildHSTS renders the Strict-Transport-Security value of cfg.
func buildHSTS(cfg *SecurityHeadersConfig) string {
	var b strings.Builder
	b.WriteString("max-age=")
	b.WriteString(strconv.Itoa(cfg.HSTSMaxAge))
	if cfg.HSTSIncludeSubDomains {
		b.WriteString("; includeSubDomains")
	}
	if cfg.HSTSPreload {
		b.WriteString("; preload")
	}
	return b.String()
}

// sanitizeHeaderValue blanks control bytes to keep v on one header line; a
// value without any is returned as it is.
func sanitizeHeaderValue(v string) string {
	for i := range len(v) {
		if syntax.IsControl(v[i]) {
			return blankControls(v, i)
		}
	}
	return v
}

// blankControls copies v with every control byte, the first at i, blanked.
func blankControls(v string, i int) string {
	var b strings.Builder
	b.Grow(len(v))
	b.WriteString(v[:i])
	for ; i < len(v); i++ {
		c := v[i]
		if syntax.IsControl(c) {
			c = ' '
		}
		b.WriteByte(c)
	}
	return b.String()
}
