package authware

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/ubyte-source/go-authware/v2/internal/problems"
)

// MTLSConfig configures ModeMTLS. A certificate passes when a verified chain
// matches a subject, or when its SPKI SHA-256 matches a pin.
type MTLSConfig struct {
	// AllowedSubjects (AUTH_MTLS_ALLOWED_SUBJECTS, a semicolon list) holds common
	// names, or distinguished names when an entry contains '=', each written as
	// pkix.Name.String renders it, but with a dotted type's value as #DER hex.
	AllowedSubjects []string
	// AllowedSPKIPins (AUTH_MTLS_SPKI_PINS, a list of base64 digests) holds the
	// SHA-256 digests of accepted SubjectPublicKeyInfo.
	AllowedSPKIPins [][]byte
}

// inUse reports whether any mTLS setting is present.
func (m *MTLSConfig) inUse() bool { return len(m.AllowedSubjects) > 0 || len(m.AllowedSPKIPins) > 0 }

// validate requires subjects or SPKI pins, each subject in rendered form and
// each pin of the SHA-256 size.
func (m *MTLSConfig) validate(p *problems.List) {
	if !m.inUse() {
		p.Addf("mtls needs allowed subjects or SPKI pins")
	}
	for _, s := range m.AllowedSubjects {
		switch {
		case s == "":
			p.Addf("mtls allowed subject is empty")
		case !renderedSubject(s):
			p.Addf("mtls allowed subject %q is not written as a subject renders", s)
		}
	}
	for i, pin := range m.AllowedSPKIPins {
		if len(pin) != sha256.Size {
			p.Addf("mtls SPKI pin %d is not a 32-byte SHA-256", i)
		}
	}
}

// renderedSubject reports whether s, a subject entry, is a common name or a
// distinguished name that subjectDN renders exactly as written.
func renderedSubject(s string) bool {
	if !strings.Contains(s, "=") {
		return subjectDN(&pkix.Name{CommonName: unescaped(s)}) == "CN="+s
	}
	rdns := parseDN(s)
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	return subjectDN(&name) == s
}

// subjectDN renders name, parsed from a certificate or by parseDN, as
// pkix.Name.String does, but writes the value of a dotted type that has a DER
// encoding as # and its hex whatever the Go version.
func subjectDN(name *pkix.Name) string {
	var b strings.Builder
	for _, rdn := range slices.Backward(name.ToRDNSequence()) {
		for i, atv := range rdn {
			writeSeparator(&b, i)
			writeAttribute(&b, atv)
		}
	}
	for _, atv := range slices.Backward(name.Names) {
		if x520Name(atv.Type) == "" {
			writeSeparator(&b, 0)
			writeAttribute(&b, atv)
		}
	}
	return b.String()
}

// writeSeparator writes the plus sign before the attribute at index inRDN > 0
// of its RDN, or the comma before the first attribute of a later RDN.
func writeSeparator(b *strings.Builder, inRDN int) {
	switch {
	case inRDN > 0:
		b.WriteByte('+')
	case b.Len() != 0:
		b.WriteByte(',')
	}
}

// writeAttribute writes atv as TYPE=value: a named type with its escaped value,
// a dotted type with # and the hex of its value's DER, or with the escaped text
// of a value that has none.
func writeAttribute(b *strings.Builder, atv pkix.AttributeTypeAndValue) {
	name := x520Name(atv.Type)
	if name == "" {
		name = atv.Type.String()
		if der, err := asn1.Marshal(atv.Value); err == nil {
			b.WriteString(name)
			b.WriteString("=#")
			b.WriteString(hex.EncodeToString(der))
			return
		}
	}
	b.WriteString(name)
	b.WriteByte('=')
	value, ok := atv.Value.(string)
	if !ok {
		value = fmt.Sprint(atv.Value)
	}
	writeEscaped(b, value)
}

// writeEscaped writes value with a backslash before each of ,+"\<>; and
// before a space at either end or a # at the start; a byte outside UTF-8 is
// written as U+FFFD.
func writeEscaped(b *strings.Builder, value string) {
	for k, c := range value {
		escape := false
		switch c {
		case ',', '+', '"', '\\', '<', '>', ';':
			escape = true
		case ' ':
			escape = k == 0 || k == len(value)-1
		case '#':
			escape = k == 0
		}
		if escape {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
}

// parseDN returns the RDN sequence that dn spells, RDNs last first, reading each
// attribute with parseAttribute; nil, which renders as no DN, when one is refused.
func parseDN(dn string) pkix.RDNSequence {
	var rdns pkix.RDNSequence
	for _, attrs := range slices.Backward(splitDN(dn)) {
		rdn := make([]pkix.AttributeTypeAndValue, len(attrs))
		for i, attr := range attrs {
			var ok bool
			if rdn[i], ok = parseAttribute(attr); !ok {
				return nil
			}
		}
		rdns = append(rdns, rdn)
	}
	return rdns
}

// splitDN cuts dn into its RDNs at unescaped commas, and each RDN into its
// attributes at unescaped plus signs.
func splitDN(dn string) [][]string {
	var rdns [][]string
	var rdn []string
	start, escaped := 0, false
	for i := range len(dn) {
		switch c := dn[i]; {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == ',' || c == '+':
			rdn, start = append(rdn, dn[start:i]), i+1
			if c == ',' {
				rdns, rdn = append(rdns, rdn), nil
			}
		}
	}
	return append(rdns, append(rdn, dn[start:]))
}

// X.520 attribute types have the x520Arcs arcs 2.5.4.n, n the last arc of a
// type below; pkix.Name keeps one common name and one serial number, the last
// of each, and its String names x520Named types.
const (
	x520Arcs         = 4
	x520Named        = 9
	arcJointISOITUT  = 2
	arcDS            = 5
	arcAttributeType = 4
	arcCommonName    = 3
	arcSerialNumber  = 5
	arcCountry       = 6
	arcLocality      = 7
	arcProvince      = 8
	arcStreet        = 9
	arcOrganization  = 10
	arcOrgUnit       = 11
	arcPostalCode    = 17
)

// x520Type is the type 2.5.4.arc and the name pkix.Name.String writes for it.
type x520Type struct {
	arc  int
	name string
}

// x520Types returns the types pkix.Name.String writes by name.
func x520Types() [x520Named]x520Type {
	return [...]x520Type{
		{arcCommonName, "CN"}, {arcSerialNumber, "SERIALNUMBER"}, {arcCountry, "C"}, {arcLocality, "L"},
		{arcProvince, "ST"}, {arcStreet, "STREET"}, {arcOrganization, "O"}, {arcOrgUnit, "OU"},
		{arcPostalCode, "POSTALCODE"},
	}
}

// x520Arc returns n when t is the X.520 attribute type 2.5.4.n.
func x520Arc(t asn1.ObjectIdentifier) (int, bool) {
	if len(t) != x520Arcs || t[0] != arcJointISOITUT || t[1] != arcDS || t[2] != arcAttributeType {
		return 0, false
	}
	return t[x520Arcs-1], true
}

// x520Name returns the name pkix.Name.String writes for the type t, or "" for
// a type it writes dotted.
func x520Name(t asn1.ObjectIdentifier) string {
	arc, ok := x520Arc(t)
	for _, x := range x520Types() {
		if ok && x.arc == arc {
			return x.name
		}
	}
	return ""
}

// parseAttribute reads attr, TYPE=value: a type pkix.Name.String names with
// its escaped value, or a dotted OID with the hex of a DER string after '#',
// the only values a certificate's subject holds; ok is false for any other.
func parseAttribute(attr string) (pkix.AttributeTypeAndValue, bool) {
	typ, value, _ := strings.Cut(attr, "=")
	for _, x := range x520Types() {
		if x.name == typ {
			oid := asn1.ObjectIdentifier{arcJointISOITUT, arcDS, arcAttributeType, x.arc}
			return pkix.AttributeTypeAndValue{Type: oid, Value: unescaped(value)}, true
		}
	}
	oid, dotted := dottedOID(typ)
	encoded, hashed := strings.CutPrefix(value, "#")
	s, decoded := derString(encoded)
	if !dotted || !hashed || !decoded {
		return pkix.AttributeTypeAndValue{}, false
	}
	return pkix.AttributeTypeAndValue{Type: oid, Value: s}, true
}

// derString returns the string that encoded, the hex of exactly one DER
// string, holds; ok is false, and s empty, when encoded is not one.
func derString(encoded string) (s string, ok bool) {
	der, err := hex.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil || len(rest) > 0 {
		return "", false
	}
	return s, true
}

// The arcs of a dotted OID: minArcs of them at least, decimal, and 31 bits
// wide at most, as in the certificates crypto/x509 parses.
const (
	minArcs = 2
	arcBase = 10
	arcBits = 31
)

// dottedOID parses s, decimal arcs joined by dots, as an object identifier
// of minArcs arcs or more.
func dottedOID(s string) (asn1.ObjectIdentifier, bool) {
	var oid asn1.ObjectIdentifier
	for arc := range strings.SplitSeq(s, ".") {
		n, err := strconv.ParseUint(arc, arcBase, arcBits)
		if err != nil {
			return nil, false
		}
		oid = append(oid, int(n))
	}
	if len(oid) < minArcs {
		return nil, false
	}
	return oid, true
}

// unescaped returns the value that entry, an escaped attribute value, spells:
// each backslash escapes the byte after it.
func unescaped(entry string) string {
	if !strings.Contains(entry, `\`) {
		return entry
	}
	var b strings.Builder
	escaped := false
	for i := range len(entry) {
		c := entry[i]
		if c == '\\' && !escaped {
			escaped = true
			continue
		}
		escaped = false
		b.WriteByte(c)
	}
	return b.String()
}

// pinPrefix starts the subject of a pinned key whose chain is unverified.
const pinPrefix = "sha256/"

// mtlsAuthenticator admits a client certificate whose verified chain matches
// an allowed common or distinguished name, or whose SPKI digest is pinned. A
// DN proves nothing without a verified chain, so such a pin names the client.
type mtlsAuthenticator struct {
	cns    map[string]struct{}
	dnames map[string]struct{}
	// pins maps each pinned digest to the subject it reports without a chain.
	pins map[[sha256.Size]byte]string
	// absent refuses a request without a certificate, rejected any other.
	absent   *authError
	rejected *authError
}

func newMTLSAuthenticator(c MTLSConfig) *mtlsAuthenticator {
	a := &mtlsAuthenticator{
		cns:      make(map[string]struct{}, len(c.AllowedSubjects)),
		dnames:   make(map[string]struct{}, len(c.AllowedSubjects)),
		pins:     make(map[[sha256.Size]byte]string, len(c.AllowedSPKIPins)),
		absent:   failure(ErrMissingCredentials, "no client certificate", nil),
		rejected: failure(ErrInvalidCredentials, "client certificate rejected", nil),
	}
	for _, s := range c.AllowedSubjects {
		if strings.Contains(s, "=") {
			a.dnames[s] = struct{}{}
		} else {
			a.cns[unescaped(s)] = struct{}{}
		}
	}
	for _, pin := range c.AllowedSPKIPins {
		a.pins[[sha256.Size]byte(pin)] = pinPrefix + base64.StdEncoding.EncodeToString(pin)
	}
	return a
}

func (a *mtlsAuthenticator) authenticate(r *http.Request) (*Identity, *authError) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, a.absent
	}
	cert := r.TLS.PeerCertificates[0]
	verified := len(r.TLS.VerifiedChains) > 0
	if verified {
		if subject, ok := a.allowedSubject(cert); ok {
			return &Identity{mode: ModeMTLS, subject: subject, peer: cert}, nil
		}
	}
	subject, ok := a.pins[sha256.Sum256(cert.RawSubjectPublicKeyInfo)]
	if !ok {
		return nil, a.rejected
	}
	if verified {
		subject = subjectDN(&cert.Subject)
	}
	return &Identity{mode: ModeMTLS, subject: subject, peer: cert}, nil
}

func (*mtlsAuthenticator) challengeScheme() string { return "" }

func (*mtlsAuthenticator) mode() Mode { return ModeMTLS }

// allowedSubject returns the allowed DN or CN of cert. A subject repeating
// its common name or serial number matches nothing, since pkix.Name keeps
// only the last; the DN is rendered only when some DN is allowed.
func (a *mtlsAuthenticator) allowedSubject(cert *x509.Certificate) (string, bool) {
	if repeatsSingleValued(cert.Subject.Names) {
		return "", false
	}
	if len(a.dnames) > 0 {
		dn := subjectDN(&cert.Subject)
		if _, ok := a.dnames[dn]; ok {
			return dn, true
		}
	}
	if _, ok := a.cns[cert.Subject.CommonName]; ok {
		return cert.Subject.CommonName, true
	}
	return "", false
}

// repeatsSingleValued reports whether names holds more than one common name
// or more than one serial number.
func repeatsSingleValued(names []pkix.AttributeTypeAndValue) bool {
	cns, serials := 0, 0
	for _, atv := range names {
		arc, ok := x520Arc(atv.Type)
		if !ok {
			continue
		}
		switch arc {
		case arcCommonName:
			cns++
		case arcSerialNumber:
			serials++
		}
	}
	return cns > 1 || serials > 1
}
