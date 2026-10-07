package authware

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"unicode/utf8"
)

// The organization of the DN tests, CN=admin,O=corp, the arc of the surname
// attribute, the largest arc of a parsed certificate and the emailAddress type.
const (
	testOrg    = "corp"
	arcSurname = 4
	maxArc     = 1<<arcBits - 1
	emailType  = "1.2.840.113549.1.9.1"
)

// otherArc ends a dotted type, intValue is an attribute value that is not a
// string, and shortCN a one-letter common name.
const (
	otherArc = 3
	intValue = 7
	shortCN  = "x"
)

// x520 returns the X.520 attribute type 2.5.4.arc.
func x520(arc int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{arcJointISOITUT, arcDS, arcAttributeType, arc}
}

// emailOID returns the type of the emailAddress attribute.
func emailOID(tb testing.TB) asn1.ObjectIdentifier {
	tb.Helper()
	oid, ok := dottedOID(emailType)
	if !ok {
		tb.Fatalf("dottedOID(%s) = false, want the email type", emailType)
	}
	return oid
}

func TestMTLSAuthenticator(t *testing.T) {
	pinned := testCert("pinned")
	pin := sha256.Sum256(pinned.RawSubjectPublicKeyInfo)
	pins := [][]byte{pin[:]}
	a := newMTLSAuthenticator(MTLSConfig{AllowedSubjects: []string{testCN, testAdminDN}, AllowedSPKIPins: pins})
	pinSubject := "sha256/" + base64.StdEncoding.EncodeToString(pin[:])
	pins[0][0]++
	tests := []struct {
		name    string
		cert    *x509.Certificate
		request func(testing.TB, *x509.Certificate) *http.Request
		subject string
	}{
		{"cn", testCert(testCN), verifiedMTLSRequest, testCN},
		{"dn", testCert(testAdmin, testOrg), verifiedMTLSRequest, testAdminDN},
		{"pin without chain", pinned, mtlsRequest, pinSubject},
		{"pin with chain", pinned, verifiedMTLSRequest, "CN=pinned"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, e := a.authenticate(tc.request(t, tc.cert))
			if e != nil || id.Subject() != tc.subject || id.Mode() != ModeMTLS || id.PeerCertificate() != tc.cert {
				t.Fatalf("authenticate = %+v, %v, want an mTLS identity of %s", id, e, tc.subject)
			}
		})
	}
}

// TestMTLSAuthenticatorPinSpoofsNoSubject presents a pinned key in a
// self-signed certificate naming an allowed DN: the pin, not the DN, names it.
func TestMTLSAuthenticatorPinSpoofsNoSubject(t *testing.T) {
	forged := testCert(testAdmin, testOrg)
	pin := sha256.Sum256(forged.RawSubjectPublicKeyInfo)
	a := newMTLSAuthenticator(MTLSConfig{AllowedSubjects: []string{testAdminDN}, AllowedSPKIPins: [][]byte{pin[:]}})
	id, e := a.authenticate(mtlsRequest(t, forged))
	if want := "sha256/" + base64.StdEncoding.EncodeToString(pin[:]); e != nil || id.Subject() != want {
		t.Fatalf("authenticate(unverified %s) = %+v, %v; want the subject %s", testAdminDN, id, e, want)
	}
	if HasSubject(testAdminDN).Allow(id) {
		t.Fatalf("HasSubject(%s).Allow(unverified certificate claiming it) = true, want false", testAdminDN)
	}
}

func TestMTLSAuthenticatorRejects(t *testing.T) {
	a := newMTLSAuthenticator(MTLSConfig{AllowedSubjects: []string{testCN, testAdminDN}})
	tests := []struct {
		name    string
		cert    *x509.Certificate
		request func(testing.TB, *x509.Certificate) *http.Request
		want    error
	}{
		{"cn without chain", testCert(testCN), mtlsRequest, ErrInvalidCredentials},
		{"dn without chain", testCert(testAdmin, testOrg), mtlsRequest, ErrInvalidCredentials},
		{"dn spelled as cn", testCert(testAdminDN), verifiedMTLSRequest, ErrInvalidCredentials},
		{"cn of dn entry", testCert(testAdmin), verifiedMTLSRequest, ErrInvalidCredentials},
		{"unknown", testCert("other"), verifiedMTLSRequest, ErrInvalidCredentials},
		{"no certificate", nil, mtlsRequest, ErrMissingCredentials},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, e := a.authenticate(tc.request(t, tc.cert))
			if id != nil || e == nil || !errors.Is(e, tc.want) {
				t.Fatalf("authenticate = %+v, %v, want nil, %v", id, e, tc.want)
			}
		})
	}
	pin := sha256.Sum256([]byte("spki-pinned"))
	pinned := newMTLSAuthenticator(MTLSConfig{AllowedSPKIPins: [][]byte{pin[:]}})
	for name, tc := range map[string]struct {
		a    *mtlsAuthenticator
		r    *http.Request
		want error
	}{
		"unpinned key": {pinned, verifiedMTLSRequest(t, testCert("other")), ErrInvalidCredentials},
		"plain HTTP":   {a, newReq(t, http.MethodGet, "/", http.NoBody), ErrMissingCredentials},
	} {
		if id, e := tc.a.authenticate(tc.r); id != nil || e == nil || !errors.Is(e, tc.want) {
			t.Fatalf("authenticate(%s) = %+v, %v, want nil, %v", name, id, e, tc.want)
		}
	}
}

// TestMTLSAuthenticatorAmbiguousSubject refuses a verified certificate that
// repeats its common name or serial number, whose last value pkix.Name keeps.
func TestMTLSAuthenticatorAmbiguousSubject(t *testing.T) {
	a := newMTLSAuthenticator(MTLSConfig{AllowedSubjects: []string{"admin", "CN=admin"}})
	oidCN, oidSerial := x520(arcCommonName), x520(arcSerialNumber)
	attr := func(oid asn1.ObjectIdentifier, v string) []pkix.AttributeTypeAndValue {
		return []pkix.AttributeTypeAndValue{{Type: oid, Value: v}}
	}
	for name, rdns := range map[string]pkix.RDNSequence{
		"two common names":  {attr(oidCN, "evil"), attr(oidCN, testAdmin)},
		"two serials":       {attr(oidSerial, "1"), attr(oidSerial, "2"), attr(oidCN, testAdmin)},
		"multi-valued pair": {append(attr(oidCN, "evil"), attr(oidCN, testAdmin)...)},
	} {
		if id, e := a.authenticate(verifiedMTLSRequest(t, mustSubjectCert(rdns, "spki"))); id != nil || e == nil ||
			!errors.Is(e, ErrInvalidCredentials) {
			t.Errorf("%s: authenticate = %+v, %v, want nil, ErrInvalidCredentials", name, id, e)
		}
	}
	oidSurname := x520(arcSurname)
	other := mustSubjectCert(pkix.RDNSequence{attr(oidSurname, "a"), attr(oidSurname, "b"), attr(oidCN, testAdmin)},
		"spki")
	if id, e := a.authenticate(verifiedMTLSRequest(t, other)); e != nil || id.Subject() != testAdmin {
		t.Fatalf("one common name beside repeated surnames: authenticate = %v, %v, want admin", id, e)
	}
}

func TestRepeatsSingleValued(t *testing.T) {
	cn, serial := x520(arcCommonName), x520(arcSerialNumber)
	for name, tc := range map[string]struct {
		types []asn1.ObjectIdentifier
		want  bool
	}{
		"one of each":      {[]asn1.ObjectIdentifier{cn, serial}, false},
		"two common names": {[]asn1.ObjectIdentifier{cn, serial, cn}, true},
		"two serials":      {[]asn1.ObjectIdentifier{serial, serial}, true},
		"longer arc": {[]asn1.ObjectIdentifier{cn, append(x520(arcCommonName), 1),
			{arcJointISOITUT, arcDS, arcAttributeType, 1, arcCommonName}}, false},
		"other arcs": {[]asn1.ObjectIdentifier{cn, {arcJointISOITUT, arcDS, arcDS, arcCommonName},
			{1, arcDS, arcAttributeType, arcCommonName}, {arcJointISOITUT, arcAttributeType, arcAttributeType,
				arcCommonName}},
			false},
		"other types": {[]asn1.ObjectIdentifier{x520(arcSurname), x520(arcSurname), x520(arcOrganization),
			x520(arcOrganization)}, false},
		"after an email": {[]asn1.ObjectIdentifier{emailOID(t), cn, cn}, true},
	} {
		names := make([]pkix.AttributeTypeAndValue, len(tc.types))
		for i, oid := range tc.types {
			names[i] = pkix.AttributeTypeAndValue{Type: oid, Value: "v"}
		}
		if got := repeatsSingleValued(names); got != tc.want {
			t.Errorf("%s: repeatsSingleValued = %v, want %v", name, got, tc.want)
		}
	}
}

func TestNewMTLSAuthenticator(t *testing.T) {
	pins := [][]byte{make([]byte, sha256.Size)}
	a := newMTLSAuthenticator(MTLSConfig{AllowedSubjects: []string{`a\,b`, "O=x"}, AllowedSPKIPins: pins})
	_, cn := a.cns["a,b"]
	_, dn := a.dnames["O=x"]
	pinSubject := a.pins[[sha256.Size]byte{}]
	if len(a.cns) != 1 || !cn || len(a.dnames) != 1 || !dn || len(a.pins) != 1 ||
		pinSubject != "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("authenticator = %+v, want the common name a,b, the DN O=x and the zero pin", a)
	}
}

// TestMTLSAuthenticatorRenderedCommonName allows common names written as
// pkix.Name.String renders them: each admits the certificate of its name.
func TestMTLSAuthenticatorRenderedCommonName(t *testing.T) {
	cns := map[string]string{`svc\;blue`: "svc;blue", `a\,b\+c`: "a,b+c", `\#hash`: "#hash", `q\"\\`: `q"\`}
	allowed := slices.Collect(maps.Keys(cns))
	a := newMTLSAuthenticator(MTLSConfig{AllowedSubjects: allowed})
	for entry, cn := range cns {
		if id, e := a.authenticate(verifiedMTLSRequest(t, testCert(cn))); e != nil || id.Subject() != cn {
			t.Errorf("authenticate(CN %q) with entry %q = %v, %v; want the identity %q", cn, entry, id, e, cn)
		}
		if id, e := a.authenticate(verifiedMTLSRequest(t, testCert(entry))); id != nil ||
			!errors.Is(e, ErrInvalidCredentials) {
			t.Errorf("authenticate(CN %q, the escaped entry) = %+v, %v, want nil, ErrInvalidCredentials", entry, id, e)
		}
	}
	if err := (&Config{Mode: ModeMTLS, MTLS: MTLSConfig{AllowedSubjects: allowed}}).Validate(); err != nil {
		t.Fatalf("Validate(rendered common names) = %v, want nil", err)
	}
}

func TestMTLSConfigInUse(t *testing.T) {
	for m, want := range map[*MTLSConfig]bool{
		{}: false, {AllowedSubjects: []string{}}: false, {AllowedSubjects: []string{"a"}}: true,
		{AllowedSPKIPins: [][]byte{{1}}}: true,
	} {
		if got := m.inUse(); got != want {
			t.Errorf("inUse(%+v) = %t, want %t", m, got, want)
		}
	}
}

func TestRenderedSubject(t *testing.T) {
	for s, want := range map[string]bool{
		testCN: true, `a\;b`: true, `\#x`: true, `x\#`: false, `\ lead`: true, "trail ": false, `trail\ `: true,
		"a;b": false, "a,b": false, `a\`: false, `a\\`: true, testAdminDN: true, `CN=a\,b`: true, `CN=a\`: false,
		`CN=a\\`: true, `CN=a\+b`: true, "CN=a=b": true, "OU=a+OU=b,O=corp": true,
		"CN=x," + emailType + "=#0c0b6140622e6578616d706c65": true, "CN=x," + emailType + "=a@b.example": false,
		"SERIALNUMBER=1,CN=x,OU=u,O=o,POSTALCODE=p,STREET=s,L=l,ST=st,C=IT": true,
		"CN=admin, O=corp": false, "cn=admin,o=corp": false, "O=corp,CN=admin": false, "CN=a+CN=b": false,
		"X=y": false, `CN=a\b`: false, "CN=admin,,O=corp": false, "1.2.3=#zz": false, "1.2.3=0c0161": false,
		"1.x.3=#130161": false, "5=#130161": false, "1.2.3=#1301": false, "1.2.3=#13016100": false,
		"1.2.3=#0c0161": false, "1.2.3=#130161": true, "1.2.4=#130162,1.2.3=#130161": true, "1.2.3=130161": false,
		"1.2.3=a": false, "=x": false, "CN=\xff": false, `=\<nil\>`: false, `CN=a,=\<nil\>`: false,
		`X=\<nil\>`: false, `1.2=\<nil\>`: false, `CN=a,1.2.3=\<nil\>`: false, "=#130161": false,
		"1.2.3=#0101ff": false, "1.2.3=#020101": false, "1.2.3=#0500": false, "1.2.3=#1e020061": false,
	} {
		if got := renderedSubject(s); got != want {
			t.Errorf("renderedSubject(%q) = %t, want %t", s, got, want)
		}
	}
}

// stdlibDN renders name with pkix.Name.String after giving every dotted type's
// value that has a DER encoding as that DER, which every Go version writes
// as # and its hex.
func stdlibDN(name *pkix.Name) string {
	named := []int{arcCommonName, arcSerialNumber, arcCountry, arcLocality, arcProvince, arcStreet,
		arcOrganization, arcOrgUnit, arcPostalCode}
	names := slices.Clone(name.Names)
	for i, atv := range names {
		t := atv.Type
		if len(t) == x520Arcs && t[0] == arcJointISOITUT && t[1] == arcDS && t[2] == arcAttributeType &&
			slices.Contains(named, t[3]) {
			continue
		}
		if der, err := asn1.Marshal(atv.Value); err == nil {
			names[i].Value = asn1.RawValue{FullBytes: der}
		}
	}
	dotted := *name
	dotted.Names = names
	return dotted.String()
}

// TestSubjectDN renders names as pkix.Name.String does on every Go version,
// a dotted type's string value included.
func TestSubjectDN(t *testing.T) {
	email := pkix.AttributeTypeAndValue{Type: emailOID(t), Value: "a@b.example"}
	other := asn1.ObjectIdentifier{1, 2, otherArc}
	for name, n := range map[string]pkix.Name{
		"empty":   {},
		"escapes": {CommonName: ` #a,b+c"d\e<f>g;h `, Organization: []string{"#", " ", "o p"}},
		"invalid utf-8": {CommonName: "a\xffb", Names: []pkix.AttributeTypeAndValue{
			{Type: other, Value: "\xfe"}}},
		"ordered": {SerialNumber: "1", CommonName: "x", OrganizationalUnit: []string{"u", "v"},
			Organization: []string{"o"}, PostalCode: []string{"p"}, StreetAddress: []string{"s"},
			Locality: []string{"l"}, Province: []string{"st"}, Country: []string{"IT"}},
		"dotted": {CommonName: shortCN, Names: []pkix.AttributeTypeAndValue{
			{Type: x520(arcCommonName), Value: shortCN}, email, {Type: other, Value: int64(intValue)},
			{Type: x520(arcSurname), Value: "s"}, {Type: other, Value: nil}}},
	} {
		if got, want := subjectDN(&n), stdlibDN(&n); got != want {
			t.Errorf("%s: subjectDN = %q, want %q", name, got, want)
		}
	}
	n := pkix.Name{CommonName: shortCN, Names: []pkix.AttributeTypeAndValue{email}}
	if got, want := subjectDN(&n), "CN=x,"+emailType+"=#0c0b6140622e6578616d706c65"; got != want {
		t.Fatalf("subjectDN(CN x, an email) = %q, want %q whatever the Go version", got, want)
	}
}

// FuzzSubjectDN renders fuzzed names as the standard library does, and reads
// each rendering of UTF-8 values back as itself.
func FuzzSubjectDN(f *testing.F) {
	f.Add("admin", "corp", "a@b.example", intValue)
	f.Add(` #a,b+c"d\e<f>g;h `, "", "", 0)
	f.Add("a\xff", "+", "\xfe", otherArc)
	f.Fuzz(func(t *testing.T, cn, org, value string, arc int) {
		n := pkix.Name{CommonName: cn, Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, arc & maxArc}, Value: value},
			{Type: x520(arc & 0xff), Value: org},
		}}
		if org != "" {
			n.Organization = []string{org}
		}
		got := subjectDN(&n)
		if want := stdlibDN(&n); got != want {
			t.Fatalf("subjectDN(%+v) = %q, want %q", n, got, want)
		}
		if got != "" && utf8.ValidString(value) && utf8.ValidString(org) && !renderedSubject(got) {
			t.Fatalf("renderedSubject(%q) = false, want true for a rendered subject", got)
		}
	})
}

func TestX520Name(t *testing.T) {
	for _, tc := range []struct {
		t    asn1.ObjectIdentifier
		want string
	}{
		{x520(arcCommonName), "CN"}, {x520(arcPostalCode), "POSTALCODE"}, {x520(arcSurname), ""},
		{x520(-1), ""}, {x520(arcPostalCode + 1), ""}, {append(x520(arcCommonName), 1), ""},
		{asn1.ObjectIdentifier{1, arcDS, arcAttributeType, arcCommonName}, ""},
		{asn1.ObjectIdentifier{arcJointISOITUT, 1, arcAttributeType, arcCommonName}, ""},
		{asn1.ObjectIdentifier{arcJointISOITUT, arcDS, 1, arcCommonName}, ""},
	} {
		if got := x520Name(tc.t); got != tc.want {
			t.Errorf("x520Name(%v) = %q, want %q", tc.t, got, tc.want)
		}
	}
}

// TestUnescapedAllocs returns a value without a backslash as it is.
func TestUnescapedAllocs(t *testing.T) {
	assertAllocs(t, 0, func() {
		if got := unescaped(testOrg); got != testOrg {
			t.Fatalf("unescaped(%q) = %q, want it unchanged", testOrg, got)
		}
	})
}

func TestParseAttribute(t *testing.T) {
	for attr, want := range map[string]string{
		"CN=a": "2.5.4.3", "SERIALNUMBER=1": "2.5.4.5", "1.2.3=#130161": "1.2.3", "=x": "", "X=y": "",
		"cn=a": "", "2.5.4.4=#130161": "2.5.4.4", "1=#130161": "", "1.2.3=#zz": "", "1.2.3=#0101ff": "",
		"1.2.3=130161": "", "1.2.3=#13016100": "", "x=#130161": "",
	} {
		atv, ok := parseAttribute(attr)
		refused := !ok && (atv.Type != nil || atv.Value != nil)
		if ok != (want != "") || ok && atv.Type.String() != want || refused {
			t.Errorf("parseAttribute(%q) = %v, %t; want the type %q, or the zero value when refused", attr, atv, ok,
				want)
		}
	}
}

// TestDerString reads the hex of exactly one DER string, and refuses odd or
// non-hex text, a DER value that is no string, and bytes after the value.
func TestDerString(t *testing.T) {
	type result struct {
		s  string
		ok bool
	}
	for encoded, want := range map[string]result{
		"130161": {"a", true}, "0c0161": {"a", true}, "0c00": {"", true}, "1301610": {}, "13016": {}, "zz": {},
		"0101ff": {}, "13016100": {}, "130261": {}, "": {},
	} {
		if s, ok := derString(encoded); s != want.s || ok != want.ok {
			t.Errorf("derString(%q) = %q, %t; want %q, %t", encoded, s, ok, want.s, want.ok)
		}
	}
}

func TestDottedOID(t *testing.T) {
	for s, want := range map[string]asn1.ObjectIdentifier{
		"1.2": {1, 2}, "1.2147483647": {1, maxArc}, "1": nil, "": nil, "1..2": nil, "1.-2": nil,
		"1.+2": nil, "1.2147483648": nil,
	} {
		if got, ok := dottedOID(s); ok != (want != nil) || !got.Equal(want) {
			t.Errorf("dottedOID(%q) = %v, %t; want %v", s, got, ok, want)
		}
	}
}

func TestUnescaped(t *testing.T) {
	for entry, want := range map[string]string{
		"svc": "svc", `svc\;x`: "svc;x", `c\\d`: `c\d`, `c\\;d`: `c\;d`, `tail\`: "tail", `\#lead`: "#lead",
	} {
		if got := unescaped(entry); got != want {
			t.Errorf("unescaped(%q) = %q, want %q", entry, got, want)
		}
	}
}

// TestMTLSAuthenticatorCommonNameOnly checks that an allow list without DNs
// admits a CN without rendering the subject DN.
func TestMTLSAuthenticatorCommonNameOnly(t *testing.T) {
	a := newMTLSAuthenticator(MTLSConfig{AllowedSubjects: []string{testCN}})
	r := verifiedMTLSRequest(t, testCert(testCN, testOrg))
	// One allocation: the identity alone.
	assertAllocs(t, 1, func() {
		if _, e := a.authenticate(r); e != nil {
			t.Errorf("authenticate = %v, want nil", e)
		}
	})
}

func BenchmarkMTLSAuthenticator(b *testing.B) {
	pinned := testCert("pinned")
	pin := sha256.Sum256(pinned.RawSubjectPublicKeyInfo)
	for _, bc := range []struct {
		name string
		cfg  MTLSConfig
		r    *http.Request
		want string
	}{
		{"common name", MTLSConfig{AllowedSubjects: []string{testCN}}, verifiedMTLSRequest(b, testCert(testCN)),
			testCN},
		{"subject DN", MTLSConfig{AllowedSubjects: []string{testAdminDN}},
			verifiedMTLSRequest(b, testCert(testAdmin, testOrg)), testAdminDN},
		{"SPKI pin", MTLSConfig{AllowedSPKIPins: [][]byte{pin[:]}}, mtlsRequest(b, pinned),
			"sha256/" + base64.StdEncoding.EncodeToString(pin[:])},
	} {
		a := newMTLSAuthenticator(bc.cfg)
		b.Run(bc.name, func(b *testing.B) {
			if id, e := a.authenticate(bc.r); e != nil || id.subject != bc.want {
				b.Fatalf("authenticate = %v, %v, want %s", id, e, bc.want)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, e := a.authenticate(bc.r); e != nil {
					b.Fatalf("authenticate = %v, want nil", e)
				}
			}
		})
	}
}

// ExampleMTLSConfig admits a client certificate by its common name over a
// verified chain, or by the SHA-256 pin of its key.
func ExampleMTLSConfig() {
	client, pinned := testCert("client.example"), testCert("anyone")
	pin := sha256.Sum256(pinned.RawSubjectPublicKeyInfo)
	spkiSHA256 := pin[:]
	gate, err := New(&Config{
		Mode: ModeMTLS,
		MTLS: MTLSConfig{
			AllowedSubjects: []string{"client.example", "CN=admin,O=corp"},
			AllowedSPKIPins: [][]byte{spkiSHA256},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, pathRoot, http.NoBody)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{client},
		VerifiedChains: [][]*x509.Certificate{{client}}}
	id, err := gate.Authenticate(r)
	fmt.Println(id.Subject(), err)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{pinned}}
	id, err = gate.Authenticate(r)
	fmt.Println(id.Subject(), err)
	// Output:
	// client.example <nil>
	// sha256/BI1oy9BwcDx6zD32DDP2nf3UUS7j3zekFjDCbOaPfIc= <nil>
}
