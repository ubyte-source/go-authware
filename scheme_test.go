package authware

import "testing"

const schemeLower = "bearer"

func TestParseAuthScheme(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		header string
		scheme string
		want   string
		wantOK bool
	}{
		{name: "exact lower", header: "bearer " + testTok, scheme: schemeLower, want: testTok, wantOK: true},
		{name: "canonical case", header: "Bearer " + testTok, scheme: schemeLower, want: testTok, wantOK: true},
		{name: "upper case", header: "BEARER " + testTok, scheme: schemeLower, want: testTok, wantOK: true},
		{name: "mixed case", header: "bEaReR " + testTok, scheme: schemeLower, want: testTok, wantOK: true},
		{name: "wrong scheme", header: "Basic tok", scheme: schemeLower, wantOK: false},
		{name: "missing space", header: "Bearertok", scheme: schemeLower, wantOK: false},
		{name: "empty credential", header: "Bearer ", scheme: schemeLower, wantOK: false},
		{name: "empty header", header: "", scheme: schemeLower, wantOK: false},
		{name: "scheme only", header: "Bearer", scheme: schemeLower, wantOK: false},
		{name: "scheme plus one char no space", header: "BearerX", scheme: schemeLower, wantOK: false},
		{name: "almost scheme", header: "Xearer tok", scheme: schemeLower, wantOK: false},
		{name: "tab separator", header: "Bearer\ttok", scheme: schemeLower, wantOK: false},
		{name: "double space keeps second", header: "Bearer  tok", scheme: schemeLower, want: " tok", wantOK: true},
		{name: "credential preserved verbatim", header: "apikey a.b-c_d=", scheme: "apikey", want: "a.b-c_d=", wantOK: true},
		{name: "scheme shorter than header prefix", header: "bear tok", scheme: schemeLower, wantOK: false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseAuthScheme(tt.header, tt.scheme)
			if ok != tt.wantOK {
				t.Fatalf("parseAuthScheme(%q, %q) ok = %v, want %v", tt.header, tt.scheme, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Fatalf("parseAuthScheme(%q, %q) = %q, want %q", tt.header, tt.scheme, got, tt.want)
			}
		})
	}
}
