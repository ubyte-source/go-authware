package cred

import (
	"net/http"
	"testing"
	"time"

	"github.com/ubyte-source/go-authware/v2/secret"
)

func TestDefaultTimeout(t *testing.T) {
	for timeout, want := range map[time.Duration]time.Duration{0: wantTimeout, customTimeout: customTimeout} {
		for _, src := range timedSources(t, timeout) {
			if c := sourceClient(t, src); c.Timeout != want || c.CheckRedirect == nil {
				t.Errorf("%T with Timeout %v: timeout %v, redirect policy set %v, want %v and true",
					src, timeout, c.Timeout, c.CheckRedirect != nil, want)
			}
		}
	}
}

// timedSources builds every token source that takes a Timeout with timeout.
func timedSources(t *testing.T, timeout time.Duration) []TokenSource {
	t.Helper()
	builds := []func() (TokenSource, error){
		func() (TokenSource, error) {
			return NewClientCredentials(&ClientCredentialsConfig{ClientConfig: ClientConfig{
				TokenURL: idpEndpoint, ClientID: "c", Timeout: timeout,
			}})
		},
		func() (TokenSource, error) {
			cfg := &ClientConfig{TokenURL: idpEndpoint, ClientID: "c",
				Timeout: timeout}
			return NewRefreshToken(cfg, NewMemoryRefreshStore(secret.Value{}))
		},
		func() (TokenSource, error) { return NewAzureMSI(&AzureMSIConfig{Resource: "r", Timeout: timeout}) },
		func() (TokenSource, error) { return NewGCPMetadata(&GCPMetadataConfig{Timeout: timeout}) },
	}
	sources := make([]TokenSource, 0, len(builds))
	for _, build := range builds {
		src, err := build()
		if err != nil {
			t.Fatalf("build = %v, want a source", err)
		}
		sources = append(sources, src)
	}
	return sources
}

func sourceClient(t *testing.T, src TokenSource) *http.Client {
	t.Helper()
	switch s := src.(type) {
	case *clientCredentials:
		return s.endpoint.client
	case *refreshToken:
		return s.endpoint.client
	case *metadataSource:
		return s.client
	}
	t.Fatalf("sourceClient(%T) = no client, want a source of this package", src)
	return nil
}

func TestDefaultAzureMSIEndpoint(t *testing.T) {
	src, err := NewAzureMSI(&AzureMSIConfig{Resource: "r"})
	if err != nil {
		t.Fatalf("NewAzureMSI = %v, want a source", err)
	}
	want := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=r"
	if m, ok := src.(*metadataSource); !ok || m.target.String() != want {
		t.Fatalf("source = %+v, want target %s", src, want)
	}
}

func TestDefaultGCPMetadataURL(t *testing.T) {
	src, err := NewGCPMetadata(&GCPMetadataConfig{})
	if err != nil {
		t.Fatalf("NewGCPMetadata = %v, want a source", err)
	}
	want := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" +
		"?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform"
	if g, ok := src.(*metadataSource); !ok || g.target.String() != want {
		t.Fatalf("source = %+v, want target %s", src, want)
	}
}
