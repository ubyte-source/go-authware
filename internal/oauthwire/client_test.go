package oauthwire

import (
	"net/url"
	"testing"
)

// testClient is the client of the parameter tests.
const testClient = "app"

func TestSetClientParams(t *testing.T) {
	t.Parallel()
	for secret, want := range map[string]url.Values{
		"s3cret": {"client_id": {testClient}, "client_secret": {"s3cret"}, ParamScope: {"a"}},
		"":       {"client_id": {testClient}, ParamScope: {"a"}},
	} {
		form := url.Values{ParamScope: {"a"}, ParamClientID: {"stale"}}
		SetClientParams(form, testClient, secret)
		if form.Encode() != want.Encode() {
			t.Errorf("SetClientParams(secret %q) = %v, want %v", secret, form, want)
		}
	}
}
