package oauthwire

import "net/url"

// SetClientParams sets client_id in form, and client_secret unless secret is
// empty, the credentials a client sends in the form body.
func SetClientParams(form url.Values, id, secret string) {
	form.Set(ParamClientID, id)
	if secret != "" {
		form.Set(ParamClientSecret, secret)
	}
}
