// Package oauthwire holds the OAuth 2.0 wire format shared by the outbound
// credential sources and the authorization server facade: the parameter names
// and error codes both sides use, the client parameters ([SetClientParams]),
// strict token response decoding ([ParseTokenResponse]), error responses
// ([WriteError]), uncached JSON replies ([WriteJSON]) over [WriteBody], the
// token request ([NewTokenRequest]) and the metadata request ([NewGetRequest])
// to URLs accepted by the netguard policy, the bounded fetch ([Fetch]) of a
// caller-supplied non-redirecting client, which reads the status of an answer
// before its body, and the token answer of any status ([Send]) the facade relays.
// Each caller passes the errors that report its failures. No argument may be nil
// unless its godoc says what nil means.
package oauthwire
