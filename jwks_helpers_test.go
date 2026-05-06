package authware

// jwk and jwkSet are marshalable representations of a JSON Web Key set,
// used by tests to build fixture JWKS responses. Production code parses
// JWKS payloads directly via jsonfast and never instantiates these types.
type jwk struct {
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}
