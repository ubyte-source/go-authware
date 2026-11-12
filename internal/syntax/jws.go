package syntax

import "strings"

// JWS holds the three segments of a compact JWS, still encoded.
type JWS struct {
	// Header is the first segment, the base64url form of the JOSE header.
	Header string
	// Payload is the second segment, the base64url form of the signed content.
	Payload string
	// Signature is the third segment, the base64url form of the signature.
	Signature string
}

// segmentEnd separates the segments of a compact JWS.
const segmentEnd = "."

// SplitJWS splits s at its dots, reporting false unless there are exactly two.
func SplitJWS(s string) (JWS, bool) {
	header, rest, first := strings.Cut(s, segmentEnd)
	payload, signature, second := strings.Cut(rest, segmentEnd)
	if !first || !second || strings.Contains(signature, segmentEnd) {
		return JWS{}, false
	}
	return JWS{Header: header, Payload: payload, Signature: signature}, true
}
