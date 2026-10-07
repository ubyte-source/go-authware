// Package syntax holds the character rules, the compact JWS splitter and the
// strict base64url decoder shared across the module: [IsControl] spots an ASCII
// control byte, [IsUnreserved] accepts an unreserved URI character, [IsToken] a
// header name or an authentication scheme, [IsScope] an OAuth scope token and
// [IsFieldValue] a credential that travels intact in one header line, while
// [SplitJWS] splits the compact JWS form and [AppendSegment] decodes unpadded
// base64url, the encoding of its segments.
package syntax
