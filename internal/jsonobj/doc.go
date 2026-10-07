// Package jsonobj holds the shape every JSON document the module parses must
// have: exactly one UTF-8 object, nested at most 32 deep, in which no object
// repeats a member name, as go-jsonfast checks and walks it. It maps go-jsonfast's
// failures to the caller's sentinel error and hands over names and values safe
// to keep, each value a substring of the document. No argument may be nil.
package jsonobj
