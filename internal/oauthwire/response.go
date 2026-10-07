package oauthwire

import (
	"net/http"

	"github.com/ubyte-source/go-jsonfast"
)

const (
	// JSONContentType is the media type of the module's JSON responses and the one its
	// token and document requests accept.
	JSONContentType = "application/json"
	// CacheNoStore is the Cache-Control value of responses that carry credentials.
	CacheNoStore = "no-store"
	// PragmaNoCache is the Pragma value of responses that carry credentials.
	PragmaNoCache = "no-cache"
)

// WriteError writes the OAuth JSON error response of code, and of description
// unless it is empty, that caches must not keep.
func WriteError(w http.ResponseWriter, status int, code, description string) {
	b := jsonfast.Acquire()
	defer jsonfast.Release(b)
	b.BeginObject()
	b.AddStringField(ParamError, code)
	if description != "" {
		b.AddStringField(ParamErrorDescription, description)
	}
	b.EndObject()
	w.Header().Set("Pragma", PragmaNoCache)
	WriteJSON(w, status, b.Bytes())
}

// WriteJSON writes a JSON response with status that caches must not keep.
func WriteJSON(w http.ResponseWriter, status int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", JSONContentType)
	h.Set("Cache-Control", CacheNoStore)
	WriteBody(w, status, body)
}

// WriteBody sends status and body after the headers already set on w. A
// failed write means the client is gone, so its error has no receiver.
func WriteBody(w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)
	_, _ = w.Write(body) //nolint:errcheck // a failed write means the client is gone
}
