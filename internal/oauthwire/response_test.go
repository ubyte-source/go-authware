package oauthwire

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteError(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "invalid_request", `bad "redirect_uri"`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	for k, v := range map[string]string{
		headerContentType: "application/json",
		"Cache-Control":   "no-store",
		"Pragma":          "no-cache",
	} {
		if got := rec.Header().Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 2 ||
		got["error"] != "invalid_request" || got["error_description"] != `bad "redirect_uri"` {
		t.Fatalf("body = %s (%v), want the code and the quoted description", rec.Body, err)
	}
}

func TestWriteErrorOmitsEmptyDescription(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusUnauthorized, "invalid_client", "")
	if got := rec.Body.String(); got != `{"error":"invalid_client"}` {
		t.Fatalf("body = %s, want %s", got, `{"error":"invalid_client"}`)
	}
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, []byte(`{"a":1}`))
	hd := rec.Header()
	if rec.Code != http.StatusCreated || rec.Body.String() != `{"a":1}` ||
		hd.Get(headerContentType) != "application/json" ||
		hd.Get("Cache-Control") != "no-store" || hd.Get("Pragma") != "" {
		t.Fatalf("WriteJSON = %d %v %s, want 201 JSON no-store without Pragma", rec.Code, hd, rec.Body)
	}
}

func TestWriteBody(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	rec.Header().Set(headerContentType, "text/plain")
	WriteBody(rec, http.StatusAccepted, []byte("done"))
	if rec.Code != http.StatusAccepted || rec.Body.String() != "done" ||
		rec.Header().Get(headerContentType) != "text/plain" {
		t.Fatalf("WriteBody = %d %v %q, want 202 done with the headers set before", rec.Code, rec.Header(), rec.Body)
	}
}
