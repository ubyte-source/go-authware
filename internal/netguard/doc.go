// Package netguard holds the outbound URL policy shared by every fetch the
// module makes: [Check] accepts https URLs and plain http only toward a
// loopback host, and refuses userinfo in any form; [Client] derives a
// [net/http.Client] that never follows redirects, so the policy checked on
// the first URL is the policy of every request. Each caller passes the error
// that reports a refused URL or an oversized body: [ReadRequest] bounds the
// body of a server request and [ReadSized] any other, which [ReadClose] also
// closes; [Exchange] sends a request and closes the body of its answer, a
// [Digester] hashes the body of a client request within a bound and leaves it
// replayable, and [SplitZone] and [SentAsIs] model how net/http sends a request
// host. No argument may be nil unless its godoc says what nil means, and no
// byte limit is math.MaxInt64.
package netguard
