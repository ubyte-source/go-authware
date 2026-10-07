// Package flight runs one shared call on behalf of many concurrent callers: a
// [Group] starts at most one call at a time, detached from the cancellation of
// the caller that starts it and bounded by its own timeout, so a caller that
// gives up returns early with its own context error while the call completes
// for everyone still waiting. No argument may be nil.
package flight
