// Package retry paces the calls that follow a failure or a forced call: a
// [Backoff] holds the end of a pause of [After] that a failed call starts or a
// forced call claims, and compares instants by their monotonic readings, so a
// step of the wall clock neither shortens nor stretches a pause.
package retry
