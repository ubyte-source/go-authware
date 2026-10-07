package authware

import "time"

// Defaults applied to a zero Config field.
const (
	defaultRealm        = "restricted"
	defaultKeyHeader    = "X-Api-Key"
	defaultClockSkew    = 30 * time.Second
	defaultKeysCacheTTL = 5 * time.Minute
	defaultFetchTimeout = 10 * time.Second
)
