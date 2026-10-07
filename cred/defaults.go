package cred

import "time"

// Defaults of the token sources and the cache.
const (
	defaultTokenType = "Bearer"

	// defaultTimeout bounds outbound fetches and cache refreshes.
	defaultTimeout   = 10 * time.Second
	defaultCacheSkew = 30 * time.Second

	defaultGCPScope         = "https://www.googleapis.com/auth/cloud-platform"
	defaultAzureMSIEndpoint = "http://" + azureIMDSHost + "/metadata/identity/oauth2/token"
	defaultGCPMetadataURL   = "http://" + gcpMetadataHost
)
