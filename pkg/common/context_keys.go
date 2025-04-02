package common

type contextKey string

const (
	MetadataKey             contextKey = "metadata"
	CacherKey               contextKey = "cacher"
	StageKey                contextKey = "stage"
	GatewayContextKey       contextKey = "gateway_id"
	ApiKeyContextKey        contextKey = "api_key"
	ApiKeyIdContextKey      contextKey = "api_key_id"
	GatewayDataContextKey   contextKey = "gateway_data"
	PluginsChainContextKey  contextKey = "gateway_data"
	FingerprintIdContextKey contextKey = "fingerprint_id"
)
