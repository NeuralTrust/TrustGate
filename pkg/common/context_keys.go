package common

type contextKey string

const (
	LoggerKey             contextKey = "logger"
	FastHTTPKey           contextKey = "fasthttp"
	ResponseWriterKey     contextKey = "http_response_writer"
	MetadataKey           contextKey = "metadata"
	CacherKey             contextKey = "cacher"
	StageKey              contextKey = "stage"
	GatewayContextKey     contextKey = "gateway_id"
	ApiKeyContextKey      contextKey = "api_key"
	GatewayDataContextKey contextKey = "gateway_data"
)
