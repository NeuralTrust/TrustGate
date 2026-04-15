package common

type contextKey string

const TraceIDHeader = "X-Trace-ID"

const (
	TraceIdKey                 contextKey = "trace_id"
	MetadataKey                contextKey = "metadata"
	CacherKey                  contextKey = "cacher"
	StageKey                   contextKey = "stage"
	GatewayContextKey          contextKey = "gateway_id"
	ApiKeyContextKey           contextKey = "api_key"
	ApiKeyIdContextKey         contextKey = "api_key_id"
	GatewayDataContextKey      contextKey = "gateway_data"
	FingerprintIdContextKey    contextKey = "fingerprint_id"
	MatchedRuleContextKey      contextKey = "matched_rule"
	LatencyContextKey          contextKey = "__execution_time"
	WsRequestContextContextKey contextKey = "__req_context"
	StreamResponseContextKey   contextKey = "__stream_response"
	StreamModeContextKey       contextKey = "__stream_mode"
	StreamDoneContextKey       contextKey = "__stream_done"
	PluginsDoneContextKey      contextKey = "__plugins_done"
	SessionContextKey          contextKey = "session_id"
	PathParamsKey              contextKey = "path_params"
	TeamIDContextKey           contextKey = "team_id"
	UserIDContextKey           contextKey = "user_id"
	UserEmailContextKey        contextKey = "user_email"
)
