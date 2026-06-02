package metric_events

import (
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/google/uuid"
)

const (
	PluginType = "plugin"
	TraceType  = "trace"
)

type Event struct {
	GatewayID      string            `json:"gateway_id"`
	EngineID       string            `json:"engine_id"`
	TraceID        string            `json:"trace_id"`
	InteractionID  string            `json:"interaction_id"`
	ConversationID string            `json:"conversation_id"`
	UserID         string            `json:"user_id"`
	Path           string            `json:"path"`
	Input          string            `json:"input"`
	Output         string            `json:"output"`
	Task           string            `json:"task"`
	Type           string            `json:"type"`
	StartTimestamp int64             `json:"start_timestamp"`
	EndTimestamp   int64             `json:"end_timestamp"`
	Latency        int64             `json:"latency"`
	IP             string            `json:"user_ip,omitempty"`
	Params         map[string]string `json:"params,omitempty"`

	// Trace Params
	Method          string              `json:"method,omitempty"`
	Error           string              `json:"error,omitempty"`
	Locale          string              `json:"locale,omitempty"`
	Device          string              `json:"device,omitempty"`
	Os              string              `json:"os,omitempty"`
	Browser         string              `json:"browser,omitempty"`
	Upstream        *UpstreamEvent      `json:"upstream,omitempty"`
	Usage           *UsageEvent         `json:"usage,omitempty"`
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	StatusCode      int                 `json:"status_code"`
	Streaming       bool                `json:"streaming"`

	// Failover params: per-hop attribution emitted once per backend attempt.
	// Attempt is the 1-based attempt index within the request, Fallback marks an
	// attempt against the consumer's fallback chain (vs the primary pool),
	// BackendID is the backend tried and Outcome is its classification
	// (success/retryable/terminal).
	Attempt   int    `json:"attempt,omitempty"`
	Fallback  bool   `json:"fallback,omitempty"`
	BackendID string `json:"backend_id,omitempty"`
	Outcome   string `json:"outcome,omitempty"`

	TeamID string `json:"team_id,omitempty"`
	AppID  string `json:"app_id,omitempty"`

	FeedBackTag  string `json:"feedback_tag,omitempty"`
	FeedBackText string `json:"feedback_text,omitempty"`

	SessionID     string `json:"session_id,omitempty"`
	FingerprintID string `json:"fingerprint_id,omitempty"`

	// Plugin Params
	Plugin *PluginDataEvent `json:"plugin,omitempty"`

	RuleID   string `json:"rule_id,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
}

type UpstreamEvent struct {
	Target TargetEvent `json:"target"`
}

type TargetEvent struct {
	Path     string            `json:"path,omitempty"`
	Host     string            `json:"host,omitempty"`
	Port     int               `json:"port,omitempty"`
	Protocol string            `json:"protocol,omitempty"`
	Provider string            `json:"provider,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Latency  int64             `json:"latency"`
}

type PluginDataEvent struct {
	PluginName   string      `json:"plugin_name"`
	Stage        string      `json:"stage"`
	Mode         string      `json:"mode,omitempty"`
	Decision     string      `json:"decision,omitempty"`
	Error        bool        `json:"error"`
	ErrorMessage string      `json:"error_message,omitempty"`
	Extras       interface{} `json:"extras,omitempty"`
	StatusCode   int         `json:"status_code,omitempty"`
	Latency      int64       `json:"latency"`
	LatencyUnit  string      `json:"latency_unit"`
}

type UsageEvent struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	TotalTokens              int `json:"total_tokens"`
	CachedInputTokens        int `json:"cached_input_tokens,omitempty"`
	ReasoningOutputTokens    int `json:"reasoning_output_tokens,omitempty"`
	ToolUseInputTokens       int `json:"tool_use_input_tokens,omitempty"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
}

func UsageEventFromCanonical(u *adapter.CanonicalUsage) *UsageEvent {
	if u == nil {
		return nil
	}
	return &UsageEvent{
		InputTokens:              u.InputTokens,
		OutputTokens:             u.OutputTokens,
		TotalTokens:              u.TotalTokens,
		CachedInputTokens:        u.CachedInputTokens,
		ReasoningOutputTokens:    u.ReasoningOutputTokens,
		ToolUseInputTokens:       u.ToolUseInputTokens,
		CacheCreationInputTokens: u.CacheCreationInputTokens,
		CacheReadInputTokens:     u.CacheReadInputTokens,
	}
}

func NewTraceEvent() *Event {
	return &Event{
		ConversationID: uuid.New().String(),
		Task:           "message",
		Type:           TraceType,
		StartTimestamp: time.Now().Unix(),
		Upstream:       &UpstreamEvent{},
	}
}

func NewPluginEvent() *Event {
	return &Event{
		ConversationID: uuid.New().String(),
		Task:           "message",
		Type:           PluginType,
		StartTimestamp: time.Now().Unix(),
		Upstream:       &UpstreamEvent{},
	}
}

func (evt *Event) IsTypePlugin() bool {
	return evt.Type == PluginType
}

func (evt *Event) IsTypeTrace() bool {
	return evt.Type == TraceType
}
