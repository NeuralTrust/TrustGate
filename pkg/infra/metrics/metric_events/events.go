package metric_events

import (
	"time"

	"github.com/google/uuid"
)

const (
	PluginType = "plugin"
	TraceType  = "trace"
)

type Event struct {
	GatewayID      string            `json:"gateway_id"`
	TraceID        string            `json:"trace_id"`
	InteractionID  string            `json:"interaction_id"`
	ConversationID string            `json:"conversation_id"`
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
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	StatusCode      int                 `json:"status_code"`

	LastStreamLine []byte `json:"-"`

	TeamID string `json:"team_id,omitempty"`
	AppID  string `json:"app_id,omitempty"`

	FeedBackTag  string `json:"feedback_tag,omitempty"`
	FeedBackText string `json:"feedback_text,omitempty"`

	SessionID string `json:"session_id,omitempty"`

	// Plugin Params
	Plugin *PluginDataEvent `json:"plugin,omitempty"`
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
	Error        bool        `json:"error"`
	ErrorMessage string      `json:"error_message,omitempty"`
	Extras       interface{} `json:"extras,omitempty"`
	StatusCode   int         `json:"status_code,omitempty"`
}

func NewTraceEvent() *Event {
	return &Event{
		ConversationID: uuid.New().String(),
		Task:           "message",
		Type:           TraceType,
		StartTimestamp: time.Now().Unix(),
	}
}

func NewPluginEvent() *Event {
	return &Event{
		ConversationID: uuid.New().String(),
		Task:           "message",
		Type:           PluginType,
		StartTimestamp: time.Now().Unix(),
	}
}

func (evt *Event) IsTypePlugin() bool {
	return evt.Type == PluginType
}

func (evt *Event) IsTypeTrace() bool {
	return evt.Type == TraceType
}
