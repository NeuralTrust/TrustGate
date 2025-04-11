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
	TraceID        string            `json:"trace_id"`
	InteractionID  string            `json:"interaction_id"`
	ConversationID string            `json:"conversation_id"`
	Input          string            `json:"input"`
	Output         string            `json:"output"`
	Task           string            `json:"task"`
	Type           string            `json:"type"`
	StartTimestamp int64             `json:"start_timestamp"`
	EndTimestamp   int64             `json:"end_timestamp"`
	Latency        int64             `json:"latency_ms"`
	IP             string            `json:"ip,omitempty"`
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

	// Plugin Params
	Extras *PluginDataEvent `json:"extras,omitempty"`
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
}

type PluginDataEvent struct {
	PluginName    string `json:"plugin_name"`
	ExecutionTime int64  `json:"execution_time"`
	Stage         string `json:"stage"`
	Error         bool   `json:"error"`
	ErrorMessage  string `json:"error_message,omitempty"`
	Code          string `json:"code,omitempty"`
}

func NewTraceEvent() *Event {
	return &Event{
		InteractionID:  uuid.New().String(),
		ConversationID: uuid.New().String(),
		Task:           "message",
		Type:           TraceType,
		StartTimestamp: time.Now().Unix(),
	}
}

func NewPluginEvent() *Event {
	return &Event{
		InteractionID:  uuid.New().String(),
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
