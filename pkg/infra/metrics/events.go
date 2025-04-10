package metrics

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
	Latency        int64             `json:"latency"`
	IP             string            `json:"ip,omitempty"`
	Params         map[string]string `json:"params,omitempty"`
}

type TraceEvent struct {
	Event
	Locale          string            `json:"locale,omitempty"`
	Device          string            `json:"device,omitempty"`
	Os              string            `json:"os,omitempty"`
	Browser         string            `json:"browser,omitempty"`
	Forwarded       bool              `json:"forwarded"`
	Upstream        UpstreamEvent     `json:"upstream"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	StatusCode      int               `json:"status_code"`
}

func NewTraceEvent() *TraceEvent {
	return &TraceEvent{
		Event: Event{
			InteractionID:  uuid.New().String(),
			ConversationID: uuid.New().String(),
			Task:           "message",
			Type:           TraceType,
			StartTimestamp: time.Now().Unix(),
		},
	}
}

func NewPluginEvent() *PluginEvent {
	return &PluginEvent{
		Event: Event{
			InteractionID:  uuid.New().String(),
			ConversationID: uuid.New().String(),
			Task:           "message",
			Type:           PluginType,
			StartTimestamp: time.Now().Unix(),
		},
	}
}

type UpstreamEvent struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

type TargetEvent struct {
	Path     string `json:"path,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type PluginEvent struct {
	Event
	Extras PluginDataEvent `json:"extras"`
}

type PluginDataEvent struct {
	PluginName    string `json:"plugin_name"`
	ExecutionTime int64  `json:"execution_time"`
	Stage         string `json:"stage"`
	Error         bool   `json:"error"`
	ErrorMessage  string `json:"error_message,omitempty"`
	Code          string `json:"code,omitempty"`
}
