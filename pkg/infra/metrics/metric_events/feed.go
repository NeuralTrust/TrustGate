package metric_events

import (
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

const (
	headerConversationID = "X-Conversation-Id"
	headerInteractionID  = "X-Interaction-Id"

	redactedValue = "[REDACTED]"
)

// sensitiveHeaders are stored lower-cased; their values are never exported to a
// telemetry exporter to avoid leaking credentials/PII into the metrics topic.
var sensitiveHeaders = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"x-api-key":            {},
	"api-key":              {},
	"x-auth-token":         {},
	"x-access-token":       {},
	"x-amz-security-token": {},
}

// Exchange carries the request/response data captured for a single proxied
// call. It is the neutral input used to populate an Event, keeping this package
// free of any HTTP or request-context dependency.
type Exchange struct {
	GatewayID       string
	SessionID       string
	Method          string
	Path            string
	IP              string
	RequestHeaders  map[string][]string
	ResponseHeaders map[string][]string
	RequestBody     []byte
	ResponseBody    []byte
	StatusCode      int
	Streaming       bool
	TargetLatency   float64
	Usage           *adapter.CanonicalUsage
	StartTime       time.Time
	EndTime         time.Time
}

// Feed enriches the event in place with the data captured for a proxied call.
func (evt *Event) Feed(x Exchange) {
	evt.StartTimestamp = x.StartTime.UnixMilli()
	evt.EndTimestamp = x.EndTime.UnixMilli()
	evt.Latency = x.EndTime.Sub(x.StartTime).Milliseconds()
	evt.IP = x.IP
	evt.Method = x.Method
	evt.Path = x.Path
	evt.GatewayID = x.GatewayID

	if x.SessionID != "" {
		evt.SessionID = x.SessionID
	}
	if conversationID := lookupHeader(x.RequestHeaders, headerConversationID); conversationID != "" {
		evt.ConversationID = conversationID
	}
	if interactionID := lookupHeader(x.RequestHeaders, headerInteractionID); interactionID != "" {
		evt.InteractionID = interactionID
	}

	evt.Input = sanitizeBody(x.RequestBody, x.RequestHeaders)
	evt.Output = sanitizeBody(x.ResponseBody, x.ResponseHeaders)
	if evt.StatusCode == 0 {
		evt.StatusCode = x.StatusCode
	}
	evt.RequestHeaders = redactHeaders(x.RequestHeaders)
	evt.ResponseHeaders = redactHeaders(x.ResponseHeaders)
	evt.Streaming = x.Streaming
	if x.Usage != nil {
		evt.Usage = UsageEventFromCanonical(x.Usage)
	}

	if x.Streaming && evt.Upstream != nil {
		evt.Upstream.Target.Latency += int64(x.TargetLatency)
	}
}

// redactHeaders returns a copy of headers with the values of sensitive headers
// replaced by a redaction marker. The original map is never mutated.
func redactHeaders(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for key, values := range headers {
		if _, sensitive := sensitiveHeaders[strings.ToLower(key)]; sensitive {
			out[key] = []string{redactedValue}
			continue
		}
		out[key] = values
	}
	return out
}

func lookupHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
