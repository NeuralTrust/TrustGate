package metric_events_test

import (
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvent_Feed(t *testing.T) {
	start := time.Now()
	end := start.Add(150 * time.Millisecond)

	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{
		GatewayID:       "gw-1",
		SessionID:       "sess-1",
		Method:          "POST",
		Path:            "/v1/chat/completions",
		IP:              "10.0.0.1",
		RequestHeaders:  map[string][]string{"X-Conversation-Id": {"conv-1"}, "x-interaction-id": {"int-1"}},
		ResponseHeaders: map[string][]string{"Content-Type": {"application/json"}},
		RequestBody:     []byte(`{"model":"gpt"}`),
		ResponseBody:    []byte(`{"ok":true}`),
		StatusCode:      200,
		Streaming:       true,
		StartTime:       start,
		EndTime:         end,
	})

	assert.Equal(t, "gw-1", evt.GatewayID)
	assert.Equal(t, "sess-1", evt.SessionID)
	assert.Equal(t, "POST", evt.Method)
	assert.Equal(t, "/v1/chat/completions", evt.Path)
	assert.Equal(t, "10.0.0.1", evt.IP)
	assert.Equal(t, int64(150), evt.Latency)
	assert.Equal(t, start.UnixMilli(), evt.StartTimestamp)
	assert.Equal(t, end.UnixMilli(), evt.EndTimestamp)
	assert.Equal(t, 200, evt.StatusCode)
	assert.Equal(t, `{"model":"gpt"}`, evt.Input)
	assert.Equal(t, `{"ok":true}`, evt.Output)
	assert.Equal(t, "conv-1", evt.ConversationID, "conversation id from header")
	assert.Equal(t, "int-1", evt.InteractionID, "interaction id is case-insensitive")
	assert.True(t, evt.Streaming, "streaming flag carried into the event")
}

func TestEvent_FeedNonStreaming(t *testing.T) {
	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{Streaming: false, StartTime: time.Now(), EndTime: time.Now()})
	assert.False(t, evt.Streaming)
}

func TestEvent_FeedMapsUsage(t *testing.T) {
	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{
		Usage:     &adapter.CanonicalUsage{InputTokens: 7, OutputTokens: 9, TotalTokens: 16},
		StartTime: time.Now(),
		EndTime:   time.Now(),
	})
	require.NotNil(t, evt.Usage)
	assert.Equal(t, 7, evt.Usage.InputTokens)
	assert.Equal(t, 9, evt.Usage.OutputTokens)
	assert.Equal(t, 16, evt.Usage.TotalTokens)
}

func TestEvent_FeedWithoutUsageLeavesNil(t *testing.T) {
	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{StartTime: time.Now(), EndTime: time.Now()})
	assert.Nil(t, evt.Usage)
}

func TestEvent_FeedDoesNotOverrideExistingStatus(t *testing.T) {
	evt := metric_events.NewTraceEvent()
	evt.StatusCode = 503
	evt.Feed(metric_events.Exchange{StatusCode: 200, StartTime: time.Now(), EndTime: time.Now()})
	assert.Equal(t, 503, evt.StatusCode)
}

func TestEvent_FeedMultipartBodyIsSanitized(t *testing.T) {
	body := "--BOUND\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\n\r\n" +
		"super secret contents\r\n" +
		"--BOUND--\r\n"

	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{
		RequestHeaders: map[string][]string{"Content-Type": {"multipart/form-data; boundary=BOUND"}},
		RequestBody:    []byte(body),
		StartTime:      time.Now(),
		EndTime:        time.Now(),
	})

	assert.Contains(t, evt.Input, "secret.txt")
	assert.NotContains(t, evt.Input, "super secret contents")
}

func TestEvent_FeedRedactsSensitiveHeaders(t *testing.T) {
	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{
		RequestHeaders: map[string][]string{
			"Authorization": {"Bearer super-secret-token"},
			"X-Api-Key":     {"sk-12345"},
			"cookie":        {"session=abc"},
			"X-Gateway-Id":  {"gw-1"},
		},
		ResponseHeaders: map[string][]string{
			"Set-Cookie":   {"session=abc; HttpOnly"},
			"Content-Type": {"application/json"},
		},
		StartTime: time.Now(),
		EndTime:   time.Now(),
	})

	assert.Equal(t, []string{"[REDACTED]"}, evt.RequestHeaders["Authorization"])
	assert.Equal(t, []string{"[REDACTED]"}, evt.RequestHeaders["X-Api-Key"])
	assert.Equal(t, []string{"[REDACTED]"}, evt.RequestHeaders["cookie"], "redaction is case-insensitive")
	assert.Equal(t, []string{"gw-1"}, evt.RequestHeaders["X-Gateway-Id"], "non-sensitive headers preserved")
	assert.Equal(t, []string{"[REDACTED]"}, evt.ResponseHeaders["Set-Cookie"])
	assert.Equal(t, []string{"application/json"}, evt.ResponseHeaders["Content-Type"])
}

func TestEvent_FeedDoesNotMutateInputHeaders(t *testing.T) {
	headers := map[string][]string{"Authorization": {"Bearer x"}}
	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{RequestHeaders: headers, StartTime: time.Now(), EndTime: time.Now()})
	assert.Equal(t, []string{"Bearer x"}, headers["Authorization"], "original header map must not be mutated")
}

func TestEvent_FeedCapsLargeBody(t *testing.T) {
	large := make([]byte, 200*1024)
	for i := range large {
		large[i] = 'a'
	}

	evt := metric_events.NewTraceEvent()
	evt.Feed(metric_events.Exchange{
		RequestBody: large,
		StartTime:   time.Now(),
		EndTime:     time.Now(),
	})

	assert.Less(t, len(evt.Input), len(large), "large body must be truncated")
	assert.Contains(t, evt.Input, "...[truncated]")
}

func TestEvent_FeedStreamingAddsUpstreamLatency(t *testing.T) {
	evt := metric_events.NewTraceEvent()
	evt.Upstream.Target.Latency = 10
	evt.Feed(metric_events.Exchange{
		Streaming:     true,
		TargetLatency: 40,
		StartTime:     time.Now(),
		EndTime:       time.Now(),
	})
	assert.Equal(t, int64(50), evt.Upstream.Target.Latency)
}
