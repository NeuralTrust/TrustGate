package adapter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Streaming Responses API bodies are decoded per SSE data line via DecodeStreamChunk,
// not as a full body in DecodeResponse.

func TestOpenAIAdapter_DecodeStreamChunk_ResponseCompleted(t *testing.T) {
	a := &OpenAIAdapter{}
	payload := `{"type":"response.completed","response":{"id":"r1","object":"response","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"hi"}]}],"usage":{"total_tokens":3}}}`
	sc, err := a.DecodeStreamChunk([]byte(payload))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "stop", sc.FinishReason)
	assert.Equal(t, "r1", sc.ID)
	require.NotNil(t, sc.Usage)
	assert.Equal(t, 3, sc.Usage.TotalTokens)
}

func TestOpenAIAdapter_DecodeStreamChunk_ResponseCreatedThenCompleted(t *testing.T) {
	a := &OpenAIAdapter{}
	sse := "event: x\n" +
		"data: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\"}}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"done\",\"object\":\"response\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}],\"usage\":{\"total_tokens\":9}}}\n"

	for _, line := range strings.Split(strings.ReplaceAll(sse, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		sc, err := a.DecodeStreamChunk([]byte(payload))
		require.NoError(t, err)
		if strings.Contains(payload, `"type":"response.created"`) {
			assert.Nil(t, sc, "created event has no canonical chunk mapping")
			continue
		}
		require.NotNil(t, sc, "completed event")
		assert.Equal(t, "stop", sc.FinishReason)
		require.NotNil(t, sc.Usage)
		assert.Equal(t, 9, sc.Usage.TotalTokens)
	}
}
