package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractOpenAIResponseFromResponsesSSE(t *testing.T) {
	sse := "event: x\n" +
		"data: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\"}}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"done\",\"object\":\"response\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}],\"usage\":{\"total_tokens\":9}}}\n"

	raw, ok := ExtractOpenAIResponseFromResponsesSSE([]byte(sse))
	require.True(t, ok)
	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &obj))
	assert.Equal(t, "response", obj["object"])
	u, _ := obj["usage"].(map[string]interface{})
	require.NotNil(t, u)
	assert.Equal(t, float64(9), u["total_tokens"])
}

func TestExtractOpenAIResponseFromResponsesSSE_NotSSE(t *testing.T) {
	_, ok := ExtractOpenAIResponseFromResponsesSSE([]byte(`{"id":"x"}`))
	assert.False(t, ok)
}

func TestOpenAIAdapter_DecodeResponse_ResponsesSSE(t *testing.T) {
	a := &OpenAIAdapter{}
	sse := "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}],\"usage\":{\"total_tokens\":3}}}\n"
	cr, err := a.DecodeResponse([]byte(sse))
	require.NoError(t, err)
	assert.Contains(t, cr.Content, "hi")
	assert.Equal(t, 3, cr.Usage.TotalTokens)
}
