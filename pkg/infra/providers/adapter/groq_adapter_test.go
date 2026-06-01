package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const groqResponseWithXGroq = `{
  "id": "chatcmpl-groq-1",
  "object": "chat.completion",
  "model": "llama-3.3-70b-versatile",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "hello"},
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 5,
    "total_tokens": 15
  },
  "x_groq": {
    "usage": {
      "queue_time": 0.012,
      "prompt_time": 0.034,
      "completion_time": 0.056,
      "total_time": 0.102
    }
  }
}`

const groqStreamFinalChunkWithXGroq = `{
  "id": "chatcmpl-groq-stream",
  "object": "chat.completion.chunk",
  "model": "llama-3.3-70b-versatile",
  "choices": [{
    "index": 0,
    "delta": {},
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 5,
    "total_tokens": 15
  },
  "x_groq": {
    "usage": {
      "queue_time": 0.012,
      "prompt_time": 0.034,
      "completion_time": 0.056,
      "total_time": 0.102
    }
  }
}`

const groqChatRequest = `{
  "model": "llama-3.3-70b-versatile",
  "messages": [{"role": "user", "content": "hi"}],
  "max_tokens": 128
}`

func groqAdapter(t *testing.T) ProviderAdapter {
	t.Helper()
	a, err := NewRegistry().GetAdapter(FormatGroq)
	require.NoError(t, err)
	return a
}

func TestGroqAdapter_FormatRegistration(t *testing.T) {
	assert.Equal(t, Format("groq"), FormatGroq)

	reg := NewRegistry()
	_, err := reg.GetAdapter(FormatGroq)
	require.NoError(t, err)

	assert.Equal(t, FormatGroq, ResolveTargetFormat("groq", nil))

	got, err := ResolveAgentFormat("groq", "", nil)
	require.NoError(t, err)
	assert.Equal(t, FormatGroq, got)

	assert.True(t, IsSameWireFormat(FormatGroq, FormatOpenAI))
	assert.True(t, IsSameWireFormat(FormatOpenAI, FormatGroq))

	assert.True(t, ShouldPassthroughSameWireFormat(FormatGroq, FormatGroq))
	assert.False(t, ShouldPassthroughSameWireFormat(FormatOpenAI, FormatGroq))
	assert.False(t, ShouldPassthroughSameWireFormat(FormatGroq, FormatOpenAI))

	opts := map[string]any{"api": "responses"}
	assert.Equal(t, FormatOpenAIResponses, ResolveTargetFormat("openai", opts))
	assert.Equal(t, FormatOpenAIResponses, ResolveTargetFormat("azure", opts))
	assert.Equal(t, FormatGroq, ResolveTargetFormat("groq", opts))
}

func TestGroqAdapter_RoundTripPreservesXGroqBlock(t *testing.T) {
	a := groqAdapter(t)

	canonical, err := a.DecodeResponse([]byte(groqResponseWithXGroq))
	require.NoError(t, err)
	require.NotNil(t, canonical.ProviderExtensions["x_groq"])

	encoded, err := a.EncodeResponse(canonical)
	require.NoError(t, err)

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &parsed))
	require.NotNil(t, parsed["x_groq"])

	var xGroq struct {
		Usage struct {
			QueueTime      float64 `json:"queue_time"`
			PromptTime     float64 `json:"prompt_time"`
			CompletionTime float64 `json:"completion_time"`
			TotalTime      float64 `json:"total_time"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(parsed["x_groq"], &xGroq))
	assert.InDelta(t, 0.012, xGroq.Usage.QueueTime, 1e-9)
	assert.InDelta(t, 0.034, xGroq.Usage.PromptTime, 1e-9)
	assert.InDelta(t, 0.056, xGroq.Usage.CompletionTime, 1e-9)
	assert.InDelta(t, 0.102, xGroq.Usage.TotalTime, 1e-9)
}

func TestGroqAdapter_StreamFinalChunkPreservesUsageAndXGroq(t *testing.T) {
	a := groqAdapter(t)

	canonical, err := a.DecodeStreamChunk([]byte(groqStreamFinalChunkWithXGroq))
	require.NoError(t, err)
	require.NotNil(t, canonical)
	require.NotNil(t, canonical.Usage)
	assert.Equal(t, 15, canonical.Usage.TotalTokens)
	require.NotNil(t, canonical.ProviderExtensions["x_groq"])

	lines, err := a.EncodeStreamChunk(canonical)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	var dataLine string
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("data: ")) {
			dataLine = string(line)
			break
		}
	}
	require.NotEmpty(t, dataLine)
	payload := strings.TrimPrefix(dataLine, "data: ")

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(payload), &parsed))
	require.NotNil(t, parsed["x_groq"])
	require.NotNil(t, parsed["usage"])

	var usage struct {
		TotalTokens int `json:"total_tokens"`
	}
	require.NoError(t, json.Unmarshal(parsed["usage"], &usage))
	assert.Equal(t, 15, usage.TotalTokens)
}

func TestGroqAdapter_CrossFormatDropsXGroq(t *testing.T) {
	out, err := NewRegistry().AdaptResponse([]byte(groqResponseWithXGroq), FormatAnthropic, FormatGroq)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "x_groq")

	var probe struct {
		Type string `json:"type"`
	}
	require.NoError(t, json.Unmarshal(out, &probe))
	assert.Equal(t, "message", probe.Type)
}

func TestGroqAdapter_CrossFormatDropsXGroqToOpenAIResponse(t *testing.T) {
	out, err := NewRegistry().AdaptResponse([]byte(groqResponseWithXGroq), FormatOpenAI, FormatGroq)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "x_groq")

	var parsed struct {
		Object  string          `json:"object"`
		Choices json.RawMessage `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(out, &parsed))
	assert.Equal(t, "chat.completion", parsed.Object)
	require.NotNil(t, parsed.Choices)
}

func TestGroqAdapter_CrossFormatDropsXGroqToOpenAIStream(t *testing.T) {
	lines, err := NewRegistry().AdaptStreamChunk([]byte(groqStreamFinalChunkWithXGroq), FormatOpenAI, FormatGroq)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	combined := ""
	for _, line := range lines {
		combined += string(line) + "\n"
	}
	assert.NotContains(t, combined, "x_groq")
	assert.Contains(t, combined, "usage")
	assert.Contains(t, combined, "data: ")
}

func TestGroqAdapter_RequestMappings(t *testing.T) {
	reg := NewRegistry()
	a, err := reg.GetAdapter(FormatGroq)
	require.NoError(t, err)

	t.Run("provider to canonical request", func(t *testing.T) {
		cr, err := a.DecodeRequest([]byte(groqChatRequest))
		require.NoError(t, err)
		assert.Equal(t, "llama-3.3-70b-versatile", cr.Model)
		require.Len(t, cr.Messages, 1)
		assert.Equal(t, "user", cr.Messages[0].Role)
	})

	t.Run("canonical to provider request", func(t *testing.T) {
		cr, err := a.DecodeRequest([]byte(groqChatRequest))
		require.NoError(t, err)

		encoded, err := a.EncodeRequest(cr)
		require.NoError(t, err)

		var parsed map[string]any
		require.NoError(t, json.Unmarshal(encoded, &parsed))
		assert.Equal(t, "llama-3.3-70b-versatile", parsed["model"])
	})

	t.Run("provider to canonical response", func(t *testing.T) {
		cr, err := a.DecodeResponse([]byte(groqResponseWithXGroq))
		require.NoError(t, err)
		require.NotNil(t, cr.ProviderExtensions["x_groq"])
		assert.Equal(t, "hello", cr.Content)
	})

	t.Run("canonical to provider response", func(t *testing.T) {
		cr, err := a.DecodeResponse([]byte(groqResponseWithXGroq))
		require.NoError(t, err)

		encoded, err := a.EncodeResponse(cr)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"x_groq"`)
	})

	t.Run("provider to canonical stream", func(t *testing.T) {
		sc, err := a.DecodeStreamChunk([]byte(groqStreamFinalChunkWithXGroq))
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.NotNil(t, sc.ProviderExtensions["x_groq"])
		require.NotNil(t, sc.Usage)
	})

	t.Run("canonical to provider stream", func(t *testing.T) {
		sc, err := a.DecodeStreamChunk([]byte(groqStreamFinalChunkWithXGroq))
		require.NoError(t, err)

		lines, err := a.EncodeStreamChunk(sc)
		require.NoError(t, err)
		combined := string(lines[0])
		for _, line := range lines[1:] {
			combined += string(line)
		}
		assert.Contains(t, combined, `"x_groq"`)
	})
}
