package adapter

import "encoding/json"

// MetadataUsageKey is the RequestContext.Metadata key under which the streaming
// usage observer records the latest *CanonicalUsage. The metrics pipeline reads
// it back from the same key when building the exchange.
const MetadataUsageKey = "usage"

// CanonicalRequest is the internal neutral representation of any AI provider
type CanonicalRequest struct {
	Model          string                 `json:"model,omitempty"`
	System         string                 `json:"system,omitempty"`
	Messages       []CanonicalMessage     `json:"messages,omitempty"`
	Tools          []CanonicalTool        `json:"tools,omitempty"`
	ToolChoice     *CanonicalToolChoice   `json:"tool_choice,omitempty"`
	MaxTokens      int                    `json:"max_tokens,omitempty"`
	Temperature    *float64               `json:"temperature,omitempty"`
	TopP           *float64               `json:"top_p,omitempty"`
	TopK           *int                   `json:"top_k,omitempty"`
	Stop           []string               `json:"stop,omitempty"`
	Stream         bool                   `json:"stream,omitempty"`
	ResponseFormat *CanonicalRespFormat   `json:"response_format,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// CanonicalMessage represents a single turn in the conversation.
type CanonicalMessage struct {
	Role       string              `json:"role"`
	Content    string              `json:"content"`
	ToolCalls  []CanonicalToolCall `json:"tool_calls,omitempty"`
	ToolCallID string              `json:"tool_call_id,omitempty"`
}

// CanonicalTool represents a tool/function the model can call.
type CanonicalTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
}

// CanonicalToolChoice controls how the model selects tools.
type CanonicalToolChoice struct {
	// Type: "auto", "none", "any", "tool"
	Type string `json:"type"`
	// Name is only set when Type == "tool"
	Name string `json:"name,omitempty"`
}

// CanonicalToolCall represents a tool invocation by the model.
type CanonicalToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // raw JSON string
}

// CanonicalRespFormat controls the response format.
type CanonicalRespFormat struct {
	Type string `json:"type"` // "json_object", "text"
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// CanonicalResponse is the internal neutral representation of a provider
// response.
type CanonicalResponse struct {
	ID                 string                     `json:"id,omitempty"`
	Model              string                     `json:"model,omitempty"`
	Content            string                     `json:"content,omitempty"`
	Role               string                     `json:"role,omitempty"`
	ToolCalls          []CanonicalToolCall        `json:"tool_calls,omitempty"`
	FinishReason       string                     `json:"finish_reason,omitempty"` // "stop", "length", "tool_calls"
	Usage              *CanonicalUsage            `json:"usage,omitempty"`
	Reasoning          *CanonicalReasoning        `json:"reasoning,omitempty"` // e.g. OpenAI reasoning / thinking
	ProviderExtensions map[string]json.RawMessage `json:"provider_extensions,omitempty"`
}

// CanonicalReasoning holds optional reasoning/thinking metadata from the model.
// OpenAI uses Effort/Summary; Anthropic/Gemini use ThinkingText (raw thinking content).
type CanonicalReasoning struct {
	Effort       []byte  `json:"effort,omitempty"`        // OpenAI: provider-specific (e.g. JSON)
	Summary      *string `json:"summary,omitempty"`       // OpenAI: summary
	ThinkingText string  `json:"thinking_text,omitempty"` // Anthropic/Gemini: raw thinking blocks concatenated
}

// CanonicalUsage holds token counts in a provider-neutral split: Input / Output / Total.
// The three buckets are the canonical view; sub-counts are optional refinements
// of InputTokens / OutputTokens (NOT subtracted from the totals). The
// nil-on-absence and total-synthesis contracts live in newCanonicalUsage.
type CanonicalUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
	// Provider-specific cache/billing fields (pass-through).
	CacheCreationInputTokens int    `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int    `json:"cache_read_input_tokens,omitempty"`
	ServiceTier              string `json:"service_tier,omitempty"`
	CachedInputTokens        int    `json:"cached_input_tokens,omitempty"`     // sub-count of InputTokens
	ReasoningOutputTokens    int    `json:"reasoning_output_tokens,omitempty"` // sub-count of OutputTokens
	ToolUseInputTokens       int    `json:"tool_use_input_tokens,omitempty"`   // sub-count of InputTokens
}

// newCanonicalUsage returns the canonical usage view, or nil when no tokens are
// reported. When the provider does not emit a total, it is synthesized as in+out.
//
// Adapters MUST funnel their wire-struct decode through this factory so the
// "nil-on-absence" contract on CanonicalUsage is enforced in code, not prose.
func newCanonicalUsage(in, out, total int) *CanonicalUsage {
	if in == 0 && out == 0 && total == 0 {
		return nil
	}
	if total == 0 {
		total = in + out
	}
	return &CanonicalUsage{
		InputTokens:  in,
		OutputTokens: out,
		TotalTokens:  total,
	}
}

// ---------------------------------------------------------------------------
// Stream chunk types
// ---------------------------------------------------------------------------

// StreamToolCallDelta is one tool-call delta in a streamed response (OpenAI
// streams tool_calls with incremental arguments; Anthropic uses input_json_delta).
type StreamToolCallDelta struct {
	Index          int    `json:"index"`
	ID             string `json:"id,omitempty"`
	Name           string `json:"name,omitempty"`
	ArgumentsDelta string `json:"arguments_delta,omitempty"` // incremental piece
}

// CanonicalStreamChunk is one piece of a streamed response.
type CanonicalStreamChunk struct {
	ID                 string                     `json:"id,omitempty"`
	Model              string                     `json:"model,omitempty"`
	Role               string                     `json:"role,omitempty"`  // only on first chunk
	Delta              string                     `json:"delta,omitempty"` // text content delta
	FinishReason       string                     `json:"finish_reason,omitempty"`
	ToolCallDeltas     []StreamToolCallDelta      `json:"tool_call_deltas,omitempty"`
	Usage              *CanonicalUsage            `json:"usage,omitempty"` // present in the final chunk of some providers
	ProviderExtensions map[string]json.RawMessage `json:"provider_extensions,omitempty"`
}
