package adapter

// CanonicalRequest is the internal neutral representation of any AI provider
// request. Every provider adapter converts FROM its native format TO this
// struct (Decode) and FROM this struct TO its native format (Encode).
//
// Adding a new provider = implementing 2 functions. Adding a new field here
// enriches all providers at once.
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
	ID           string              `json:"id,omitempty"`
	Model        string              `json:"model,omitempty"`
	Content      string              `json:"content,omitempty"`
	Role         string              `json:"role,omitempty"`
	ToolCalls    []CanonicalToolCall `json:"tool_calls,omitempty"`
	FinishReason string              `json:"finish_reason,omitempty"` // "stop", "length", "tool_calls"
	Usage        *CanonicalUsage     `json:"usage,omitempty"`
}

// CanonicalUsage holds token counts.
type CanonicalUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	// Provider-specific cache/billing fields (pass-through).
	CacheCreationInputTokens int    `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int    `json:"cache_read_input_tokens,omitempty"`
	ServiceTier              string `json:"service_tier,omitempty"`
}

// ---------------------------------------------------------------------------
// Stream chunk types
// ---------------------------------------------------------------------------

// CanonicalStreamChunk is one piece of a streamed response.
type CanonicalStreamChunk struct {
	ID           string `json:"id,omitempty"`
	Model        string `json:"model,omitempty"`
	Role         string `json:"role,omitempty"`   // only on first chunk
	Delta        string `json:"delta,omitempty"`   // text content delta
	FinishReason string `json:"finish_reason,omitempty"`
}
