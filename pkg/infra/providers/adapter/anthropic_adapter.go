package adapter

import "encoding/json"

// AnthropicAdapter converts between Anthropic Messages API format and the
// canonical internal model.
type AnthropicAdapter struct{}

// ---------------------------------------------------------------------------
// Provider-specific typed structs
// ---------------------------------------------------------------------------

type anthropicRequest struct {
	Model       string                 `json:"model,omitempty"`
	System      string                 `json:"system,omitempty"`
	Messages    []anthropicMessage     `json:"messages"`
	MaxTokens   int                    `json:"max_tokens"`
	Temperature *float64               `json:"temperature,omitempty"`
	TopP        *float64               `json:"top_p,omitempty"`
	TopK        *int                   `json:"top_k,omitempty"`
	Stream      *bool                  `json:"stream,omitempty"`
	StopSeqs    []string               `json:"stop_sequences,omitempty"`
	Tools       []anthropicTool        `json:"tools,omitempty"`
	ToolChoice  *anthropicToolChoice   `json:"tool_choice,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string or []anthropicContentBlock
}

type anthropicTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema,omitempty"`
}

type anthropicToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

type anthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Model        string                  `json:"model"`
	Content      []anthropicContentBlock `json:"content"`
	StopReason   string                  `json:"stop_reason"`
	StopSequence *string                 `json:"stop_sequence"` // null or the matched stop sequence
	Usage        *anthropicUsage         `json:"usage,omitempty"`
}

type anthropicContentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type anthropicUsage struct {
	InputTokens              int                     `json:"input_tokens"`
	OutputTokens             int                     `json:"output_tokens"`
	CacheCreationInputTokens int                     `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int                     `json:"cache_read_input_tokens,omitempty"`
	CacheCreation            *anthropicCacheCreation `json:"cache_creation,omitempty"`
	ServiceTier              string                  `json:"service_tier,omitempty"`
	InferenceGeo             string                  `json:"inference_geo,omitempty"`
}

type anthropicCacheCreation struct {
	Ephemeral5mInputTokens int `json:"ephemeral_5m_input_tokens,omitempty"`
	Ephemeral1hInputTokens int `json:"ephemeral_1h_input_tokens,omitempty"`
}

// Stream event types

type anthropicStreamEvent struct {
	Type    string          `json:"type"`
	Message json.RawMessage `json:"message,omitempty"`
	Delta   json.RawMessage `json:"delta,omitempty"`
	Index   int             `json:"index,omitempty"`
}

type anthropicMessageStart struct {
	ID    string `json:"id"`
	Model string `json:"model"`
	Role  string `json:"role"`
}

type anthropicDelta struct {
	Type       string `json:"type,omitempty"`
	Text       string `json:"text,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Request: Decode (Anthropic → Canonical)
// ---------------------------------------------------------------------------

func (a *AnthropicAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	cr := &CanonicalRequest{
		Model:       req.Model,
		System:      req.System,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
		Stop:        req.StopSeqs,
		Metadata:    req.Metadata,
	}

	if req.Stream != nil {
		cr.Stream = *req.Stream
	}

	// Messages
	for _, m := range req.Messages {
		cr.Messages = append(cr.Messages, CanonicalMessage{
			Role:    m.Role,
			Content: contentToString(m.Content),
		})
	}

	// Tools
	for _, t := range req.Tools {
		cr.Tools = append(cr.Tools, CanonicalTool{
			Name:        t.Name,
			Description: t.Description,
			Schema:      t.InputSchema,
		})
	}

	// ToolChoice
	if req.ToolChoice != nil {
		cr.ToolChoice = &CanonicalToolChoice{
			Type: req.ToolChoice.Type,
			Name: req.ToolChoice.Name,
		}
	}

	return cr, nil
}

// ---------------------------------------------------------------------------
// Request: Encode (Canonical → Anthropic)
// ---------------------------------------------------------------------------

func (a *AnthropicAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := anthropicRequest{
		Model:       req.Model,
		System:      req.System,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
		StopSeqs:    req.Stop,
		Metadata:    req.Metadata,
	}

	if req.Stream {
		out.Stream = boolPtr(true)
	}

	// max_tokens (required by Anthropic)
	if req.MaxTokens > 0 {
		out.MaxTokens = req.MaxTokens
	} else {
		out.MaxTokens = 4096
	}

	// Messages
	for _, m := range req.Messages {
		out.Messages = append(out.Messages, anthropicMessage{
			Role:    m.Role,
			Content: stringToContent(m.Content),
		})
	}

	// Tools
	for _, t := range req.Tools {
		out.Tools = append(out.Tools, anthropicTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.Schema,
		})
	}

	// ToolChoice
	if req.ToolChoice != nil {
		tc := &anthropicToolChoice{
			Type: req.ToolChoice.Type,
			Name: req.ToolChoice.Name,
		}
		// Map "required" (OpenAI) → "any" (Anthropic)
		if tc.Type == "required" {
			tc.Type = "any"
		}
		out.ToolChoice = tc
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Response: Decode (Anthropic response → Canonical)
// ---------------------------------------------------------------------------

func (a *AnthropicAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	cr := &CanonicalResponse{
		ID:    resp.ID,
		Model: resp.Model,
		Role:  "assistant",
	}

	// Content blocks
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			cr.Content += block.Text
		case "tool_use":
			cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
				ID:        block.ID,
				Name:      block.Name,
				Arguments: string(block.Input),
			})
		}
	}

	// stop_reason → finish_reason
	switch resp.StopReason {
	case "end_turn":
		cr.FinishReason = "stop"
	case "max_tokens":
		cr.FinishReason = "length"
	case "tool_use":
		cr.FinishReason = "tool_calls"
	default:
		cr.FinishReason = resp.StopReason
	}

	// Usage
	if resp.Usage != nil {
		cr.Usage = &CanonicalUsage{
			PromptTokens:             resp.Usage.InputTokens,
			CompletionTokens:         resp.Usage.OutputTokens,
			TotalTokens:              resp.Usage.InputTokens + resp.Usage.OutputTokens,
			CacheCreationInputTokens: resp.Usage.CacheCreationInputTokens,
			CacheReadInputTokens:     resp.Usage.CacheReadInputTokens,
			ServiceTier:              resp.Usage.ServiceTier,
		}
	}

	return cr, nil
}

// ---------------------------------------------------------------------------
// Response: Encode (Canonical → Anthropic response)
// ---------------------------------------------------------------------------

func (a *AnthropicAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	var content []anthropicContentBlock
	if resp.Content != "" {
		content = append(content, anthropicContentBlock{
			Type: "text",
			Text: resp.Content,
		})
	}
	for _, tc := range resp.ToolCalls {
		content = append(content, anthropicContentBlock{
			Type:  "tool_use",
			ID:    tc.ID,
			Name:  tc.Name,
			Input: json.RawMessage(tc.Arguments),
		})
	}

	stopReason := "end_turn"
	switch resp.FinishReason {
	case "stop":
		stopReason = "end_turn"
	case "length":
		stopReason = "max_tokens"
	case "tool_calls":
		stopReason = "tool_use"
	}

	out := anthropicResponse{
		ID:         resp.ID,
		Type:       "message",
		Role:       "assistant",
		Model:      resp.Model,
		Content:    content,
		StopReason: stopReason,
	}

	if resp.Usage != nil {
		out.Usage = &anthropicUsage{
			InputTokens:              resp.Usage.PromptTokens,
			OutputTokens:             resp.Usage.CompletionTokens,
			CacheCreationInputTokens: resp.Usage.CacheCreationInputTokens,
			CacheReadInputTokens:     resp.Usage.CacheReadInputTokens,
			ServiceTier:              resp.Usage.ServiceTier,
		}
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Stream: Decode (Anthropic SSE event → Canonical)
// ---------------------------------------------------------------------------

func (a *AnthropicAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var event anthropicStreamEvent
	if err := json.Unmarshal(chunk, &event); err != nil {
		return nil, nil // skip non-JSON
	}

	switch event.Type {
	case "content_block_delta":
		var delta anthropicDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil {
			return nil, nil
		}
		if delta.Type == "text_delta" && delta.Text != "" {
			return &CanonicalStreamChunk{Delta: delta.Text}, nil
		}
		return nil, nil

	case "message_start":
		var msg anthropicMessageStart
		if err := json.Unmarshal(event.Message, &msg); err != nil {
			return nil, nil
		}
		return &CanonicalStreamChunk{
			ID:    msg.ID,
			Model: msg.Model,
			Role:  "assistant",
		}, nil

	case "message_delta":
		var delta anthropicDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil {
			return nil, nil
		}
		if delta.StopReason != "" {
			fr := delta.StopReason
			switch fr {
			case "end_turn":
				fr = "stop"
			case "max_tokens":
				fr = "length"
			case "tool_use":
				fr = "tool_calls"
			}
			return &CanonicalStreamChunk{FinishReason: fr}, nil
		}
		return nil, nil

	default:
		return nil, nil // skip ping, message_stop, content_block_start, etc.
	}
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → Anthropic SSE event)
// ---------------------------------------------------------------------------

func (a *AnthropicAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([]byte, error) {
	if chunk.Role != "" {
		msg := anthropicMessageStart{
			ID:    chunk.ID,
			Model: chunk.Model,
			Role:  "assistant",
		}
		msgBytes, _ := json.Marshal(msg)
		out := anthropicStreamEvent{
			Type:    "message_start",
			Message: msgBytes,
		}
		return json.Marshal(out)
	}

	if chunk.Delta != "" {
		delta := anthropicDelta{Type: "text_delta", Text: chunk.Delta}
		deltaBytes, _ := json.Marshal(delta)
		out := anthropicStreamEvent{
			Type:  "content_block_delta",
			Index: 0,
			Delta: deltaBytes,
		}
		return json.Marshal(out)
	}

	if chunk.FinishReason != "" {
		sr := "end_turn"
		switch chunk.FinishReason {
		case "length":
			sr = "max_tokens"
		case "tool_calls":
			sr = "tool_use"
		}
		delta := anthropicDelta{StopReason: sr}
		deltaBytes, _ := json.Marshal(delta)
		out := anthropicStreamEvent{
			Type:  "message_delta",
			Delta: deltaBytes,
		}
		return json.Marshal(out)
	}

	return nil, nil
}
