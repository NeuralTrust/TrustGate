package adapter

import (
	"encoding/json"
	"fmt"
	"strings"
)

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

// anthropicTool is used when decoding requests (supports flat and type+custom).
type anthropicTool struct {
	Type        string                 `json:"type,omitempty"`
	Custom      *anthropicToolCustom    `json:"custom,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema,omitempty"`
}

// anthropicToolCustom is the nested shape required by the API for custom tools (encode).
type anthropicToolCustom struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema"`
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
	Type       string          `json:"type"`
	Text       string          `json:"text,omitempty"`
	Thinking   string          `json:"thinking,omitempty"`   // extended thinking block content
	Signature  string          `json:"signature,omitempty"` // thinking block signature
	ID         string          `json:"id,omitempty"`
	Name       string          `json:"name,omitempty"`
	Input      json.RawMessage `json:"input,omitempty"`
	ToolUseID  string          `json:"tool_use_id,omitempty"` // user message: tool_result block
	BlockContent string        `json:"content,omitempty"`     // user message: tool_result block content
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

// Stream event types — Decode (incoming)

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

// Stream event types — Encode (outgoing, faithful to Anthropic API)

type anthropicSSEMessageStartPayload struct {
	Type    string                  `json:"type"`
	Message anthropicSSEMessageInfo `json:"message"`
}

type anthropicSSEMessageInfo struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Role         string            `json:"role"`
	Content      []interface{}     `json:"content"`
	Model        string            `json:"model"`
	StopReason   *string           `json:"stop_reason"`
	StopSequence *string           `json:"stop_sequence"`
	Usage        anthropicSSEUsage `json:"usage"`
}

type anthropicSSEUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicSSEContentBlockStart struct {
	Type         string                   `json:"type"`
	Index        int                      `json:"index"`
	ContentBlock anthropicSSEContentBlock `json:"content_block"`
}

type anthropicSSEContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicSSEContentBlockDelta struct {
	Type  string         `json:"type"`
	Index int            `json:"index"`
	Delta anthropicDelta `json:"delta"`
}

type anthropicSSEContentBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type anthropicSSEMessageDelta struct {
	Type  string                       `json:"type"`
	Delta anthropicSSEMessageDeltaBody `json:"delta"`
	Usage anthropicSSEUsage            `json:"usage"`
}

type anthropicSSEMessageDeltaBody struct {
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
}

type anthropicSSESimple struct {
	Type string `json:"type"`
}

// decodeAnthropicMessageContent turns one Anthropic message into one or more canonical
// messages. User messages with content blocks of type "tool_result" become separate
// canonical messages with Role="tool" so the target (e.g. OpenAI) receives proper
// tool result messages; without this, tool results are lost and the model never sees
// them (causing repeated tool calls / loops).
func decodeAnthropicMessageContent(role string, content json.RawMessage) []CanonicalMessage {
	if content == nil {
		return []CanonicalMessage{{Role: role, Content: ""}}
	}
	// Plain string
	var s string
	if json.Unmarshal(content, &s) == nil {
		return []CanonicalMessage{{Role: role, Content: s}}
	}
	// Array of content blocks
	var blocks []anthropicContentBlock
	if json.Unmarshal(content, &blocks) != nil {
		return []CanonicalMessage{{Role: role, Content: contentToString(content)}}
	}
	var out []CanonicalMessage
	switch role {
	case "user":
		var textParts []string
		var toolMessages []CanonicalMessage
		for _, b := range blocks {
			switch b.Type {
			case "tool_result":
				toolMessages = append(toolMessages, CanonicalMessage{
					Role:       "tool",
					ToolCallID: b.ToolUseID,
					Content:    b.BlockContent,
				})
			case "text":
				textParts = append(textParts, b.Text)
			}
		}
		// OpenAI order: user (if any text) then tool messages
		if len(textParts) > 0 {
			out = append(out, CanonicalMessage{Role: "user", Content: strings.Join(textParts, "\n")})
		}
		out = append(out, toolMessages...)
	case "assistant":
		var textParts []string
		var toolCalls []CanonicalToolCall
		for _, b := range blocks {
			switch b.Type {
			case "text":
				textParts = append(textParts, b.Text)
			case "tool_use":
				toolCalls = append(toolCalls, CanonicalToolCall{
					ID:        b.ID,
					Name:      b.Name,
					Arguments: string(b.Input),
				})
			}
		}
		out = append(out, CanonicalMessage{
			Role:      "assistant",
			Content:   strings.Join(textParts, "\n"),
			ToolCalls: toolCalls,
		})
	default:
		out = append(out, CanonicalMessage{
			Role:    role,
			Content: contentToString(content),
		})
	}
	return out
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

	// Messages: decode content blocks so tool_result (user) and tool_use (assistant) are preserved
	for _, m := range req.Messages {
		cr.Messages = append(cr.Messages, decodeAnthropicMessageContent(m.Role, m.Content)...)
	}

	// Tools (support both flat and type+custom shapes)
	for _, t := range req.Tools {
		name, desc, schema := t.Name, t.Description, t.InputSchema
		if t.Custom != nil {
			name, desc, schema = t.Custom.Name, t.Custom.Description, t.Custom.InputSchema
		}
		cr.Tools = append(cr.Tools, CanonicalTool{
			Name:        name,
			Description: desc,
			Schema:      schema,
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

	// Messages: collapse canonical Role="tool" messages into one Anthropic "user" message with tool_result blocks
	for i := 0; i < len(req.Messages); i++ {
		m := req.Messages[i]
		if m.Role == "tool" {
			var toolResultBlocks []anthropicContentBlock
			for i < len(req.Messages) && req.Messages[i].Role == "tool" {
				toolResultBlocks = append(toolResultBlocks, anthropicContentBlock{
					Type:         "tool_result",
					ToolUseID:    req.Messages[i].ToolCallID,
					BlockContent: req.Messages[i].Content,
				})
				i++
			}
			i-- // loop will i++ again
			raw, _ := json.Marshal(toolResultBlocks)
			out.Messages = append(out.Messages, anthropicMessage{
				Role:    "user",
				Content: raw,
			})
			continue
		}
		// Assistant messages with tool_calls must send content as array of blocks (text + tool_use)
		// so Anthropic can match tool_result blocks to the previous message's tool_use.
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			var blocks []anthropicContentBlock
			if m.Content != "" {
				blocks = append(blocks, anthropicContentBlock{Type: "text", Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				blocks = append(blocks, anthropicContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Name,
					Input: json.RawMessage(tc.Arguments),
				})
			}
			raw, _ := json.Marshal(blocks)
			out.Messages = append(out.Messages, anthropicMessage{
				Role:    "assistant",
				Content: raw,
			})
			continue
		}
		out.Messages = append(out.Messages, anthropicMessage{
			Role:    m.Role,
			Content: stringToContent(m.Content),
		})
	}

	// Tools: use flat format (name, input_schema, description at top level) — matches working Anthropic requests
	for i, t := range req.Tools {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = fmt.Sprintf("tool_%d", i)
		}
		schema := t.Schema
		if len(schema) == 0 {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		out.Tools = append(out.Tools, anthropicTool{
			Name:        name,
			Description: t.Description,
			InputSchema: schema,
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

	// Content blocks (including extended thinking)
	var thinkingBlocks []string
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			cr.Content += block.Text
		case "thinking":
			if block.Thinking != "" {
				thinkingBlocks = append(thinkingBlocks, block.Thinking)
			}
		case "tool_use":
			cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
				ID:        block.ID,
				Name:      block.Name,
				Arguments: string(block.Input),
			})
		}
	}
	if len(thinkingBlocks) > 0 {
		cr.Reasoning = &CanonicalReasoning{
			ThinkingText: strings.Join(thinkingBlocks, "\n\n"),
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
	// Prepend thinking blocks if present (Anthropic extended thinking)
	if resp.Reasoning != nil && resp.Reasoning.ThinkingText != "" {
		content = append(content, anthropicContentBlock{
			Type:     "thinking",
			Thinking: resp.Reasoning.ThinkingText,
		})
	}
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
//
// Produces a faithful Anthropic SSE stream with event: lines, including the
// structural events that the Anthropic API emits (content_block_start,
// content_block_stop, message_stop, etc.).
// ---------------------------------------------------------------------------

func (a *AnthropicAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	// --- message_start → also emit content_block_start -----------------------
	if chunk.Role != "" {
		var lines [][]byte

		// 1. event: message_start
		msgStart := anthropicSSEMessageStartPayload{
			Type: "message_start",
			Message: anthropicSSEMessageInfo{
				ID:      chunk.ID,
				Type:    "message",
				Role:    "assistant",
				Content: []interface{}{},
				Model:   chunk.Model,
				Usage:   anthropicSSEUsage{InputTokens: 0, OutputTokens: 0},
			},
		}
		data, _ := json.Marshal(msgStart)
		lines = append(lines, SSEEvent("message_start", data)...)

		// 2. event: content_block_start (index 0, text block)
		cbStart := anthropicSSEContentBlockStart{
			Type:  "content_block_start",
			Index: 0,
			ContentBlock: anthropicSSEContentBlock{
				Type: "text",
				Text: "",
			},
		}
		data, _ = json.Marshal(cbStart)
		lines = append(lines, SSEEvent("content_block_start", data)...)

		return lines, nil
	}

	// --- content_block_delta -------------------------------------------------
	if chunk.Delta != "" {
		cbDelta := anthropicSSEContentBlockDelta{
			Type:  "content_block_delta",
			Index: 0,
			Delta: anthropicDelta{Type: "text_delta", Text: chunk.Delta},
		}
		data, _ := json.Marshal(cbDelta)
		return SSEEvent("content_block_delta", data), nil
	}

	// --- finish_reason → content_block_stop + message_delta + message_stop ----
	if chunk.FinishReason != "" {
		sr := "end_turn"
		switch chunk.FinishReason {
		case "length":
			sr = "max_tokens"
		case "tool_calls":
			sr = "tool_use"
		}

		var lines [][]byte

		// 1. event: content_block_stop
		cbStop := anthropicSSEContentBlockStop{Type: "content_block_stop", Index: 0}
		data, _ := json.Marshal(cbStop)
		lines = append(lines, SSEEvent("content_block_stop", data)...)

		// 2. event: message_delta
		msgDelta := anthropicSSEMessageDelta{
			Type: "message_delta",
			Delta: anthropicSSEMessageDeltaBody{
				StopReason: sr,
			},
			Usage: anthropicSSEUsage{OutputTokens: 0},
		}
		data, _ = json.Marshal(msgDelta)
		lines = append(lines, SSEEvent("message_delta", data)...)

		// 3. event: message_stop
		msgStop := anthropicSSESimple{Type: "message_stop"}
		data, _ = json.Marshal(msgStop)
		lines = append(lines, SSEEvent("message_stop", data)...)

		return lines, nil
	}

	return nil, nil
}
