package adapter

import (
	"encoding/json"
	"strings"
)

// OpenAIAdapter converts between OpenAI chat-completion format and the
// canonical internal model.
type OpenAIAdapter struct{}

// ---------------------------------------------------------------------------
// Provider-specific typed structs
// ---------------------------------------------------------------------------

type openaiRequest struct {
	Model               string            `json:"model,omitempty"`
	Messages            []openaiMessage   `json:"messages"`
	MaxTokens           *int              `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int              `json:"max_completion_tokens,omitempty"`
	Temperature         *float64          `json:"temperature,omitempty"`
	TopP                *float64          `json:"top_p,omitempty"`
	TopK                *int              `json:"top_k,omitempty"`
	Stream              *bool             `json:"stream,omitempty"`
	Stop                json.RawMessage   `json:"stop,omitempty"` // string or []string
	ResponseFormat      *openaiRespFormat `json:"response_format,omitempty"`
	Tools               []openaiTool      `json:"tools,omitempty"`
	ToolChoice          json.RawMessage   `json:"tool_choice,omitempty"` // string or object
}

type openaiMessage struct {
	Role       string           `json:"role"`
	Content    json.RawMessage  `json:"content,omitempty"` // string or []contentPart
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openaiTool struct {
	Type     string         `json:"type"`
	Function openaiFunction `json:"function"`
}

type openaiFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

type openaiToolCall struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function openaiCallFunc `json:"function"`
}

type openaiCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openaiRespFormat struct {
	Type string `json:"type"`
}

type openaiResponse struct {
	ID        string           `json:"id"`
	Object    string           `json:"object"`
	Model     string           `json:"model"`
	Choices   []openaiChoice   `json:"choices"`
	Usage     *openaiUsage     `json:"usage,omitempty"`
	Reasoning *openAIReasoning `json:"reasoning,omitempty"`
}

type openAIReasoning struct {
	Effort  json.RawMessage `json:"effort,omitempty"`
	Summary *string         `json:"summary"`
}

type openaiChoice struct {
	Index        int            `json:"index"`
	Message      *openaiMessage `json:"message,omitempty"`
	FinishReason string         `json:"finish_reason"`
}

type openaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openaiStreamChunk struct {
	ID      string               `json:"id,omitempty"`
	Object  string               `json:"object"`
	Model   string               `json:"model,omitempty"`
	Choices []openaiStreamChoice `json:"choices"`
}

type openaiStreamChoice struct {
	Index        int               `json:"index"`
	Delta        openaiStreamDelta `json:"delta"`
	FinishReason *string           `json:"finish_reason,omitempty"`
}

type openaiStreamDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// ---------------------------------------------------------------------------
// Request: Decode (OpenAI → Canonical)
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req openaiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	cr := &CanonicalRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
	}

	// Stream
	if req.Stream != nil {
		cr.Stream = *req.Stream
	}

	// max_tokens / max_completion_tokens
	if req.MaxCompletionTokens != nil {
		cr.MaxTokens = *req.MaxCompletionTokens
	} else if req.MaxTokens != nil {
		cr.MaxTokens = *req.MaxTokens
	}

	// stop
	cr.Stop = decodeStopField(req.Stop)

	// response_format
	if req.ResponseFormat != nil {
		cr.ResponseFormat = &CanonicalRespFormat{Type: req.ResponseFormat.Type}
	}

	// messages
	for _, m := range req.Messages {
		content := contentToString(m.Content)

		cm := CanonicalMessage{
			Role:       m.Role,
			Content:    content,
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			cm.ToolCalls = append(cm.ToolCalls, CanonicalToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
		}

		if m.Role == "system" {
			if cr.System != "" {
				cr.System += "\n"
			}
			cr.System += content
		} else {
			cr.Messages = append(cr.Messages, cm)
		}
	}

	// tools
	for _, t := range req.Tools {
		cr.Tools = append(cr.Tools, CanonicalTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Schema:      t.Function.Parameters,
		})
	}

	// tool_choice
	cr.ToolChoice = decodeOpenAIToolChoice(req.ToolChoice)

	return cr, nil
}

// ---------------------------------------------------------------------------
// Request: Encode (Canonical → OpenAI)
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := openaiRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}

	// Stream
	if req.Stream {
		out.Stream = boolPtr(true)
	}

	// max_tokens
	if req.MaxTokens > 0 {
		out.MaxTokens = &req.MaxTokens
	}

	// stop
	if len(req.Stop) > 0 {
		out.Stop, _ = json.Marshal(req.Stop)
	}

	// response_format
	if req.ResponseFormat != nil {
		out.ResponseFormat = &openaiRespFormat{Type: req.ResponseFormat.Type}
	}

	// messages: system first, then the rest
	if req.System != "" {
		out.Messages = append(out.Messages, openaiMessage{
			Role:    "system",
			Content: stringToContent(req.System),
		})
	}
	for _, m := range req.Messages {
		msg := openaiMessage{
			Role:       m.Role,
			Content:    stringToContent(m.Content),
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			msg.ToolCalls = append(msg.ToolCalls, openaiToolCall{
				ID:   tc.ID,
				Type: "function",
				Function: openaiCallFunc{
					Name:      tc.Name,
					Arguments: tc.Arguments,
				},
			})
		}
		out.Messages = append(out.Messages, msg)
	}

	// tools
	for _, t := range req.Tools {
		out.Tools = append(out.Tools, openaiTool{
			Type: "function",
			Function: openaiFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Schema,
			},
		})
	}

	// tool_choice
	if req.ToolChoice != nil {
		out.ToolChoice = encodeOpenAIToolChoice(req.ToolChoice)
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Response: Decode (OpenAI response → Canonical)
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp openaiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	cr := &CanonicalResponse{
		ID:    resp.ID,
		Model: resp.Model,
		Role:  "assistant",
	}

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		if choice.Message != nil {
			cr.Content = contentToString(choice.Message.Content)
			for _, tc := range choice.Message.ToolCalls {
				cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
					ID:        tc.ID,
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				})
			}
		}
		cr.FinishReason = choice.FinishReason
	}

	if resp.Usage != nil {
		cr.Usage = &CanonicalUsage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}

	if resp.Reasoning != nil {
		cr.Reasoning = &CanonicalReasoning{
			Effort:       []byte(resp.Reasoning.Effort),
			Summary:      resp.Reasoning.Summary,
			ThinkingText: "",
		}
		if resp.Reasoning.Summary != nil {
			cr.Reasoning.ThinkingText = *resp.Reasoning.Summary
		}
	}

	return cr, nil
}

// ---------------------------------------------------------------------------
// Response: Encode (Canonical → OpenAI response)
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	msg := openaiMessage{
		Role:    "assistant",
		Content: stringToContent(resp.Content),
	}
	for _, tc := range resp.ToolCalls {
		msg.ToolCalls = append(msg.ToolCalls, openaiToolCall{
			ID:   tc.ID,
			Type: "function",
			Function: openaiCallFunc{
				Name:      tc.Name,
				Arguments: tc.Arguments,
			},
		})
	}

	out := openaiResponse{
		ID:     resp.ID,
		Object: "chat.completion",
		Model:  resp.Model,
		Choices: []openaiChoice{{
			Index:        0,
			Message:      &msg,
			FinishReason: resp.FinishReason,
		}},
	}

	if resp.Usage != nil {
		out.Usage = &openaiUsage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}

	if resp.Reasoning != nil {
		summary := resp.Reasoning.Summary
		if summary == nil && resp.Reasoning.ThinkingText != "" {
			s := resp.Reasoning.ThinkingText
			summary = &s
		}
		out.Reasoning = &openAIReasoning{
			Effort:  json.RawMessage(resp.Reasoning.Effort),
			Summary: summary,
		}
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Stream: Decode (OpenAI chunk → Canonical)
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var raw openaiStreamChunk
	if err := json.Unmarshal(chunk, &raw); err != nil {
		return nil, nil // skip non-JSON
	}

	if len(raw.Choices) == 0 {
		return nil, nil
	}

	choice := raw.Choices[0]
	sc := &CanonicalStreamChunk{
		ID:    raw.ID,
		Model: raw.Model,
		Role:  choice.Delta.Role,
		Delta: choice.Delta.Content,
	}
	if choice.FinishReason != nil {
		sc.FinishReason = *choice.FinishReason
	}

	// Skip empty chunks.
	if sc.Delta == "" && sc.Role == "" && sc.FinishReason == "" {
		return nil, nil
	}

	return sc, nil
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → OpenAI chunk)
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	delta := openaiStreamDelta{
		Role:    chunk.Role,
		Content: chunk.Delta,
	}

	choice := openaiStreamChoice{
		Index: 0,
		Delta: delta,
	}
	if chunk.FinishReason != "" {
		fr := chunk.FinishReason
		choice.FinishReason = &fr
	}

	out := openaiStreamChunk{
		ID:      chunk.ID,
		Object:  "chat.completion.chunk",
		Model:   chunk.Model,
		Choices: []openaiStreamChoice{choice},
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return SSEData(data), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func decodeOpenAIToolChoice(raw json.RawMessage) *CanonicalToolChoice {
	if raw == nil {
		return nil
	}
	// Try string first ("auto", "none", "required").
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return &CanonicalToolChoice{Type: s}
	}
	// Try object {"type":"function","function":{"name":"..."}}
	var obj struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Function.Name != "" {
		return &CanonicalToolChoice{Type: "tool", Name: obj.Function.Name}
	}
	return nil
}

func encodeOpenAIToolChoice(tc *CanonicalToolChoice) json.RawMessage {
	switch tc.Type {
	case "auto", "none", "required":
		b, _ := json.Marshal(tc.Type)
		return b
	case "any":
		b, _ := json.Marshal("required")
		return b
	case "tool":
		b, _ := json.Marshal(map[string]interface{}{
			"type":     "function",
			"function": map[string]string{"name": tc.Name},
		})
		return b
	default:
		b, _ := json.Marshal(tc.Type)
		return b
	}
}

// contentToString extracts text from a JSON content field that may be a plain
// string or an array of content-part objects.
func contentToString(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	// Try plain string.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	// Try array of content parts.
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var texts []string
		for _, p := range parts {
			if p.Text != "" {
				texts = append(texts, p.Text)
			}
		}
		return strings.Join(texts, "\n")
	}
	return string(raw)
}

// stringToContent marshals a plain string into json.RawMessage.
func stringToContent(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

// decodeStopField decodes the OpenAI "stop" field which can be a string or
// an array of strings.
func decodeStopField(raw json.RawMessage) []string {
	if raw == nil {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	return nil
}

func boolPtr(b bool) *bool { return &b }
