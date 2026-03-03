package adapter

import "encoding/json"

// ---------------------------------------------------------------------------
// Chat Completions API typed structs
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
	Usage   *openaiUsage         `json:"usage,omitempty"`
}

type openaiStreamChoice struct {
	Index        int               `json:"index"`
	Delta        openaiStreamDelta `json:"delta"`
	FinishReason *string           `json:"finish_reason,omitempty"`
}

type openaiStreamDelta struct {
	Role      string                 `json:"role,omitempty"`
	Content   string                 `json:"content,omitempty"`
	ToolCalls []openaiStreamToolCall `json:"tool_calls,omitempty"`
}

type openaiStreamToolCall struct {
	Index    int                    `json:"index"`
	ID       string                 `json:"id,omitempty"`
	Type     string                 `json:"type,omitempty"`
	Function openaiStreamToolCallFn `json:"function,omitempty"`
}

type openaiStreamToolCallFn struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// ---------------------------------------------------------------------------
// Request: Decode (Chat Completions → Canonical)
// ---------------------------------------------------------------------------

func decodeCompletionsRequest(body []byte) (*CanonicalRequest, error) {
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

	if req.Stream != nil {
		cr.Stream = *req.Stream
	}

	if req.MaxCompletionTokens != nil {
		cr.MaxTokens = *req.MaxCompletionTokens
	} else if req.MaxTokens != nil {
		cr.MaxTokens = *req.MaxTokens
	}

	cr.Stop = decodeStopField(req.Stop)

	if req.ResponseFormat != nil {
		cr.ResponseFormat = &CanonicalRespFormat{Type: req.ResponseFormat.Type}
	}

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

	for _, t := range req.Tools {
		cr.Tools = append(cr.Tools, CanonicalTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Schema:      t.Function.Parameters,
		})
	}

	cr.ToolChoice = decodeOpenAIToolChoice(req.ToolChoice)

	return cr, nil
}

// ---------------------------------------------------------------------------
// Request: Encode (Canonical → Chat Completions)
// ---------------------------------------------------------------------------

func encodeCompletionsRequest(req *CanonicalRequest) ([]byte, error) {
	out := openaiRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}

	if req.Stream {
		out.Stream = boolPtr(true)
	}

	if req.MaxTokens > 0 {
		out.MaxTokens = &req.MaxTokens
	}

	if len(req.Stop) > 0 {
		out.Stop, _ = json.Marshal(req.Stop)
	}

	if req.ResponseFormat != nil {
		out.ResponseFormat = &openaiRespFormat{Type: req.ResponseFormat.Type}
	}

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

	if req.ToolChoice != nil {
		out.ToolChoice = encodeOpenAIToolChoice(req.ToolChoice)
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Response: Decode (Chat Completions response → Canonical)
// ---------------------------------------------------------------------------

func decodeCompletionsResponse(body []byte) (*CanonicalResponse, error) {
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
// Response: Encode (Canonical → Chat Completions response)
// ---------------------------------------------------------------------------

func encodeCompletionsResponse(resp *CanonicalResponse) ([]byte, error) {
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
// Stream: Decode (Chat Completions chunk → Canonical)
// ---------------------------------------------------------------------------

func decodeCompletionsStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var raw openaiStreamChunk
	if err := json.Unmarshal(chunk, &raw); err != nil {
		return nil, nil // skip non-JSON
	}

	sc := &CanonicalStreamChunk{
		ID:    raw.ID,
		Model: raw.Model,
	}

	if len(raw.Choices) > 0 {
		choice := raw.Choices[0]
		delta := choice.Delta
		sc.Role = delta.Role
		sc.Delta = delta.Content
		if choice.FinishReason != nil {
			sc.FinishReason = *choice.FinishReason
		}
		for _, tc := range delta.ToolCalls {
			sc.ToolCallDeltas = append(sc.ToolCallDeltas, StreamToolCallDelta{
				Index:          tc.Index,
				ID:             tc.ID,
				Name:           tc.Function.Name,
				ArgumentsDelta: tc.Function.Arguments,
			})
		}
	}

	if raw.Usage != nil {
		sc.Usage = &CanonicalUsage{
			PromptTokens:     raw.Usage.PromptTokens,
			CompletionTokens: raw.Usage.CompletionTokens,
			TotalTokens:      raw.Usage.TotalTokens,
		}
	}

	if sc.Delta == "" && sc.Role == "" && sc.FinishReason == "" && len(sc.ToolCallDeltas) == 0 && sc.Usage == nil {
		return nil, nil
	}

	return sc, nil
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → Chat Completions chunk)
// ---------------------------------------------------------------------------

func encodeCompletionsStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	delta := openaiStreamDelta{
		Role:    chunk.Role,
		Content: chunk.Delta,
	}
	for _, tc := range chunk.ToolCallDeltas {
		delta.ToolCalls = append(delta.ToolCalls, openaiStreamToolCall{
			Index: tc.Index,
			ID:    tc.ID,
			Type:  "function",
			Function: openaiStreamToolCallFn{
				Name:      tc.Name,
				Arguments: tc.ArgumentsDelta,
			},
		})
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

	if chunk.Usage != nil {
		out.Usage = &openaiUsage{
			PromptTokens:     chunk.Usage.PromptTokens,
			CompletionTokens: chunk.Usage.CompletionTokens,
			TotalTokens:      chunk.Usage.TotalTokens,
		}
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return SSEData(data), nil
}
