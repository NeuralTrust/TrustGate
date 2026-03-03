package adapter

import (
	"encoding/json"
	"strings"
)

// ---------------------------------------------------------------------------
// Responses API typed structs
// ---------------------------------------------------------------------------

type openaiResponsesRequest struct {
	Model           string            `json:"model,omitempty"`
	Input           json.RawMessage   `json:"input"`
	Instructions    string            `json:"instructions,omitempty"`
	MaxOutputTokens *int              `json:"max_output_tokens,omitempty"`
	Temperature     *float64          `json:"temperature,omitempty"`
	TopP            *float64          `json:"top_p,omitempty"`
	Stream          *bool             `json:"stream,omitempty"`
	Tools           []json.RawMessage `json:"tools,omitempty"`
	Text            *openaiTextFormat `json:"text,omitempty"`
}

type openaiTextFormat struct {
	Format *openaiRespFormat `json:"format,omitempty"`
}

type openaiResponsesInputItem struct {
	Role    string          `json:"role,omitempty"`
	Content json.RawMessage `json:"content,omitempty"` // string or []contentPart
	Type    string          `json:"type,omitempty"`     // "input_text", etc.
	Text    string          `json:"text,omitempty"`
}

type openaiResponsesTool struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Strict      *bool                  `json:"strict,omitempty"`
}

type openaiResponsesResponse struct {
	ID     string                `json:"id"`
	Object string                `json:"object"`
	Model  string                `json:"model"`
	Status string                `json:"status"`
	Output []openaiResponsesItem `json:"output"`
	Usage  *openaiResponsesUsage `json:"usage,omitempty"`
}

type openaiResponsesItem struct {
	Type      string                   `json:"type"`
	ID        string                   `json:"id,omitempty"`
	Role      string                   `json:"role,omitempty"`
	Content   []openaiResponsesContent `json:"content,omitempty"`
	Status    string                   `json:"status,omitempty"`
	CallID    string                   `json:"call_id,omitempty"`
	Name      string                   `json:"name,omitempty"`
	Arguments string                   `json:"arguments,omitempty"`
}

type openaiResponsesContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type openaiResponsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type openaiResponsesStreamEvent struct {
	Type         string          `json:"type"`
	Delta        string          `json:"delta,omitempty"`
	ItemID       string          `json:"item_id,omitempty"`
	OutputIndex  int             `json:"output_index,omitempty"`
	ContentIndex int             `json:"content_index,omitempty"`
	Item         json.RawMessage `json:"item,omitempty"`
	Response     json.RawMessage `json:"response,omitempty"`
}

// ---------------------------------------------------------------------------
// Request: Decode (Responses API → Canonical)
// ---------------------------------------------------------------------------

func decodeResponsesRequest(body []byte) (*CanonicalRequest, error) {
	var req openaiResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	cr := &CanonicalRequest{
		Model:       req.Model,
		System:      req.Instructions,
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}

	if req.Stream != nil {
		cr.Stream = *req.Stream
	}

	if req.MaxOutputTokens != nil {
		cr.MaxTokens = *req.MaxOutputTokens
	}

	if req.Text != nil && req.Text.Format != nil {
		cr.ResponseFormat = &CanonicalRespFormat{Type: req.Text.Format.Type}
	}

	// input: string or array of items
	if req.Input != nil {
		var inputStr string
		if json.Unmarshal(req.Input, &inputStr) == nil {
			cr.Messages = append(cr.Messages, CanonicalMessage{
				Role:    "user",
				Content: inputStr,
			})
		} else {
			var items []openaiResponsesInputItem
			if json.Unmarshal(req.Input, &items) == nil {
				for _, item := range items {
					switch {
					case item.Role != "":
						content := contentToString(item.Content)
						if item.Role == "system" || item.Role == "developer" {
							if cr.System != "" {
								cr.System += "\n"
							}
							cr.System += content
						} else {
							cr.Messages = append(cr.Messages, CanonicalMessage{
								Role:    item.Role,
								Content: content,
							})
						}
					case item.Type == "input_text":
						cr.Messages = append(cr.Messages, CanonicalMessage{
							Role:    "user",
							Content: item.Text,
						})
					}
				}
			}
		}
	}

	// tools: internally-tagged format
	for _, raw := range req.Tools {
		var tool openaiResponsesTool
		if json.Unmarshal(raw, &tool) == nil && tool.Type == "function" && tool.Name != "" {
			cr.Tools = append(cr.Tools, CanonicalTool{
				Name:        tool.Name,
				Description: tool.Description,
				Schema:      tool.Parameters,
			})
		}
	}

	return cr, nil
}

// ---------------------------------------------------------------------------
// Response: Decode (Responses API response → Canonical)
// ---------------------------------------------------------------------------

func decodeResponsesResponse(body []byte) (*CanonicalResponse, error) {
	var resp openaiResponsesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	cr := &CanonicalResponse{
		ID:    resp.ID,
		Model: resp.Model,
		Role:  "assistant",
	}

	var texts []string
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			for _, c := range item.Content {
				if c.Type == "output_text" && c.Text != "" {
					texts = append(texts, c.Text)
				}
			}
		case "function_call":
			cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
				ID:        item.CallID,
				Name:      item.Name,
				Arguments: item.Arguments,
			})
		}
	}
	cr.Content = strings.Join(texts, "\n")

	switch resp.Status {
	case "completed":
		if len(cr.ToolCalls) > 0 {
			cr.FinishReason = "tool_calls"
		} else {
			cr.FinishReason = "stop"
		}
	case "incomplete":
		cr.FinishReason = "length"
	default:
		cr.FinishReason = "stop"
	}

	if resp.Usage != nil {
		cr.Usage = &CanonicalUsage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}

	return cr, nil
}

// ---------------------------------------------------------------------------
// Stream: Decode (Responses API stream event → Canonical)
// ---------------------------------------------------------------------------

func decodeResponsesStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var event openaiResponsesStreamEvent
	if err := json.Unmarshal(chunk, &event); err != nil {
		return nil, nil
	}

	switch event.Type {
	case "response.output_text.delta":
		if event.Delta == "" {
			return nil, nil
		}
		return &CanonicalStreamChunk{
			Delta: event.Delta,
		}, nil

	case "response.function_call_arguments.delta":
		return &CanonicalStreamChunk{
			ToolCallDeltas: []StreamToolCallDelta{{
				Index:          event.OutputIndex,
				ArgumentsDelta: event.Delta,
			}},
		}, nil

	case "response.output_item.added":
		if event.Item != nil {
			var item struct {
				Type string `json:"type"`
				Role string `json:"role"`
				ID   string `json:"id"`
			}
			if json.Unmarshal(event.Item, &item) == nil && item.Type == "message" {
				return &CanonicalStreamChunk{
					Role: item.Role,
				}, nil
			}
		}
		return nil, nil

	case "response.function_call_arguments.done":
		return &CanonicalStreamChunk{
			FinishReason: "tool_calls",
		}, nil

	case "response.completed":
		sc := &CanonicalStreamChunk{
			FinishReason: "stop",
		}
		if event.Response != nil {
			var completed struct {
				ID    string                `json:"id"`
				Model string                `json:"model"`
				Usage *openaiResponsesUsage `json:"usage"`
			}
			if json.Unmarshal(event.Response, &completed) == nil {
				sc.ID = completed.ID
				sc.Model = completed.Model
				if completed.Usage != nil {
					sc.Usage = &CanonicalUsage{
						PromptTokens:     completed.Usage.InputTokens,
						CompletionTokens: completed.Usage.OutputTokens,
						TotalTokens:      completed.Usage.TotalTokens,
					}
				}
			}
		}
		return sc, nil

	default:
		return nil, nil
	}
}

// ---------------------------------------------------------------------------
// Request: Encode (Canonical → Responses API)
// ---------------------------------------------------------------------------

func encodeResponsesRequest(req *CanonicalRequest) ([]byte, error) {
	out := openaiResponsesRequest{
		Model:        req.Model,
		Instructions: req.System,
		Temperature:  req.Temperature,
		TopP:         req.TopP,
	}

	if req.Stream {
		out.Stream = boolPtr(true)
	}

	if req.MaxTokens > 0 {
		out.MaxOutputTokens = &req.MaxTokens
	}

	if req.ResponseFormat != nil {
		out.Text = &openaiTextFormat{
			Format: &openaiRespFormat{Type: req.ResponseFormat.Type},
		}
	}

	var inputItems []openaiResponsesInputItem
	for _, m := range req.Messages {
		inputItems = append(inputItems, openaiResponsesInputItem{
			Role:    m.Role,
			Content: stringToContent(m.Content),
		})
	}
	if len(inputItems) > 0 {
		out.Input, _ = json.Marshal(inputItems)
	}

	for _, t := range req.Tools {
		tool := openaiResponsesTool{
			Type:        "function",
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Schema,
		}
		raw, _ := json.Marshal(tool)
		out.Tools = append(out.Tools, raw)
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Response: Encode (Canonical → Responses API response)
// ---------------------------------------------------------------------------

func encodeResponsesResponse(resp *CanonicalResponse) ([]byte, error) {
	out := openaiResponsesResponse{
		ID:     resp.ID,
		Object: "response",
		Model:  resp.Model,
	}

	switch resp.FinishReason {
	case "length":
		out.Status = "incomplete"
	default:
		out.Status = "completed"
	}

	if resp.Content != "" {
		out.Output = append(out.Output, openaiResponsesItem{
			Type: "message",
			Role: "assistant",
			Content: []openaiResponsesContent{{
				Type: "output_text",
				Text: resp.Content,
			}},
			Status: "completed",
		})
	}

	for _, tc := range resp.ToolCalls {
		out.Output = append(out.Output, openaiResponsesItem{
			Type:      "function_call",
			CallID:    tc.ID,
			Name:      tc.Name,
			Arguments: tc.Arguments,
			Status:    "completed",
		})
	}

	if resp.Usage != nil {
		out.Usage = &openaiResponsesUsage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
			TotalTokens:  resp.Usage.TotalTokens,
		}
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → Responses API SSE events)
// ---------------------------------------------------------------------------

func encodeResponsesStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	var allLines [][]byte

	if chunk.Role != "" {
		event := openaiResponsesStreamEvent{
			Type:        "response.output_item.added",
			OutputIndex: 0,
		}
		itemJSON, _ := json.Marshal(map[string]string{
			"type": "message",
			"role": chunk.Role,
		})
		event.Item = itemJSON
		data, _ := json.Marshal(event)
		allLines = append(allLines, SSEEvent("response.output_item.added", data)...)
	}

	if chunk.Delta != "" {
		event := openaiResponsesStreamEvent{
			Type:         "response.output_text.delta",
			Delta:        chunk.Delta,
			OutputIndex:  0,
			ContentIndex: 0,
		}
		data, _ := json.Marshal(event)
		allLines = append(allLines, SSEEvent("response.output_text.delta", data)...)
	}

	for _, tc := range chunk.ToolCallDeltas {
		if tc.Name != "" {
			event := openaiResponsesStreamEvent{
				Type:        "response.output_item.added",
				OutputIndex: tc.Index,
			}
			itemJSON, _ := json.Marshal(map[string]interface{}{
				"type":    "function_call",
				"id":      tc.ID,
				"name":    tc.Name,
				"call_id": tc.ID,
			})
			event.Item = itemJSON
			data, _ := json.Marshal(event)
			allLines = append(allLines, SSEEvent("response.output_item.added", data)...)
		}
		if tc.ArgumentsDelta != "" {
			event := openaiResponsesStreamEvent{
				Type:        "response.function_call_arguments.delta",
				Delta:       tc.ArgumentsDelta,
				OutputIndex: tc.Index,
			}
			data, _ := json.Marshal(event)
			allLines = append(allLines, SSEEvent("response.function_call_arguments.delta", data)...)
		}
	}

	if chunk.FinishReason == "tool_calls" {
		event := openaiResponsesStreamEvent{
			Type: "response.function_call_arguments.done",
		}
		data, _ := json.Marshal(event)
		allLines = append(allLines, SSEEvent("response.function_call_arguments.done", data)...)
	}

	if chunk.FinishReason != "" {
		status := "completed"
		if chunk.FinishReason == "length" {
			status = "incomplete"
		}

		respObj := map[string]interface{}{
			"status": status,
		}
		if chunk.ID != "" {
			respObj["id"] = chunk.ID
		}
		if chunk.Model != "" {
			respObj["model"] = chunk.Model
		}
		if chunk.Usage != nil {
			respObj["usage"] = map[string]int{
				"input_tokens":  chunk.Usage.PromptTokens,
				"output_tokens": chunk.Usage.CompletionTokens,
				"total_tokens":  chunk.Usage.TotalTokens,
			}
		}

		event := openaiResponsesStreamEvent{
			Type: "response.completed",
		}
		event.Response, _ = json.Marshal(respObj)
		data, _ := json.Marshal(event)
		allLines = append(allLines, SSEEvent("response.completed", data)...)
	}

	if len(allLines) == 0 {
		return nil, nil
	}

	return allLines, nil
}
