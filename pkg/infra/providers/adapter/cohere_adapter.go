// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package adapter

import (
	"encoding/json"
	"strings"
)

type CohereAdapter struct{}

type cohereRequest struct {
	Model       string                 `json:"model,omitempty"`
	Messages    []cohereMessage        `json:"messages"`
	MaxTokens   *int                   `json:"max_tokens,omitempty"`
	Temperature *float64               `json:"temperature,omitempty"`
	TopP        *float64               `json:"p,omitempty"`
	Stream      *bool                  `json:"stream,omitempty"`
	Tools       []cohereTool           `json:"tools,omitempty"`
	ToolChoice  *cohereToolChoice      `json:"tool_choice,omitempty"`
	StopSeqs    []string               `json:"stop_sequences,omitempty"`
}

type cohereMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content,omitempty"`
	ToolCalls  []cohereToolCall `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type cohereTool struct {
	Type     string              `json:"type"`
	Function cohereToolFunction  `json:"function"`
}

type cohereToolFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type cohereToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

type cohereToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function cohereToolCallFunction `json:"function"`
}

type cohereToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type cohereResponse struct {
	ID           string                 `json:"id"`
	FinishReason string                 `json:"finish_reason"`
	Message      cohereAssistantMessage `json:"message"`
	Usage        *cohereUsage           `json:"usage,omitempty"`
}

type cohereAssistantMessage struct {
	Role      string                  `json:"role"`
	Content   []cohereContentBlock    `json:"content,omitempty"`
	ToolCalls []cohereToolCall        `json:"tool_calls,omitempty"`
}

type cohereContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type cohereUsage struct {
	Tokens *cohereUsageTokens `json:"tokens,omitempty"`
}

type cohereUsageTokens struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type cohereStreamEvent struct {
	Type  string          `json:"type"`
	Index int             `json:"index,omitempty"`
	Delta json.RawMessage `json:"delta,omitempty"`
}

type cohereContentDelta struct {
	Message *cohereContentDeltaMessage `json:"message,omitempty"`
}

type cohereContentDeltaMessage struct {
	Content *cohereContentBlock `json:"content,omitempty"`
}

type cohereMessageEndDelta struct {
	FinishReason string       `json:"finish_reason,omitempty"`
	Usage        *cohereUsage `json:"usage,omitempty"`
}

type cohereToolCallDelta struct {
	ID       string                 `json:"id,omitempty"`
	Function *cohereToolCallFunction `json:"function,omitempty"`
}

func cohereUsageToCanonical(u *cohereUsage) *CanonicalUsage {
	if u == nil || u.Tokens == nil {
		return nil
	}
	return newCanonicalUsage(u.Tokens.InputTokens, u.Tokens.OutputTokens, 0)
}

func cohereFinishToCanonical(reason string) string {
	switch strings.ToUpper(reason) {
	case "COMPLETE":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "TOOL_CALL":
		return "tool_calls"
	case "STOP_SEQUENCE":
		return "stop"
	default:
		return strings.ToLower(reason)
	}
}

func canonicalFinishToCohere(reason string) string {
	switch reason {
	case "stop":
		return "COMPLETE"
	case "length":
		return "MAX_TOKENS"
	case "tool_calls":
		return "TOOL_CALL"
	default:
		return "COMPLETE"
	}
}

func decodeCohereMessageContent(role string, content json.RawMessage) []CanonicalMessage {
	if content == nil {
		return []CanonicalMessage{{Role: role}}
	}
	var s string
	if json.Unmarshal(content, &s) == nil {
		return []CanonicalMessage{{Role: role, Content: s}}
	}
	var blocks []cohereContentBlock
	if json.Unmarshal(content, &blocks) != nil {
		return []CanonicalMessage{{Role: role, Content: contentToString(content)}}
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return []CanonicalMessage{{Role: role, Content: strings.Join(parts, "\n")}}
}

func (a *CohereAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req cohereRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	cr := &CanonicalRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stop:        req.StopSeqs,
	}
	if req.MaxTokens != nil {
		cr.MaxTokens = *req.MaxTokens
	}
	if req.Stream != nil {
		cr.Stream = *req.Stream
	}
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			for _, cm := range decodeCohereMessageContent(m.Role, m.Content) {
				if cm.Content != "" {
					cr.System = cm.Content
				}
			}
		case "tool":
			cr.Messages = append(cr.Messages, CanonicalMessage{
				Role:       "tool",
				ToolCallID: m.ToolCallID,
				Content:    contentToString(m.Content),
			})
		case "assistant":
			msg := CanonicalMessage{Role: "assistant"}
			for _, cm := range decodeCohereMessageContent(m.Role, m.Content) {
				msg.Content = cm.Content
			}
			for _, tc := range m.ToolCalls {
				msg.ToolCalls = append(msg.ToolCalls, CanonicalToolCall{
					ID:        tc.ID,
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				})
			}
			cr.Messages = append(cr.Messages, msg)
		default:
			cr.Messages = append(cr.Messages, decodeCohereMessageContent(m.Role, m.Content)...)
		}
	}
	for _, t := range req.Tools {
		cr.Tools = append(cr.Tools, CanonicalTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Schema:      t.Function.Parameters,
		})
	}
	if req.ToolChoice != nil {
		cr.ToolChoice = &CanonicalToolChoice{
			Type: req.ToolChoice.Type,
			Name: req.ToolChoice.Name,
		}
	}
	return cr, nil
}

func (a *CohereAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := cohereRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		StopSeqs:    req.Stop,
	}
	if req.MaxTokens > 0 {
		out.MaxTokens = &req.MaxTokens
	}
	if req.Stream {
		out.Stream = boolPtr(true)
	}
	if req.System != "" {
		raw, _ := json.Marshal(req.System)
		out.Messages = append(out.Messages, cohereMessage{Role: "system", Content: raw})
	}
	for _, m := range req.Messages {
		if m.Role == "tool" {
			raw, _ := json.Marshal(m.Content)
			out.Messages = append(out.Messages, cohereMessage{
				Role:       "tool",
				ToolCallID: m.ToolCallID,
				Content:    raw,
			})
			continue
		}
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			msg := cohereMessage{Role: "assistant"}
			if m.Content != "" {
				block, _ := json.Marshal([]cohereContentBlock{{Type: "text", Text: m.Content}})
				msg.Content = block
			}
			for _, tc := range m.ToolCalls {
				msg.ToolCalls = append(msg.ToolCalls, cohereToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: cohereToolCallFunction{
						Name:      tc.Name,
						Arguments: tc.Arguments,
					},
				})
			}
			out.Messages = append(out.Messages, msg)
			continue
		}
		out.Messages = append(out.Messages, cohereMessage{
			Role:    m.Role,
			Content: stringToContent(m.Content),
		})
	}
	for _, t := range req.Tools {
		schema := t.Schema
		if len(schema) == 0 {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		out.Tools = append(out.Tools, cohereTool{
			Type: "function",
			Function: cohereToolFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  schema,
			},
		})
	}
	if req.ToolChoice != nil {
		out.ToolChoice = &cohereToolChoice{
			Type: req.ToolChoice.Type,
			Name: req.ToolChoice.Name,
		}
	}
	return json.Marshal(out)
}

func (a *CohereAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp cohereResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{
		ID:           resp.ID,
		Role:         "assistant",
		FinishReason: cohereFinishToCanonical(resp.FinishReason),
		Usage:        cohereUsageToCanonical(resp.Usage),
	}
	for _, block := range resp.Message.Content {
		if block.Type == "text" {
			cr.Content += block.Text
		}
	}
	for _, tc := range resp.Message.ToolCalls {
		cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}
	return cr, nil
}

func (a *CohereAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	var content []cohereContentBlock
	if resp.Content != "" {
		content = append(content, cohereContentBlock{Type: "text", Text: resp.Content})
	}
	var toolCalls []cohereToolCall
	for _, tc := range resp.ToolCalls {
		toolCalls = append(toolCalls, cohereToolCall{
			ID:   tc.ID,
			Type: "function",
			Function: cohereToolCallFunction{
				Name:      tc.Name,
				Arguments: tc.Arguments,
			},
		})
	}
	out := cohereResponse{
		ID:           resp.ID,
		FinishReason: canonicalFinishToCohere(resp.FinishReason),
		Message: cohereAssistantMessage{
			Role:      "assistant",
			Content:   content,
			ToolCalls: toolCalls,
		},
	}
	if resp.Usage != nil {
		out.Usage = &cohereUsage{
			Tokens: &cohereUsageTokens{
				InputTokens:  resp.Usage.InputTokens,
				OutputTokens: resp.Usage.OutputTokens,
			},
		}
	}
	return json.Marshal(out)
}

func (a *CohereAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var event cohereStreamEvent
	if err := json.Unmarshal(chunk, &event); err != nil {
		return nil, nil
	}
	switch event.Type {
	case "content-delta":
		var delta cohereContentDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil || delta.Message == nil || delta.Message.Content == nil {
			return nil, nil
		}
		if delta.Message.Content.Text == "" {
			return nil, nil
		}
		return &CanonicalStreamChunk{Delta: delta.Message.Content.Text}, nil
	case "tool-call-delta":
		var delta cohereToolCallDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil {
			return nil, nil
		}
		args := ""
		if delta.Function != nil {
			args = delta.Function.Arguments
		}
		return &CanonicalStreamChunk{
			ToolCallDeltas: []StreamToolCallDelta{{
				Index:          event.Index,
				ID:             delta.ID,
				Name:           deltaFunctionName(delta.Function),
				ArgumentsDelta: args,
			}},
		}, nil
	case "message-end":
		var delta cohereMessageEndDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil {
			return nil, nil
		}
		sc := &CanonicalStreamChunk{}
		if delta.FinishReason != "" {
			sc.FinishReason = cohereFinishToCanonical(delta.FinishReason)
		}
		sc.Usage = cohereUsageToCanonical(delta.Usage)
		if sc.FinishReason == "" && sc.Usage == nil {
			return nil, nil
		}
		return sc, nil
	default:
		return nil, nil
	}
}

func deltaFunctionName(fn *cohereToolCallFunction) string {
	if fn == nil {
		return ""
	}
	return fn.Name
}

func (a *CohereAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	if chunk == nil {
		return nil, nil
	}
	var lines [][]byte
	if chunk.Delta != "" {
		payload, _ := json.Marshal(cohereStreamEvent{
			Type: "content-delta",
			Delta: mustMarshal(cohereContentDelta{
				Message: &cohereContentDeltaMessage{
					Content: &cohereContentBlock{Type: "text", Text: chunk.Delta},
				},
			}),
		})
		lines = append(lines, SSEEvent("content-delta", payload)...)
	}
	if len(chunk.ToolCallDeltas) > 0 {
		for _, tc := range chunk.ToolCallDeltas {
			payload, _ := json.Marshal(cohereStreamEvent{
				Type:  "tool-call-delta",
				Index: tc.Index,
				Delta: mustMarshal(cohereToolCallDelta{
					ID: tc.ID,
					Function: &cohereToolCallFunction{
						Name:      tc.Name,
						Arguments: tc.ArgumentsDelta,
					},
				}),
			})
			lines = append(lines, SSEEvent("tool-call-delta", payload)...)
		}
	}
	if chunk.FinishReason != "" || chunk.Usage != nil {
		delta := cohereMessageEndDelta{FinishReason: canonicalFinishToCohere(chunk.FinishReason)}
		if chunk.Usage != nil {
			delta.Usage = &cohereUsage{
				Tokens: &cohereUsageTokens{
					InputTokens:  chunk.Usage.InputTokens,
					OutputTokens: chunk.Usage.OutputTokens,
				},
			}
		}
		payload, _ := json.Marshal(cohereStreamEvent{
			Type:  "message-end",
			Delta: mustMarshal(delta),
		})
		lines = append(lines, SSEEvent("message-end", payload)...)
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return lines, nil
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
