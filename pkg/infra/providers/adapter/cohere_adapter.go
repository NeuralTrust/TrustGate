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
	ToolPlan   string          `json:"tool_plan,omitempty"`
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
	ToolPlan  string                  `json:"tool_plan,omitempty"`
	ToolCalls []cohereToolCall        `json:"tool_calls,omitempty"`
}

type cohereContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type cohereUsage struct {
	BilledUnits  *cohereUsageTokens `json:"billed_units,omitempty"`
	Tokens       *cohereUsageTokens `json:"tokens,omitempty"`
	CachedTokens int                `json:"cached_tokens,omitempty"`
}

type cohereUsageTokens struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type cohereStreamEvent struct {
	ID    string          `json:"id,omitempty"`
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
	Error        string       `json:"error,omitempty"`
	Usage        *cohereUsage `json:"usage,omitempty"`
}

type cohereToolPlanDelta struct {
	Message *struct {
		ToolPlan string `json:"tool_plan"`
	} `json:"message"`
}

func cohereUsageToCanonical(u *cohereUsage) *CanonicalUsage {
	if u == nil || (u.Tokens == nil && u.BilledUnits == nil) {
		return nil
	}
	var in, out int
	for _, t := range []*cohereUsageTokens{u.Tokens, u.BilledUnits} {
		if t != nil {
			in, out = max(in, t.InputTokens), max(out, t.OutputTokens)
		}
	}
	// Billed input omits uncharged prompt tokens, so without usage.tokens this is only a lower bound.
	cu := newCanonicalUsage(max(in, u.CachedTokens), out, 0)
	if cu != nil && u.CachedTokens > 0 {
		cu.setCache(u.CachedTokens, 0, 0)
	}
	return cu
}

func cohereUsageFromCanonical(u *CanonicalUsage) *cohereUsage {
	if u == nil {
		return nil
	}
	tokens := &cohereUsageTokens{InputTokens: u.InputTokens, OutputTokens: u.OutputTokens}
	return &cohereUsage{
		BilledUnits:  tokens,
		Tokens:       tokens,
		CachedTokens: u.CachedInputTokens,
	}
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
	case "ERROR_TOXIC":
		return "content_filter"
	case "TIMEOUT", "ERROR_LIMIT":
		return "error"
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
			if msg.Content == "" {
				msg.Content = m.ToolPlan
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
			msg := cohereMessage{Role: "assistant", ToolPlan: m.Content}
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
	if cr.Content == "" {
		cr.Content = resp.Message.ToolPlan
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
	var toolPlan string
	switch {
	case len(resp.ToolCalls) > 0:
		toolPlan = resp.Content
	case resp.Content != "":
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
	finishReason, _ := cohereFinish(resp.FinishReason)
	if len(toolCalls) > 0 {
		finishReason, _ = cohereStreamFinishReason(resp.FinishReason, true)
	}
	out := cohereResponse{
		ID:           resp.ID,
		FinishReason: finishReason,
		Message: cohereAssistantMessage{
			Role:      "assistant",
			Content:   content,
			ToolPlan:  toolPlan,
			ToolCalls: toolCalls,
		},
	}
	out.Usage = cohereUsageFromCanonical(resp.Usage)
	return json.Marshal(out)
}

func (a *CohereAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var event cohereStreamEvent
	if err := json.Unmarshal(chunk, &event); err != nil {
		return nil, nil
	}
	switch event.Type {
	case "message-start":
		return &CanonicalStreamChunk{ID: event.ID, Role: "assistant"}, nil
	case "content-delta":
		var delta cohereContentDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil || delta.Message == nil || delta.Message.Content == nil {
			return nil, nil
		}
		if delta.Message.Content.Type != "" && delta.Message.Content.Type != "text" {
			return nil, nil
		}
		if delta.Message.Content.Text == "" {
			return nil, nil
		}
		return &CanonicalStreamChunk{Delta: delta.Message.Content.Text}, nil
	case "tool-plan-delta":
		var delta cohereToolPlanDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil || delta.Message == nil || delta.Message.ToolPlan == "" {
			return nil, nil
		}
		return &CanonicalStreamChunk{Delta: delta.Message.ToolPlan}, nil
	case "tool-call-start", "tool-call-delta":
		var delta cohereToolCallsDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil || delta.Message == nil || delta.Message.ToolCalls == nil {
			return nil, nil
		}
		tc := StreamToolCallDelta{Index: event.Index, ID: delta.Message.ToolCalls.ID}
		if fn := delta.Message.ToolCalls.Function; fn != nil {
			tc.Name, tc.ArgumentsDelta = fn.Name, fn.Arguments
		}
		if tc.ID == "" && tc.Name == "" && tc.ArgumentsDelta == "" {
			return nil, nil
		}
		return &CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{tc}}, nil
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

// EncodeStreamChunk encodes chunk on its own, without the state a Cohere
// client needs across the stream: it never ends content or tool calls, and
// every finish or usage becomes a message-end. Cross-format streams use a
// CohereStreamEncoder instead.
func (a *CohereAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	if chunk == nil {
		return nil, nil
	}
	var lines [][]byte
	if chunk.Role != "" {
		lines = append(lines, cohereMessageStart(chunk.ID)...)
	}
	if chunk.Delta != "" {
		lines = append(lines, cohereContentDeltaEvent(0, chunk.Delta)...)
	}
	for _, tc := range chunk.ToolCallDeltas {
		if tc.ID != "" || tc.Name != "" {
			lines = append(lines, cohereToolCallStart(tc.Index, tc.ID, tc.Name)...)
		}
		if tc.ArgumentsDelta != "" {
			lines = append(lines, cohereToolCallDeltaEvent(tc.Index, tc.ArgumentsDelta)...)
		}
	}
	if chunk.FinishReason != "" || chunk.Usage != nil {
		reason, errMessage := cohereFinish(chunk.FinishReason)
		lines = append(lines, cohereMessageEnd(reason, errMessage, chunk.Usage)...)
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
