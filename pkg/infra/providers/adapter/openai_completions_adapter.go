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
	Refusal    *string          `json:"refusal,omitempty"`
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openaiTool struct {
	Type     string            `json:"type"`
	Function *openaiFunction   `json:"function,omitempty"`
	Custom   *openaiCustomTool `json:"custom,omitempty"`
	// Clients built against the Responses API (Cursor with GPT-5 models) send
	// custom tools flat, with the payload alongside "type" instead of nested
	// under "custom". Decoding both shapes keeps such a tool from being
	// dropped; encoding always emits the nested Chat Completions shape.
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Format      json.RawMessage `json:"format,omitempty"`
}

// openaiCustomTool is the freeform tool shape GPT-5 models accept. Format is
// kept as raw JSON because its grammar payload is not part of the canonical
// model and must survive a round-trip untouched.
type openaiCustomTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Format      json.RawMessage `json:"format,omitempty"`
}

type openaiFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// A grammar format is spelled differently on each wire: Chat Completions nests
// the grammar fields under a "grammar" object, the Responses API keeps them
// alongside "type". The canonical model stores the flat form, so these two
// helpers translate on the way in and out. Non-grammar formats (e.g. plain
// text) are identical on both wires and pass through untouched.

func flattenCustomToolFormat(raw json.RawMessage) json.RawMessage {
	var format map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &format) != nil {
		return raw
	}
	inner, ok := format["grammar"]
	if !ok {
		return raw
	}
	kind, ok := format["type"]
	if !ok {
		return raw
	}
	var grammar map[string]json.RawMessage
	if json.Unmarshal(inner, &grammar) != nil {
		return raw
	}
	flat := map[string]json.RawMessage{"type": kind}
	for k, v := range grammar {
		flat[k] = v
	}
	out, err := json.Marshal(flat)
	if err != nil {
		return raw
	}
	return out
}

func wrapCustomToolFormat(raw json.RawMessage) json.RawMessage {
	var format map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &format) != nil {
		return raw
	}
	if _, already := format["grammar"]; already {
		return raw
	}
	var kind string
	if err := json.Unmarshal(format["type"], &kind); err != nil || kind != "grammar" {
		return raw
	}
	grammar := make(map[string]json.RawMessage, len(format))
	for k, v := range format {
		if k == "type" {
			continue
		}
		grammar[k] = v
	}
	if len(grammar) == 0 {
		return raw
	}
	inner, err := json.Marshal(grammar)
	if err != nil {
		return raw
	}
	out, err := json.Marshal(map[string]json.RawMessage{
		"type":    format["type"],
		"grammar": inner,
	})
	if err != nil {
		return raw
	}
	return out
}

type openaiToolCall struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Function *openaiCallFunc   `json:"function,omitempty"`
	Custom   *openaiCustomCall `json:"custom,omitempty"`
}

type openaiCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// openaiCustomCall is how GPT-5 models invoke a freeform "custom" tool: the
// payload is raw text rather than JSON arguments.
type openaiCustomCall struct {
	Name  string `json:"name"`
	Input string `json:"input"`
}

func decodeOpenAIToolCall(tc openaiToolCall) CanonicalToolCall {
	if tc.Type == "custom" && tc.Custom != nil {
		return CanonicalToolCall{
			ID:        tc.ID,
			Kind:      ToolKindCustom,
			Name:      tc.Custom.Name,
			Arguments: tc.Custom.Input,
		}
	}
	call := CanonicalToolCall{ID: tc.ID}
	if tc.Function != nil {
		call.Name = tc.Function.Name
		call.Arguments = tc.Function.Arguments
	}
	return call
}

func encodeOpenAIToolCall(tc CanonicalToolCall) openaiToolCall {
	if tc.Kind == ToolKindCustom {
		return openaiToolCall{
			ID:     tc.ID,
			Type:   "custom",
			Custom: &openaiCustomCall{Name: tc.Name, Input: tc.Arguments},
		}
	}
	return openaiToolCall{
		ID:       tc.ID,
		Type:     "function",
		Function: &openaiCallFunc{Name: tc.Name, Arguments: tc.Arguments},
	}
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
	XGroq     json.RawMessage  `json:"x_groq,omitempty"`
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
	PromptTokens            int                            `json:"prompt_tokens"`
	CompletionTokens        int                            `json:"completion_tokens"`
	TotalTokens             int                            `json:"total_tokens"`
	PromptTokensDetails     *openaiPromptTokensDetails     `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *openaiCompletionTokensDetails `json:"completion_tokens_details,omitempty"`
}

type openaiPromptTokensDetails struct {
	CachedTokens int `json:"cached_tokens"`
}

type openaiCompletionTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

func openaiUsageToCanonical(u openaiUsage) *CanonicalUsage {
	cu := newCanonicalUsage(u.PromptTokens, u.CompletionTokens, u.TotalTokens)
	if cu == nil {
		return nil
	}
	if u.PromptTokensDetails != nil {
		cu.CachedInputTokens = u.PromptTokensDetails.CachedTokens
	}
	if u.CompletionTokensDetails != nil {
		cu.ReasoningOutputTokens = u.CompletionTokensDetails.ReasoningTokens
	}
	return cu
}

type openaiStreamChunk struct {
	ID      string               `json:"id,omitempty"`
	Object  string               `json:"object"`
	Model   string               `json:"model,omitempty"`
	Choices []openaiStreamChoice `json:"choices"`
	Usage   *openaiUsage         `json:"usage,omitempty"`
	XGroq   json.RawMessage      `json:"x_groq,omitempty"`
}

type openaiStreamChoice struct {
	Index        int               `json:"index"`
	Delta        openaiStreamDelta `json:"delta"`
	FinishReason *string           `json:"finish_reason,omitempty"`
}

type openaiStreamDelta struct {
	Role             string                 `json:"role,omitempty"`
	Content          string                 `json:"content,omitempty"`
	ReasoningContent string                 `json:"reasoning_content,omitempty"`
	ToolCalls        []openaiStreamToolCall `json:"tool_calls,omitempty"`
}

type openaiStreamToolCall struct {
	Index    int                     `json:"index"`
	ID       string                  `json:"id,omitempty"`
	Type     string                  `json:"type,omitempty"`
	Function *openaiStreamToolCallFn `json:"function,omitempty"`
	Custom   *openaiStreamToolCallFn `json:"custom,omitempty"`
}

// openaiStreamToolCallFn carries the incremental name/payload of a streamed
// tool call. Custom tool calls stream their freeform text under "input"
// instead of "arguments", so both keys are decoded into Arguments.
type openaiStreamToolCallFn struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	Input     string `json:"input,omitempty"`
}

func (f *openaiStreamToolCallFn) payload() string {
	if f == nil {
		return ""
	}
	if f.Input != "" {
		return f.Input
	}
	return f.Arguments
}

func (f *openaiStreamToolCallFn) name() string {
	if f == nil {
		return ""
	}
	return f.Name
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
			cm.ToolCalls = append(cm.ToolCalls, decodeOpenAIToolCall(tc))
		}

		if m.Role == "system" || m.Role == "developer" {
			if cr.System != "" {
				cr.System += "\n"
			}
			cr.System += content
		} else {
			cr.Messages = append(cr.Messages, cm)
		}
	}

	for _, t := range req.Tools {
		switch {
		case t.Type == "custom":
			custom := t.Custom
			if custom == nil {
				custom = &openaiCustomTool{Name: t.Name, Description: t.Description, Format: t.Format}
			}
			cr.Tools = append(cr.Tools, CanonicalTool{
				Kind:        ToolKindCustom,
				Name:        custom.Name,
				Description: custom.Description,
				Format:      flattenCustomToolFormat(custom.Format),
			})
		case t.Function != nil:
			cr.Tools = append(cr.Tools, CanonicalTool{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Schema:      t.Function.Parameters,
			})
		}
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
			msg.ToolCalls = append(msg.ToolCalls, encodeOpenAIToolCall(tc))
		}
		out.Messages = append(out.Messages, msg)
	}

	for _, t := range req.Tools {
		if t.Kind == ToolKindCustom {
			out.Tools = append(out.Tools, openaiTool{
				Type: "custom",
				Custom: &openaiCustomTool{
					Name:        t.Name,
					Description: t.Description,
					Format:      wrapCustomToolFormat(t.Format),
				},
			})
			continue
		}
		out.Tools = append(out.Tools, openaiTool{
			Type: "function",
			Function: &openaiFunction{
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
			if cr.Content == "" && choice.Message.Refusal != nil {
				cr.Content = strings.TrimSpace(*choice.Message.Refusal)
			}
			for _, tc := range choice.Message.ToolCalls {
				cr.ToolCalls = append(cr.ToolCalls, decodeOpenAIToolCall(tc))
			}
		}
		cr.FinishReason = choice.FinishReason
	}

	if resp.Usage != nil {
		cr.Usage = openaiUsageToCanonical(*resp.Usage)
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

	if resp.XGroq != nil {
		cr.ProviderExtensions = map[string]json.RawMessage{
			"x_groq": resp.XGroq,
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
		msg.ToolCalls = append(msg.ToolCalls, encodeOpenAIToolCall(tc))
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
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
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

	if raw, ok := resp.ProviderExtensions["x_groq"]; ok && len(raw) > 0 {
		out.XGroq = raw
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
			scd := StreamToolCallDelta{Index: tc.Index, ID: tc.ID}
			if tc.Type == "custom" || tc.Custom != nil {
				scd.Kind = ToolKindCustom
				scd.Name = tc.Custom.name()
				scd.ArgumentsDelta = tc.Custom.payload()
			} else {
				scd.Name = tc.Function.name()
				scd.ArgumentsDelta = tc.Function.payload()
			}
			sc.ToolCallDeltas = append(sc.ToolCallDeltas, scd)
		}
	}

	if raw.Usage != nil {
		sc.Usage = openaiUsageToCanonical(*raw.Usage)
	}

	if raw.XGroq != nil {
		sc.ProviderExtensions = map[string]json.RawMessage{
			"x_groq": raw.XGroq,
		}
	}

	if sc.Delta == "" &&
		sc.Role == "" &&
		sc.FinishReason == "" &&
		len(sc.ToolCallDeltas) == 0 &&
		sc.Usage == nil &&
		len(sc.ProviderExtensions) == 0 {
		return nil, nil
	}

	return sc, nil
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → Chat Completions chunk)
// ---------------------------------------------------------------------------

func encodeCompletionsStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	delta := openaiStreamDelta{
		Role:             chunk.Role,
		Content:          chunk.Delta,
		ReasoningContent: chunk.ReasoningDelta,
	}
	for _, tc := range chunk.ToolCallDeltas {
		if tc.Kind == ToolKindCustom {
			delta.ToolCalls = append(delta.ToolCalls, openaiStreamToolCall{
				Index:  tc.Index,
				ID:     tc.ID,
				Type:   "custom",
				Custom: &openaiStreamToolCallFn{Name: tc.Name, Input: tc.ArgumentsDelta},
			})
			continue
		}
		delta.ToolCalls = append(delta.ToolCalls, openaiStreamToolCall{
			Index: tc.Index,
			ID:    tc.ID,
			Type:  "function",
			Function: &openaiStreamToolCallFn{
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
			PromptTokens:     chunk.Usage.InputTokens,
			CompletionTokens: chunk.Usage.OutputTokens,
			TotalTokens:      chunk.Usage.TotalTokens,
		}
	}

	if raw, ok := chunk.ProviderExtensions["x_groq"]; ok && len(raw) > 0 {
		out.XGroq = raw
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return SSEData(data), nil
}
