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
	"fmt"
	"strings"
)

type GeminiAdapter struct{}

type geminiRequest struct {
	Model             string            `json:"model,omitempty"`
	Contents          []geminiContent   `json:"contents"`
	SystemInstruction *geminiContent    `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenConfig  `json:"generationConfig,omitempty"`
	Tools             []geminiToolGroup `json:"tools,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string              `json:"text,omitempty"`
	Thought          bool                `json:"thought,omitempty"` // true if this part is reasoning/thinking
	FunctionCall     *geminiFunctionCall `json:"functionCall,omitempty"`
	FunctionResponse *geminiFuncResponse `json:"functionResponse,omitempty"`
	ThoughtSignature string              `json:"thoughtSignature,omitempty"`
}

type geminiFunctionCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args,omitempty"`
}

type geminiFuncResponse struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response,omitempty"`
}

type geminiGenConfig struct {
	MaxOutputTokens  *int     `json:"maxOutputTokens,omitempty"`
	Temperature      *float64 `json:"temperature,omitempty"`
	TopP             *float64 `json:"topP,omitempty"`
	TopK             *int     `json:"topK,omitempty"`
	ResponseMimeType string   `json:"responseMimeType,omitempty"`
}

type geminiToolGroup struct {
	FunctionDeclarations []geminiFuncDecl `json:"functionDeclarations,omitempty"`
}

type geminiFuncDecl struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

type geminiResponse struct {
	ResponseID    string            `json:"responseId,omitempty"`
	ModelVersion  string            `json:"modelVersion,omitempty"`
	Candidates    []geminiCandidate `json:"candidates"`
	UsageMetadata *geminiUsage      `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content       geminiContent `json:"content"`
	FinishReason  string        `json:"finishReason,omitempty"`
	Index         int           `json:"index,omitempty"`
	FinishMessage string        `json:"finishMessage,omitempty"`
}

type geminiUsage struct {
	PromptTokenCount        int                 `json:"promptTokenCount"`
	CandidatesTokenCount    int                 `json:"candidatesTokenCount"`
	TotalTokenCount         int                 `json:"totalTokenCount"`
	CachedContentTokenCount int                 `json:"cachedContentTokenCount,omitempty"`
	ThoughtsTokenCount      int                 `json:"thoughtsTokenCount,omitempty"`
	ToolUsePromptTokenCount int                 `json:"toolUsePromptTokenCount,omitempty"`
	PromptTokensDetails     []geminiTokenDetail `json:"promptTokensDetails,omitempty"`
}

type geminiTokenDetail struct {
	Modality   string `json:"modality,omitempty"`
	TokenCount int    `json:"tokenCount,omitempty"`
}

func geminiUsageToCanonical(u geminiUsage) *CanonicalUsage {
	cu := newCanonicalUsage(
		u.PromptTokenCount+u.ToolUsePromptTokenCount,
		u.CandidatesTokenCount+u.ThoughtsTokenCount,
		u.TotalTokenCount,
	)
	if cu == nil {
		return nil
	}
	cu.CachedInputTokens = u.CachedContentTokenCount
	cu.ReasoningOutputTokens = u.ThoughtsTokenCount
	cu.ToolUseInputTokens = u.ToolUsePromptTokenCount
	return cu
}

func geminiUsageFromCanonical(u *CanonicalUsage) *geminiUsage {
	return &geminiUsage{
		PromptTokenCount:        u.InputTokens - u.ToolUseInputTokens,
		CandidatesTokenCount:    u.OutputTokens - u.ReasoningOutputTokens,
		TotalTokenCount:         u.TotalTokens,
		CachedContentTokenCount: u.CachedInputTokens,
		ThoughtsTokenCount:      u.ReasoningOutputTokens,
		ToolUsePromptTokenCount: u.ToolUseInputTokens,
	}
}

func (a *GeminiAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req geminiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	cr := &CanonicalRequest{
		Model: req.Model,
	}

	if req.SystemInstruction != nil {
		for _, p := range req.SystemInstruction.Parts {
			if cr.System != "" {
				cr.System += "\n"
			}
			cr.System += p.Text
		}
	}

	for _, c := range req.Contents {
		role := c.Role
		if role == "model" {
			role = "assistant"
		}
		var textParts []string
		var toolCalls []CanonicalToolCall
		var toolResults []CanonicalMessage
		for _, p := range c.Parts {
			if p.Thought || p.ThoughtSignature != "" {
				continue
			}
			if p.Text != "" {
				textParts = append(textParts, p.Text)
			}
			if p.FunctionCall != nil {
				args, _ := json.Marshal(p.FunctionCall.Args)
				toolCalls = append(toolCalls, CanonicalToolCall{
					ID:        p.FunctionCall.Name,
					Name:      p.FunctionCall.Name,
					Arguments: string(args),
				})
			}
			if p.FunctionResponse != nil {
				resp, _ := json.Marshal(p.FunctionResponse.Response)
				toolResults = append(toolResults, CanonicalMessage{
					Role:       "tool",
					ToolCallID: p.FunctionResponse.Name,
					Content:    string(resp),
				})
			}
		}
		if role == "assistant" && len(toolCalls) > 0 {
			cr.Messages = append(cr.Messages, CanonicalMessage{
				Role:      "assistant",
				Content:   strings.Join(textParts, "\n"),
				ToolCalls: toolCalls,
			})
		} else if len(textParts) > 0 {
			cr.Messages = append(cr.Messages, CanonicalMessage{
				Role:    role,
				Content: strings.Join(textParts, "\n"),
			})
		}
		cr.Messages = append(cr.Messages, toolResults...)
	}

	if gc := req.GenerationConfig; gc != nil {
		if gc.MaxOutputTokens != nil {
			cr.MaxTokens = *gc.MaxOutputTokens
		}
		cr.Temperature = gc.Temperature
		cr.TopP = gc.TopP
		cr.TopK = gc.TopK
		if gc.ResponseMimeType == "application/json" {
			cr.ResponseFormat = &CanonicalRespFormat{Type: "json_object"}
		}
	}

	for _, tg := range req.Tools {
		for _, d := range tg.FunctionDeclarations {
			cr.Tools = append(cr.Tools, CanonicalTool{
				Name:        d.Name,
				Description: d.Description,
				Schema:      geminiSchemaToJSONSchema(d.Parameters),
			})
		}
	}

	return cr, nil
}

func (a *GeminiAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := geminiRequest{
		Model: req.Model,
	}

	if req.System != "" {
		out.SystemInstruction = &geminiContent{
			Parts: []geminiPart{{Text: req.System}},
		}
	}

	for _, m := range req.Messages {
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		if role == "tool" {
			role = "user"
		}
		var parts []geminiPart
		if m.Content != "" && m.ToolCallID == "" {
			parts = append(parts, geminiPart{Text: m.Content})
		}
		for _, tc := range m.ToolCalls {
			var args map[string]interface{}
			if err := json.Unmarshal([]byte(tc.Arguments), &args); err != nil {
				return nil, fmt.Errorf("encode Gemini tool call %q arguments: %w", tc.Name, err)
			}
			parts = append(parts, geminiPart{
				FunctionCall: &geminiFunctionCall{
					Name: tc.Name,
					Args: args,
				},
			})
		}
		if m.ToolCallID != "" {
			var resp map[string]interface{}
			if json.Unmarshal([]byte(m.Content), &resp) != nil {
				resp = map[string]interface{}{"result": m.Content}
			}
			parts = append(parts, geminiPart{
				FunctionResponse: &geminiFuncResponse{
					Name:     m.ToolCallID,
					Response: resp,
				},
			})
		}
		if len(parts) > 0 {
			out.Contents = append(out.Contents, geminiContent{
				Role:  role,
				Parts: parts,
			})
		}
	}

	var gc geminiGenConfig
	hasGC := false
	if req.MaxTokens > 0 {
		gc.MaxOutputTokens = &req.MaxTokens
		hasGC = true
	}
	if req.Temperature != nil {
		gc.Temperature = req.Temperature
		hasGC = true
	}
	if req.TopP != nil {
		gc.TopP = req.TopP
		hasGC = true
	}
	if req.TopK != nil {
		gc.TopK = req.TopK
		hasGC = true
	}
	if req.ResponseFormat != nil && req.ResponseFormat.Type == "json_object" {
		gc.ResponseMimeType = "application/json"
		hasGC = true
	}
	if hasGC {
		out.GenerationConfig = &gc
	}

	if len(req.Tools) > 0 {
		var decls []geminiFuncDecl
		for _, t := range req.Tools {
			decls = append(decls, geminiFuncDecl{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  sanitizeGeminiParameters(t.Schema),
			})
		}
		out.Tools = []geminiToolGroup{{FunctionDeclarations: decls}}
	}

	return json.Marshal(out)
}

func (a *GeminiAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp geminiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	cr := &CanonicalResponse{
		ID:    resp.ResponseID,
		Model: resp.ModelVersion,
		Role:  "assistant",
	}

	if len(resp.Candidates) > 0 {
		cand := resp.Candidates[0]
		var thinkingParts []string
		parts := cand.Content.Parts
		if parts == nil {
			parts = []geminiPart{}
		}
		for _, p := range parts {
			isThought := p.Thought || p.ThoughtSignature != ""
			if isThought && p.Text != "" {
				thinkingParts = append(thinkingParts, p.Text)
				continue
			}
			if p.Text != "" {
				cr.Content += p.Text
			}
			if p.FunctionCall != nil {
				args, _ := json.Marshal(p.FunctionCall.Args)
				cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
					ID:        p.FunctionCall.Name, // Gemini uses name as ID
					Name:      p.FunctionCall.Name,
					Arguments: string(args),
				})
			}
		}
		if len(thinkingParts) > 0 {
			cr.Reasoning = &CanonicalReasoning{
				ThinkingText: strings.Join(thinkingParts, "\n\n"),
			}
			if cr.Content == "" {
				cr.Content = strings.Join(thinkingParts, "\n\n")
			}
		}

		if len(cr.ToolCalls) > 0 {
			cr.FinishReason = "tool_calls"
		} else {
			switch cand.FinishReason {
			case "STOP":
				cr.FinishReason = "stop"
			case "MAX_TOKENS":
				cr.FinishReason = "length"
			default:
				cr.FinishReason = cand.FinishReason
			}
		}
	}

	if u := resp.UsageMetadata; u != nil {
		cr.Usage = geminiUsageToCanonical(*u)
	}

	return cr, nil
}

func (a *GeminiAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	fr := "STOP"
	switch resp.FinishReason {
	case "length":
		fr = "MAX_TOKENS"
	case "tool_calls":
		fr = "STOP" // Gemini uses STOP even for function calls
	}

	var parts []geminiPart
	if resp.Reasoning != nil && resp.Reasoning.ThinkingText != "" {
		parts = append(parts, geminiPart{
			Text:    resp.Reasoning.ThinkingText,
			Thought: true,
		})
	}
	if resp.Content != "" {
		parts = append(parts, geminiPart{Text: resp.Content})
	}
	for _, tc := range resp.ToolCalls {
		var args map[string]interface{}
		_ = json.Unmarshal([]byte(tc.Arguments), &args)
		parts = append(parts, geminiPart{
			FunctionCall: &geminiFunctionCall{
				Name: tc.Name,
				Args: args,
			},
		})
	}

	out := geminiResponse{
		ResponseID:   resp.ID,
		ModelVersion: resp.Model,
		Candidates: []geminiCandidate{{
			Content:      geminiContent{Role: "model", Parts: parts},
			FinishReason: fr,
		}},
	}

	if resp.Usage != nil {
		out.UsageMetadata = geminiUsageFromCanonical(resp.Usage)
	}

	return json.Marshal(out)
}

func (a *GeminiAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var resp geminiResponse
	if err := json.Unmarshal(chunk, &resp); err != nil {
		return nil, nil
	}

	sc := &CanonicalStreamChunk{}

	if len(resp.Candidates) > 0 {
		cand := resp.Candidates[0]
		content := cand.Content

		if content.Role != "" {
			sc.Role = content.Role
			if sc.Role == "model" {
				sc.Role = "assistant"
			}
		}

		var text string
		for i, p := range content.Parts {
			if p.Thought || p.ThoughtSignature != "" {
				continue
			}
			text += p.Text
			if p.FunctionCall != nil {
				argsBytes, _ := json.Marshal(p.FunctionCall.Args)
				sc.ToolCallDeltas = append(sc.ToolCallDeltas, StreamToolCallDelta{
					Index:          i,
					ID:             p.FunctionCall.Name,
					Name:           p.FunctionCall.Name,
					ArgumentsDelta: string(argsBytes),
				})
			}
		}
		sc.Delta = text

		switch cand.FinishReason {
		case "STOP":
			sc.FinishReason = "stop"
		case "MAX_TOKENS":
			sc.FinishReason = "length"
		default:
			if cand.FinishReason != "" {
				sc.FinishReason = cand.FinishReason
			}
		}
	}

	if u := resp.UsageMetadata; u != nil {
		sc.Usage = geminiUsageToCanonical(*u)
	}

	if sc.Delta == "" && sc.Role == "" && sc.FinishReason == "" && len(sc.ToolCallDeltas) == 0 && sc.Usage == nil {
		return nil, nil
	}

	return sc, nil
}

func (a *GeminiAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	hasContent := chunk.Delta != "" || chunk.FinishReason != "" || chunk.Role != "" || len(chunk.ToolCallDeltas) > 0
	if !hasContent {
		return nil, nil
	}

	role := chunk.Role
	if role == "" || role == "assistant" {
		role = "model" // Gemini stream expects "model"
	}

	var parts []geminiPart
	if chunk.Delta != "" {
		parts = append(parts, geminiPart{Text: chunk.Delta})
	}
	for _, tc := range chunk.ToolCallDeltas {
		var args map[string]interface{}
		argsStr := tc.ArgumentsDelta
		if argsStr == "" {
			args = make(map[string]interface{})
		} else if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
			args = map[string]interface{}{"__raw": argsStr}
		}
		parts = append(parts, geminiPart{
			FunctionCall: &geminiFunctionCall{Name: tc.Name, Args: args},
		})
	}

	finishReason := ""
	switch chunk.FinishReason {
	case "stop", "tool_calls":
		finishReason = "STOP"
	case "length":
		finishReason = "MAX_TOKENS"
	default:
		if chunk.FinishReason != "" {
			finishReason = chunk.FinishReason
		}
	}

	out := geminiResponse{
		Candidates: []geminiCandidate{{
			Content:      geminiContent{Role: role, Parts: parts},
			FinishReason: finishReason,
		}},
	}

	if chunk.Usage != nil {
		out.UsageMetadata = geminiUsageFromCanonical(chunk.Usage)
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return SSEData(data), nil
}

var geminiToJSONSchemaType = map[string]string{
	"STRING":  "string",
	"OBJECT":  "object",
	"NUMBER":  "number",
	"INTEGER": "integer",
	"BOOLEAN": "boolean",
	"ARRAY":   "array",
	"NULL":    "null",
}

var jsonSchemaToGeminiType = map[string]string{
	"string":  "STRING",
	"object":  "OBJECT",
	"number":  "NUMBER",
	"integer": "INTEGER",
	"boolean": "BOOLEAN",
	"array":   "ARRAY",
	"null":    "NULL",
}

func geminiSchemaToJSONSchema(schema map[string]interface{}) map[string]interface{} {
	if schema == nil {
		return nil
	}
	out := make(map[string]interface{}, len(schema))
	for k, v := range schema {
		if k == "type" {
			if s, ok := v.(string); ok {
				if lower, found := geminiToJSONSchemaType[s]; found {
					out[k] = lower
					continue
				}
			}
		}
		switch val := v.(type) {
		case map[string]interface{}:
			out[k] = geminiSchemaToJSONSchema(val)
		case []interface{}:
			arr := make([]interface{}, len(val))
			for i, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					arr[i] = geminiSchemaToJSONSchema(m)
				} else {
					arr[i] = item
				}
			}
			out[k] = arr
		default:
			out[k] = v
		}
	}
	return out
}
