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
	"regexp"
	"strconv"
	"strings"
)

// GeminiAdapter converts between Google Gemini generateContent format and the
// canonical internal model.
type GeminiAdapter struct {
	vertex bool
}

// NewVertexAdapter returns a GeminiAdapter for Vertex AI, which encodes
// requests without the functionCall and functionResponse ids and the
// thoughtSignature bypass sent to the Gemini API.
func NewVertexAdapter() *GeminiAdapter {
	return &GeminiAdapter{vertex: true}
}

// ---------------------------------------------------------------------------
// Provider-specific typed structs
// ---------------------------------------------------------------------------

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
	ID   string                 `json:"id,omitempty"`
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args,omitempty"`
}

type geminiFuncResponse struct {
	ID       string                 `json:"id,omitempty"`
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response,omitempty"`
}

// Gemini bypass for replayed functionCalls lacking canonical thoughtSignature support (ENG-1627).
const geminiSkipThoughtSignature = "skip_thought_signature_validator"

// geminiCallIDs hands out the canonical ids of the functionCalls of one model
// turn. A call without an id takes its name, or the name suffixed with _2, _3
// and so on when an earlier call of the turn already holds it, so parallel
// calls to one function stay distinct; EncodeRequest never sends these
// synthetic ids to Gemini.
type geminiCallIDs map[string]bool

func (u geminiCallIDs) assign(fc *geminiFunctionCall) string {
	if fc.ID != "" {
		u[fc.ID] = true
		return fc.ID
	}
	return u.synthetic(fc.Name)
}

func (u geminiCallIDs) synthetic(name string) string {
	id := name
	for n := 2; u[id]; n++ {
		id = name + "_" + strconv.Itoa(n)
	}
	u[id] = true
	return id
}

// geminiSyntheticCallID reports whether id is one geminiCallIDs gave a call
// to name that had no id of its own.
func geminiSyntheticCallID(id, name string) bool {
	if id == name {
		return true
	}
	suffix, ok := strings.CutPrefix(id, name+"_")
	if !ok {
		return false
	}
	n, err := strconv.Atoi(suffix)
	return err == nil && n >= 2 && strconv.Itoa(n) == suffix
}

// geminiSyntheticCallName returns the function name a synthetic id with a
// numeric suffix was made from, when that name is one of tools.
func geminiSyntheticCallName(id string, tools []CanonicalTool) (string, bool) {
	cut := strings.LastIndexByte(id, '_')
	if cut <= 0 {
		return "", false
	}
	name := id[:cut]
	if !geminiSyntheticCallID(id, name) {
		return "", false
	}
	for _, t := range tools {
		if t.Name == id {
			return "", false
		}
	}
	for _, t := range tools {
		if t.Name == name {
			return name, true
		}
	}
	return "", false
}

// geminiPendingCalls holds the call ids of the latest model turn that have
// no functionResponse yet, oldest first per function name.
type geminiPendingCalls map[string][]string

// resolve returns the call id fr answers and marks that call answered. A
// response without an id answers the oldest open call of its name, or keeps
// the name as its id when there is none.
func (p geminiPendingCalls) resolve(fr *geminiFuncResponse) string {
	queue := p[fr.Name]
	if fr.ID != "" {
		for i, id := range queue {
			if id == fr.ID {
				p[fr.Name] = append(queue[:i:i], queue[i+1:]...)
				break
			}
		}
		return fr.ID
	}
	if len(queue) == 0 {
		return fr.Name
	}
	p[fr.Name] = queue[1:]
	return queue[0]
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

// ---------------------------------------------------------------------------
// Request: Decode (Gemini → Canonical)
// ---------------------------------------------------------------------------

func (a *GeminiAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req geminiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	cr := &CanonicalRequest{
		Model: req.Model,
	}

	// systemInstruction → system
	if req.SystemInstruction != nil {
		for _, p := range req.SystemInstruction.Parts {
			if cr.System != "" {
				cr.System += "\n"
			}
			cr.System += p.Text
		}
	}

	// contents → messages (Gemini "user" with functionResponse must become canonical "tool" for OpenAI)
	pending := geminiPendingCalls{}
	for _, c := range req.Contents {
		role := c.Role
		ids := geminiCallIDs{}
		if role == "model" {
			role = "assistant"
			pending = geminiPendingCalls{}
		}
		var textParts []string
		var toolCalls []CanonicalToolCall
		var toolResults []CanonicalMessage
		for _, p := range c.Parts {
			if p.Thought {
				continue
			}
			if p.Text != "" {
				textParts = append(textParts, p.Text)
			}
			if p.FunctionCall != nil {
				args, _ := json.Marshal(p.FunctionCall.Args)
				id := ids.assign(p.FunctionCall)
				toolCalls = append(toolCalls, CanonicalToolCall{
					ID:        id,
					Name:      p.FunctionCall.Name,
					Arguments: string(args),
				})
				if c.Role == "model" {
					pending[p.FunctionCall.Name] = append(pending[p.FunctionCall.Name], id)
				}
			}
			if p.FunctionResponse != nil {
				resp, _ := json.Marshal(p.FunctionResponse.Response)
				toolResults = append(toolResults, CanonicalMessage{
					Role:       "tool",
					ToolCallID: pending.resolve(p.FunctionResponse),
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
		// Emit tool result messages so OpenAI gets role "tool" after assistant tool_calls.
		cr.Messages = append(cr.Messages, toolResults...)
	}

	// generationConfig
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

	// tools — convert Gemini UPPER_CASE types to JSON Schema lowercase
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

// ---------------------------------------------------------------------------
// Request: Encode (Canonical → Gemini)
// ---------------------------------------------------------------------------

var generatedToolUseID = regexp.MustCompile(`^toolu_[A-Z2-7]+_[0-9]+$`)

// geminiFunctionResponseName returns the function name Gemini pairs a result
// for callID with. A call missing from the request keeps its id as the name,
// unless the id is one AnthropicStreamEncoder generated and only one function
// is declared, which must then be the one called.
func geminiFunctionResponseName(callID string, toolNames map[string]string, tools []CanonicalTool) string {
	if name := toolNames[callID]; name != "" {
		return name
	}
	if len(tools) == 1 && generatedToolUseID.MatchString(callID) {
		return tools[0].Name
	}
	if name, ok := geminiSyntheticCallName(callID, tools); ok {
		return name
	}
	return callID
}

func (a *GeminiAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := geminiRequest{
		Model: req.Model,
	}

	// systemInstruction
	if req.System != "" {
		out.SystemInstruction = &geminiContent{
			Parts: []geminiPart{{Text: req.System}},
		}
	}

	// contents (canonical "tool" → Gemini "user" with functionResponse)
	toolNames := map[string]string{}
	lastWasToolResult := false
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
		// Tool calls from assistant → functionCall parts
		for i, tc := range m.ToolCalls {
			var args map[string]interface{}
			_ = json.Unmarshal([]byte(tc.Arguments), &args)
			part := geminiPart{
				FunctionCall: &geminiFunctionCall{
					Name: tc.Name,
					Args: args,
				},
			}
			if !a.vertex && !geminiSyntheticCallID(tc.ID, tc.Name) {
				part.FunctionCall.ID = tc.ID
			}
			if !a.vertex && i == 0 && role == "model" {
				part.ThoughtSignature = geminiSkipThoughtSignature
			}
			parts = append(parts, part)
			if tc.ID != "" {
				toolNames[tc.ID] = tc.Name
			}
		}
		// Tool result → functionResponse part
		if m.ToolCallID != "" {
			var resp map[string]interface{}
			if json.Unmarshal([]byte(m.Content), &resp) != nil {
				resp = map[string]interface{}{"result": m.Content}
			}
			fr := &geminiFuncResponse{
				Name:     geminiFunctionResponseName(m.ToolCallID, toolNames, req.Tools),
				Response: resp,
			}
			if _, ok := toolNames[m.ToolCallID]; ok && !a.vertex && !geminiSyntheticCallID(m.ToolCallID, fr.Name) {
				fr.ID = m.ToolCallID
			}
			parts = append(parts, geminiPart{FunctionResponse: fr})
		}
		isToolResult := m.Role == "tool" && m.ToolCallID != ""
		if len(parts) == 0 {
			lastWasToolResult = false
			continue
		}
		if isToolResult && lastWasToolResult {
			// Gemini requires one content with as many functionResponse parts as
			// the model turn had functionCall parts.
			last := &out.Contents[len(out.Contents)-1]
			last.Parts = append(last.Parts, parts...)
			continue
		}
		out.Contents = append(out.Contents, geminiContent{
			Role:  role,
			Parts: parts,
		})
		lastWasToolResult = isToolResult
	}

	// generationConfig
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

	// tools — convert JSON Schema lowercase types to Gemini UPPER_CASE
	if len(req.Tools) > 0 {
		var decls []geminiFuncDecl
		for _, t := range req.Tools {
			decls = append(decls, geminiFuncDecl{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  jsonSchemaToGeminiSchema(t.Schema),
			})
		}
		out.Tools = []geminiToolGroup{{FunctionDeclarations: decls}}
	}

	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Response: Decode (Gemini response → Canonical)
// ---------------------------------------------------------------------------

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
		ids := geminiCallIDs{}
		parts := cand.Content.Parts
		if parts == nil {
			parts = []geminiPart{}
		}
		for _, p := range parts {
			if p.Thought {
				if p.Text != "" {
					thinkingParts = append(thinkingParts, p.Text)
				}
				continue
			}
			if p.Text != "" {
				cr.Content += p.Text
			}
			if p.FunctionCall != nil {
				args, _ := json.Marshal(p.FunctionCall.Args)
				cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
					ID:        ids.assign(p.FunctionCall),
					Name:      p.FunctionCall.Name,
					Arguments: string(args),
				})
			}
		}
		if len(thinkingParts) > 0 {
			cr.Reasoning = &CanonicalReasoning{
				ThinkingText: strings.Join(thinkingParts, "\n\n"),
			}
			// If the model returned only thought blocks (e.g. Gemini 2.5 thinking mode),
			// use that as content so the client gets a non-empty response.
			if cr.Content == "" && len(cr.ToolCalls) == 0 {
				cr.Content = strings.Join(thinkingParts, "\n\n")
			}
		}

		// finishReason mapping
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

// ---------------------------------------------------------------------------
// Response: Encode (Canonical → Gemini response)
// ---------------------------------------------------------------------------

func (a *GeminiAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	fr := "STOP"
	switch resp.FinishReason {
	case "length":
		fr = "MAX_TOKENS"
	case "tool_calls":
		fr = "STOP" // Gemini uses STOP even for function calls
	}

	var parts []geminiPart
	// Prepend thinking part if present (Gemini thinking/reasoning)
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

// ---------------------------------------------------------------------------
// Stream: Decode (Gemini SSE chunk → Canonical)
// ---------------------------------------------------------------------------

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

		var text, reasoning string
		ids := geminiCallIDs{}
		for i, p := range content.Parts {
			if p.Thought {
				reasoning += p.Text
				continue
			}
			text += p.Text
			if p.FunctionCall != nil {
				argsBytes, _ := json.Marshal(p.FunctionCall.Args)
				sc.ToolCallDeltas = append(sc.ToolCallDeltas, StreamToolCallDelta{
					Index:          i,
					ID:             ids.assign(p.FunctionCall),
					Name:           p.FunctionCall.Name,
					ArgumentsDelta: string(argsBytes),
				})
			}
		}
		sc.Delta = text
		sc.ReasoningDelta = reasoning

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

	if sc.Delta == "" && sc.ReasoningDelta == "" && sc.Role == "" && sc.FinishReason == "" && len(sc.ToolCallDeltas) == 0 && sc.Usage == nil {
		return nil, nil
	}

	return sc, nil
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → Gemini SSE chunk)
// ---------------------------------------------------------------------------

func (a *GeminiAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	// Emit for Role (assistant start), Delta (text), ToolCallDeltas (complete tool calls), or FinishReason.
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

// ---------------------------------------------------------------------------
// Gemini ↔ JSON Schema type mapping helpers
//
// Gemini uses UPPER_CASE type names: STRING, OBJECT, NUMBER, INTEGER, BOOLEAN, ARRAY
// JSON Schema (OpenAI, Anthropic, etc.) uses lower_case: string, object, number, integer, boolean, array
// ---------------------------------------------------------------------------

var geminiToJSONSchemaType = map[string]string{
	"STRING":  "string",
	"OBJECT":  "object",
	"NUMBER":  "number",
	"INTEGER": "integer",
	"BOOLEAN": "boolean",
	"ARRAY":   "array",
}

var jsonSchemaToGeminiType = map[string]string{
	"string":  "STRING",
	"object":  "OBJECT",
	"number":  "NUMBER",
	"integer": "INTEGER",
	"boolean": "BOOLEAN",
	"array":   "ARRAY",
}

// geminiSchemaToJSONSchema recursively converts Gemini UPPER_CASE types to
// standard JSON Schema lowercase types in a schema map.
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
		// Recurse into nested objects
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

// jsonSchemaToGeminiSchema recursively converts standard JSON Schema lowercase
// types to Gemini UPPER_CASE types.
func jsonSchemaToGeminiSchema(schema map[string]interface{}) map[string]interface{} {
	if schema == nil {
		return nil
	}
	out := make(map[string]interface{}, len(schema))
	for k, v := range schema {
		if k == "type" {
			if s, ok := v.(string); ok {
				if upper, found := jsonSchemaToGeminiType[s]; found {
					out[k] = upper
					continue
				}
			}
		}
		// Recurse into nested objects
		switch val := v.(type) {
		case map[string]interface{}:
			out[k] = jsonSchemaToGeminiSchema(val)
		case []interface{}:
			arr := make([]interface{}, len(val))
			for i, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					arr[i] = jsonSchemaToGeminiSchema(m)
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

// GeminiCallIndexer renumbers the tool-call deltas of one Gemini stream.
// Gemini indexes a functionCall by its part position within its chunk, so
// parallel calls sent in separate chunks all arrive at index 0; not safe for
// concurrent use.
type GeminiCallIndexer struct {
	next int
	ids  geminiCallIDs
}

// Renumber gives each delta that starts a call, one carrying an ID or a Name,
// the next stream-wide index and, when the call had no id of its own, a
// synthetic id distinct across the stream; any other delta gets the index of
// the call it continues.
func (g *GeminiCallIndexer) Renumber(deltas []StreamToolCallDelta) {
	if g == nil {
		return
	}
	if g.ids == nil {
		g.ids = geminiCallIDs{}
	}
	for i := range deltas {
		d := &deltas[i]
		if d.ID == "" && d.Name == "" && g.next > 0 {
			d.Index = g.next - 1
			continue
		}
		d.Index = g.next
		g.next++
		if d.Name != "" && geminiSyntheticCallID(d.ID, d.Name) {
			d.ID = g.ids.synthetic(d.Name)
		} else if d.ID != "" {
			g.ids[d.ID] = true
		}
	}
}
