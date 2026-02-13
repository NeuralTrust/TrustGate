package adapter

import (
	"encoding/json"
	"strings"
)

// GeminiAdapter converts between Google Gemini generateContent format and the
// canonical internal model.
type GeminiAdapter struct{}

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
	Text             string                `json:"text,omitempty"`
	Thought          bool                  `json:"thought,omitempty"`           // true if this part is reasoning/thinking
	FunctionCall     *geminiFunctionCall   `json:"functionCall,omitempty"`
	FunctionResponse *geminiFuncResponse   `json:"functionResponse,omitempty"`
	ThoughtSignature string                `json:"thoughtSignature,omitempty"`
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
	PromptTokenCount     int                    `json:"promptTokenCount"`
	CandidatesTokenCount int                    `json:"candidatesTokenCount"`
	TotalTokenCount      int                    `json:"totalTokenCount"`
	ThoughtsTokenCount   int                    `json:"thoughtsTokenCount,omitempty"`
	PromptTokensDetails  []geminiTokenDetail    `json:"promptTokensDetails,omitempty"`
}

type geminiTokenDetail struct {
	Modality   string `json:"modality,omitempty"`
	TokenCount int    `json:"tokenCount,omitempty"`
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
	for _, c := range req.Contents {
		role := c.Role
		if role == "model" {
			role = "assistant"
		}
		var textParts []string
		var toolCalls []CanonicalToolCall
		var toolResults []CanonicalMessage
		for _, p := range c.Parts {
			if p.Text != "" {
				textParts = append(textParts, p.Text)
			}
			if p.FunctionCall != nil {
				args, _ := json.Marshal(p.FunctionCall.Args)
				// Gemini uses function name as identifier; use it as ID so tool results match.
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
		for _, tc := range m.ToolCalls {
			var args map[string]interface{}
			_ = json.Unmarshal([]byte(tc.Arguments), &args)
			parts = append(parts, geminiPart{
				FunctionCall: &geminiFunctionCall{
					Name: tc.Name,
					Args: args,
				},
			})
		}
		// Tool result → functionResponse part
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
			// If the model returned only thought blocks (e.g. Gemini 2.5 thinking mode),
			// use that as content so the client gets a non-empty response.
			if cr.Content == "" {
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
		tt := u.TotalTokenCount
		if tt == 0 {
			tt = u.PromptTokenCount + u.CandidatesTokenCount
		}
		cr.Usage = &CanonicalUsage{
			PromptTokens:     u.PromptTokenCount,
			CompletionTokens: u.CandidatesTokenCount,
			TotalTokens:      tt,
		}
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
		out.UsageMetadata = &geminiUsage{
			PromptTokenCount:     resp.Usage.PromptTokens,
			CandidatesTokenCount: resp.Usage.CompletionTokens,
			TotalTokenCount:      resp.Usage.TotalTokens,
		}
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

	if len(resp.Candidates) == 0 {
		return nil, nil
	}

	var text string
	for _, p := range resp.Candidates[0].Content.Parts {
		text += p.Text
	}
	if text == "" {
		return nil, nil
	}

	return &CanonicalStreamChunk{Delta: text}, nil
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → Gemini SSE chunk)
// ---------------------------------------------------------------------------

func (a *GeminiAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	if chunk.Delta == "" && chunk.FinishReason == "" {
		return nil, nil
	}

	var parts []geminiPart
	if chunk.Delta != "" {
		parts = append(parts, geminiPart{Text: chunk.Delta})
	}

	out := geminiResponse{
		Candidates: []geminiCandidate{{
			Content: geminiContent{Role: "model", Parts: parts},
		}},
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
