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
	"bytes"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Chat Completions API typed structs
// ---------------------------------------------------------------------------

type openaiRequest struct {
	Model                string                 `json:"model,omitempty"`
	Messages             []openaiMessage        `json:"messages"`
	MaxTokens            *int                   `json:"max_tokens,omitempty"`
	MaxCompletionTokens  *int                   `json:"max_completion_tokens,omitempty"`
	Temperature          *float64               `json:"temperature,omitempty"`
	TopP                 *float64               `json:"top_p,omitempty"`
	TopK                 *int                   `json:"top_k,omitempty"`
	Stream               *bool                  `json:"stream,omitempty"`
	Stop                 json.RawMessage        `json:"stop,omitempty"` // string or []string
	Seed                 *int64                 `json:"seed,omitempty"`
	ResponseFormat       *openaiChatRespFormat  `json:"response_format,omitempty"`
	ParallelToolCalls    *bool                  `json:"parallel_tool_calls,omitempty"`
	Tools                []openaiTool           `json:"tools,omitempty"`
	ToolChoice           json.RawMessage        `json:"tool_choice,omitempty"` // string or object
	PromptCacheKey       string                 `json:"prompt_cache_key,omitempty"`
	PromptCacheRetention string                 `json:"prompt_cache_retention,omitempty"`
	PromptCacheOptions   json.RawMessage        `json:"prompt_cache_options,omitempty"`
	CacheControl         *anthropicCacheControl `json:"cache_control,omitempty"`
	Store                json.RawMessage        `json:"store,omitempty"`
}

// chatCarriedKeys are the Chat keys a re-encode carries through
// RequestExtensions, as responsesCarriedKeys are for Responses. metadata may
// hold personal data and is left out.
var chatCarriedKeys = []string{"store"}

type openaiMessage struct {
	Role       string           `json:"role"`
	Content    json.RawMessage  `json:"content,omitempty"` // string or []contentPart
	Refusal    *string          `json:"refusal,omitempty"`
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openaiContentPart struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	Refusal  string          `json:"refusal,omitempty"`
	ImageURL json.RawMessage `json:"image_url,omitempty"`
	// CacheControl is the OpenRouter and Anthropic-compatible marker on Chat
	// parts; PromptCacheBreakpoint is the Responses marker on input parts.
	CacheControl          *anthropicCacheControl       `json:"cache_control,omitempty"`
	PromptCacheBreakpoint *openaiPromptCacheBreakpoint `json:"prompt_cache_breakpoint,omitempty"`
}

type openaiPromptCacheBreakpoint struct {
	Mode string `json:"mode"`
}

func openAIPartCacheControl(p openaiContentPart) *CanonicalCacheBreakpoint {
	return anthropicCacheBreakpoint(p.CacheControl)
}

type openaiImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

type openaiTool struct {
	Type         string                 `json:"type"`
	Function     *openaiFunction        `json:"function,omitempty"`
	Custom       *openaiCustomTool      `json:"custom,omitempty"`
	CacheControl *anthropicCacheControl `json:"cache_control,omitempty"`
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

// openaiRespFormat is the Responses API text.format, which carries the
// json_schema fields inline instead of under a json_schema object.
type openaiRespFormat struct {
	Type string `json:"type"`
	openaiJSONSchema
}

type openaiJSONSchema struct {
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

type openaiChatRespFormat struct {
	Type       string          `json:"type"`
	JSONSchema json.RawMessage `json:"json_schema,omitempty"`
}

const responseFormatJSONSchema = "json_schema"

// encodeChatResponseFormat returns nil for a json_schema format without its
// schema, which OpenAI-compatible targets reject.
func encodeChatResponseFormat(f *CanonicalRespFormat) *openaiChatRespFormat {
	if f == nil || (f.Type == responseFormatJSONSchema && isEmptyJSON(f.JSONSchema)) {
		return nil
	}
	return &openaiChatRespFormat{Type: f.Type, JSONSchema: f.JSONSchema}
}

func isEmptyJSON(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
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
	PromptCacheHitTokens    int                            `json:"prompt_cache_hit_tokens,omitempty"`
	PromptCacheMissTokens   int                            `json:"prompt_cache_miss_tokens,omitempty"`
}

type openaiPromptTokensDetails struct {
	CachedTokens     int `json:"cached_tokens"`
	CacheWriteTokens int `json:"cache_write_tokens,omitempty"`
}

type openaiCompletionTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

func openaiUsageToCanonical(u openaiUsage) *CanonicalUsage {
	in := max(u.PromptTokens, u.PromptCacheHitTokens+u.PromptCacheMissTokens)
	cu := newCanonicalUsage(in, u.CompletionTokens, u.TotalTokens)
	if cu == nil {
		return nil
	}
	cu.TotalTokens = max(cu.TotalTokens, cu.InputTokens+cu.OutputTokens)
	read, write := u.PromptCacheHitTokens, 0
	if d := u.PromptTokensDetails; d != nil {
		read, write = max(read, d.CachedTokens), d.CacheWriteTokens
	}
	if read+write > 0 {
		cu.setCache(read, write, 0)
	}
	if u.CompletionTokensDetails != nil {
		cu.ReasoningOutputTokens = u.CompletionTokensDetails.ReasoningTokens
	}
	return cu
}

// completionsUsage merges usage with x_groq.usage field-wise by max: Groq
// repeats usage under x_groq, and the max counts it once (ENG-1618).
func completionsUsage(usage *openaiUsage, xGroq json.RawMessage) *CanonicalUsage {
	var cu *CanonicalUsage
	if usage != nil {
		cu = openaiUsageToCanonical(*usage)
	}
	if len(xGroq) == 0 {
		return cu
	}
	var ext struct {
		Usage *openaiUsage `json:"usage"`
	}
	if err := json.Unmarshal(xGroq, &ext); err != nil || ext.Usage == nil {
		return cu
	}
	return MergeUsage(cu, openaiUsageToCanonical(*ext.Usage))
}

func openaiUsageFromCanonical(u *CanonicalUsage) *openaiUsage {
	if u == nil {
		return nil
	}
	out := &openaiUsage{
		PromptTokens:     u.InputTokens,
		CompletionTokens: u.OutputTokens,
		TotalTokens:      u.TotalTokens,
	}
	if u.CachedInputTokens+u.CacheWriteInputTokens > 0 {
		out.PromptTokensDetails = &openaiPromptTokensDetails{
			CachedTokens:     u.CachedInputTokens,
			CacheWriteTokens: u.CacheWriteInputTokens,
		}
	}
	if u.ReasoningOutputTokens > 0 {
		out.CompletionTokensDetails = &openaiCompletionTokensDetails{ReasoningTokens: u.ReasoningOutputTokens}
	}
	return out
}

type openaiStreamChunk struct {
	ID      string               `json:"id,omitempty"`
	Object  string               `json:"object"`
	Model   string               `json:"model,omitempty"`
	Choices []openaiStreamChoice `json:"choices"`
	Usage   *openaiUsage         `json:"usage,omitempty"`
	XGroq   json.RawMessage      `json:"x_groq,omitempty"`
	Error   json.RawMessage      `json:"error,omitempty"`
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

// openaiRequestIn reads seed and parallel_tool_calls raw so a value of the
// wrong type drops that field instead of failing the whole request.
type openaiRequestIn struct {
	openaiRequest
	Seed              json.RawMessage `json:"seed"`
	ParallelToolCalls json.RawMessage `json:"parallel_tool_calls"`
}

func decodeCompletionsRequest(body []byte) (*CanonicalRequest, error) {
	var in openaiRequestIn
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}
	req := in.openaiRequest

	cr := &CanonicalRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
	}
	carryRequestKeys(cr, chatCarriedKeys, []*json.RawMessage{&req.Store})

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
		cr.ResponseFormat = &CanonicalRespFormat{Type: req.ResponseFormat.Type, JSONSchema: req.ResponseFormat.JSONSchema}
	}
	cr.Seed, cr.ParallelToolCalls = decodeChatSeed(in.Seed), decodeOptionalBool(in.ParallelToolCalls)

	var system cacheTextJoin
	for _, m := range req.Messages {
		if m.Role == "system" || m.Role == "developer" {
			appendOpenAISystem(&system, m.Content, openAIPartCacheControl)
			continue
		}
		var text cacheTextJoin
		images := decodeOpenAIParts(m.Content, &text, openAIPartCacheControl, m.Role == "user")
		cm := CanonicalMessage{
			Role:       m.Role,
			Content:    text.String(),
			ToolCallID: m.ToolCallID,
			Cache:      text.breakpoint(),
		}
		if m.Role == "user" {
			cm.Images = images
		}
		for _, tc := range m.ToolCalls {
			cm.ToolCalls = append(cm.ToolCalls, decodeOpenAIToolCall(tc))
		}
		cr.Messages = append(cr.Messages, cm)
	}
	cr.System, cr.SystemCache = system.String(), system.breakpoint()

	for _, t := range req.Tools {
		switch {
		case t.Type == "custom" && t.Custom != nil:
			cr.Tools = append(cr.Tools, CanonicalTool{
				Kind:        ToolKindCustom,
				Name:        t.Custom.Name,
				Description: t.Custom.Description,
				Format:      t.Custom.Format,
				Cache:       anthropicCacheBreakpoint(t.CacheControl),
			})
		case t.Function != nil:
			cr.Tools = append(cr.Tools, CanonicalTool{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Schema:      t.Function.Parameters,
				Cache:       anthropicCacheBreakpoint(t.CacheControl),
			})
		}
	}

	cr.ToolChoice = decodeOpenAIToolChoice(req.ToolChoice)
	cr.CacheOptions = openAICacheOptions(req.PromptCacheKey, req.PromptCacheRetention, req.PromptCacheOptions)
	if auto := anthropicCacheBreakpoint(req.CacheControl); auto != nil {
		if cr.CacheOptions == nil {
			cr.CacheOptions = &CanonicalCacheOptions{}
		}
		cr.CacheOptions.Auto = auto
	}

	return cr, nil
}

// decodeChatSeed returns seed as an integer, taking integral floats such as
// 42.0 that JSON encoders emit for numbers, and nil for anything else.
func decodeChatSeed(raw json.RawMessage) *int64 {
	text := string(bytes.TrimSpace(raw))
	if text == "" || (text[0] != '-' && (text[0] < '0' || text[0] > '9')) {
		return nil
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return &n
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || f != math.Trunc(f) || f < math.MinInt64 || f >= math.MaxInt64 {
		return nil
	}
	n := int64(f)
	return &n
}

func decodeOptionalBool(raw json.RawMessage) *bool {
	var b *bool
	if json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return b
}

// ---------------------------------------------------------------------------
// Request: Encode (Canonical → Chat Completions)
// ---------------------------------------------------------------------------

func encodeOpenAIContent(text string, images []CanonicalImage, cache *CanonicalCacheBreakpoint) json.RawMessage {
	imageAt, onImage := cachedImageIndex(cache, len(images))
	if cache.onImage() && !onImage {
		cache = nil
	}
	if len(images) == 0 && cache == nil {
		return stringToContent(text)
	}
	parts := make([]openaiContentPart, 0, len(images)+2)
	for _, img := range images {
		imageURL, _ := json.Marshal(openaiImageURL{URL: img.dataURI(), Detail: img.Detail})
		parts = append(parts, openaiContentPart{Type: "image_url", ImageURL: imageURL})
	}
	if onImage {
		parts[imageAt].CacheControl = anthropicCacheControlFrom(cache)
		cache = nil
	}
	texts, placed := cachedTextParts(text, cache)
	first := len(parts)
	for _, t := range texts {
		parts = append(parts, openaiContentPart{Type: "text", Text: t})
	}
	if len(parts) == 0 {
		return stringToContent(text)
	}
	if cache != nil {
		at := len(parts) - 1
		if placed {
			at = first
		}
		parts[at].CacheControl = anthropicCacheControlFrom(cache)
	}
	b, _ := json.Marshal(parts)
	return b
}

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

	out.ResponseFormat = encodeChatResponseFormat(req.ResponseFormat)
	out.Seed = req.Seed
	carriedRequestKeys(req, chatCarriedKeys, []*json.RawMessage{&out.Store})

	if req.System != "" {
		out.Messages = append(out.Messages, openaiMessage{
			Role:    "system",
			Content: encodeOpenAIContent(req.System, nil, req.SystemCache),
		})
	}
	for _, m := range req.Messages {
		var images []CanonicalImage
		if m.Role == "user" {
			images = m.Images
		}
		content := encodeOpenAIContent(m.Content, images, m.Cache)
		msg := openaiMessage{
			Role:       m.Role,
			Content:    content,
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			msg.ToolCalls = append(msg.ToolCalls, encodeOpenAIToolCall(tc))
		}
		out.Messages = append(out.Messages, msg)
	}

	out.Tools = encodeCompletionsTools(req.Tools)

	dropped := len(req.Tools) > len(out.Tools)
	if req.ToolChoice != nil && (!dropped || !toolChoiceDangles(req.ToolChoice, out.Tools)) {
		out.ToolChoice = encodeOpenAIToolChoice(req.ToolChoice)
	}
	if len(out.Tools) > 0 {
		out.ParallelToolCalls = req.ParallelToolCalls
	}
	if o := req.CacheOptions; o != nil {
		out.PromptCacheKey, out.PromptCacheRetention = o.Key, o.Retention
		out.PromptCacheOptions = o.openAIOptions()
		out.CacheControl = anthropicCacheControlFrom(o.Auto)
	}

	return json.Marshal(out)
}

func encodeCompletionsTools(tools []CanonicalTool) []openaiTool {
	var out []openaiTool
	for _, t := range tools {
		if strings.TrimSpace(t.Name) == "" {
			continue
		}
		if t.Kind == ToolKindCustom {
			out = append(out, openaiTool{
				Type: "custom",
				Custom: &openaiCustomTool{
					Name:        t.Name,
					Description: t.Description,
					Format:      t.Format,
				},
				CacheControl: anthropicCacheControlFrom(t.Cache),
			})
			continue
		}
		out = append(out, openaiTool{
			Type: "function",
			Function: &openaiFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Schema,
			},
			CacheControl: anthropicCacheControlFrom(t.Cache),
		})
	}
	return out
}

func toolChoiceDangles(tc *CanonicalToolChoice, kept []openaiTool) bool {
	if len(kept) == 0 {
		return true
	}
	if tc.Type != "tool" {
		return false
	}
	return !slices.ContainsFunc(kept, func(t openaiTool) bool {
		return (t.Function != nil && t.Function.Name == tc.Name) ||
			(t.Custom != nil && t.Custom.Name == tc.Name)
	})
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

	cr.Usage = completionsUsage(resp.Usage, resp.XGroq)

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

	out.Usage = openaiUsageFromCanonical(resp.Usage)

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

// decodeCompletionsStreamChunk decodes a Chat Completions chunk. A payload
// carrying an "error" is reported on the chunk's UpstreamError, alongside the
// content, finish and usage decoded from the rest of the payload, since
// OpenRouter sends the failure's finish_reason and usage with the error.
func decodeCompletionsStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var raw openaiStreamChunk
	if err := json.Unmarshal(chunk, &raw); err != nil {
		return nil, nil // skip non-JSON
	}
	upstreamErr := decodeStreamError(raw.Error)
	sc := decodeCompletionsStreamContent(&raw)
	switch {
	case upstreamErr == nil:
		return sc, nil
	case sc == nil:
		return &CanonicalStreamChunk{UpstreamError: upstreamErr}, nil
	default:
		sc.UpstreamError = upstreamErr
		return sc, nil
	}
}

func decodeCompletionsStreamContent(raw *openaiStreamChunk) *CanonicalStreamChunk {
	sc := &CanonicalStreamChunk{
		ID:    raw.ID,
		Model: raw.Model,
	}

	if len(raw.Choices) > 0 {
		choice := raw.Choices[0]
		delta := choice.Delta
		sc.Role = delta.Role
		sc.Delta = delta.Content
		sc.ReasoningDelta = delta.ReasoningContent
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

	sc.Usage = completionsUsage(raw.Usage, raw.XGroq)

	if raw.XGroq != nil {
		sc.ProviderExtensions = map[string]json.RawMessage{
			"x_groq": raw.XGroq,
		}
	}

	if sc.Delta == "" &&
		sc.ReasoningDelta == "" &&
		sc.Role == "" &&
		sc.FinishReason == "" &&
		len(sc.ToolCallDeltas) == 0 &&
		sc.Usage == nil &&
		len(sc.ProviderExtensions) == 0 {
		return nil
	}

	return sc
}

// ---------------------------------------------------------------------------
// Stream: Encode (Canonical → Chat Completions chunk)
// ---------------------------------------------------------------------------

// encodeCompletionsStreamChunk encodes chunk as a Chat Completions chunk. With
// emptyUsageChoices a usage-only chunk gets choices: [], the OpenAI
// include_usage shape; Mistral clients keep the single empty choice.
func encodeCompletionsStreamChunk(chunk *CanonicalStreamChunk, emptyUsageChoices bool) ([][]byte, error) {
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
	if emptyUsageChoices && chunk.Usage != nil && chunk.FinishReason == "" && chunk.Role == "" && chunk.Delta == "" &&
		chunk.ReasoningDelta == "" && len(chunk.ToolCallDeltas) == 0 {
		out.Choices = []openaiStreamChoice{}
	}

	out.Usage = openaiUsageFromCanonical(chunk.Usage)

	if raw, ok := chunk.ProviderExtensions["x_groq"]; ok && len(raw) > 0 {
		out.XGroq = raw
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return SSEData(data), nil
}
