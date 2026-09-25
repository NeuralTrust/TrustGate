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

// Not the 64000 model ceiling: lower-ceiling models reject larger values, and a longer generation outlives the proxy read timeout.
const defaultAnthropicMaxTokens = 8192

// AnthropicAdapter converts between Anthropic Messages API format and the
// canonical internal model.
type AnthropicAdapter struct{}

// Provider-specific typed structs
type anthropicRequest struct {
	Model        string                 `json:"model,omitempty"`
	System       json.RawMessage        `json:"system,omitempty"`
	Messages     []anthropicMessage     `json:"messages"`
	MaxTokens    int                    `json:"max_tokens"`
	Temperature  *float64               `json:"temperature,omitempty"`
	TopP         *float64               `json:"top_p,omitempty"`
	TopK         *int                   `json:"top_k,omitempty"`
	Stream       *bool                  `json:"stream,omitempty"`
	StopSeqs     []string               `json:"stop_sequences,omitempty"`
	Tools        []anthropicTool        `json:"tools,omitempty"`
	ToolChoice   *anthropicToolChoice   `json:"tool_choice,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CacheControl *anthropicCacheControl `json:"cache_control,omitempty"`
}

type anthropicCacheControl struct {
	Type string `json:"type"`
	TTL  string `json:"ttl,omitempty"`
}

func anthropicCacheBreakpoint(cc *anthropicCacheControl) *CanonicalCacheBreakpoint {
	if cc == nil {
		return nil
	}
	return &CanonicalCacheBreakpoint{TTL: CacheTTL(cc.TTL)}
}

func anthropicCacheControlFrom(bp *CanonicalCacheBreakpoint) *anthropicCacheControl {
	if bp == nil {
		return nil
	}
	return &anthropicCacheControl{Type: "ephemeral", TTL: string(bp.TTL)}
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string or []anthropicContentBlock
}

// anthropicTool is used when decoding requests (supports flat and type+custom).
type anthropicTool struct {
	Type         string                 `json:"type,omitempty"`
	Custom       *anthropicToolCustom   `json:"custom,omitempty"`
	Name         string                 `json:"name,omitempty"`
	Description  string                 `json:"description,omitempty"`
	InputSchema  map[string]interface{} `json:"input_schema,omitempty"`
	CacheControl *anthropicCacheControl `json:"cache_control,omitempty"`
}

// anthropicToolCustom is the nested shape required by the API for custom tools (encode).
type anthropicToolCustom struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

type anthropicToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

type anthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Model        string                  `json:"model"`
	Content      []anthropicContentBlock `json:"content"`
	StopReason   string                  `json:"stop_reason"`
	StopSequence *string                 `json:"stop_sequence"` // null or the matched stop sequence
	Usage        *anthropicUsage         `json:"usage,omitempty"`
}

type anthropicContentBlock struct {
	Type         string                 `json:"type"`
	Text         string                 `json:"text,omitempty"`
	Thinking     string                 `json:"thinking,omitempty"`  // extended thinking block content
	Signature    string                 `json:"signature,omitempty"` // thinking block signature
	ID           string                 `json:"id,omitempty"`
	Name         string                 `json:"name,omitempty"`
	Input        json.RawMessage        `json:"input,omitempty"`
	ToolUseID    string                 `json:"tool_use_id,omitempty"` // user message: tool_result block
	Content      json.RawMessage        `json:"content,omitempty"`     // tool_result content: string or blocks
	IsError      bool                   `json:"is_error,omitempty"`
	Source       json.RawMessage        `json:"source,omitempty"`
	CacheControl *anthropicCacheControl `json:"cache_control,omitempty"`
}

type anthropicImageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type,omitempty"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

type anthropicUsage struct {
	InputTokens              int                     `json:"input_tokens"`
	OutputTokens             int                     `json:"output_tokens"`
	CacheCreationInputTokens int                     `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int                     `json:"cache_read_input_tokens,omitempty"`
	CacheCreation            *anthropicCacheCreation `json:"cache_creation,omitempty"`
	ServiceTier              string                  `json:"service_tier,omitempty"`
	InferenceGeo             string                  `json:"inference_geo,omitempty"`
}

type anthropicCacheCreation struct {
	Ephemeral5mInputTokens int `json:"ephemeral_5m_input_tokens"`
	Ephemeral1hInputTokens int `json:"ephemeral_1h_input_tokens"`
}

// anthropicUsageToCanonical converts the Anthropic wire usage struct (used by
// both DecodeResponse and stream events) into the canonical view. Anthropic
// does not emit a total — the factory synthesizes in+out.
func anthropicUsageToCanonical(u anthropicUsage) *CanonicalUsage {
	cu := newCanonicalUsage(
		u.InputTokens+u.CacheReadInputTokens+u.CacheCreationInputTokens,
		u.OutputTokens,
		0,
	)
	if cu == nil {
		return nil
	}
	var write1h int
	if u.CacheCreation != nil {
		write1h = u.CacheCreation.Ephemeral1hInputTokens
		cu.cacheTTLKnown = true
	}
	cu.setCache(u.CacheReadInputTokens, u.CacheCreationInputTokens, write1h)
	cu.ServiceTier = u.ServiceTier
	return cu
}

func anthropicWireInputTokens(u *CanonicalUsage) int {
	return u.PlainInputTokens()
}

func anthropicCacheCreationFrom(u *CanonicalUsage) *anthropicCacheCreation {
	if !u.hasCacheTTLBreakdown() {
		return nil
	}
	write1h := min(u.CacheWrite1hInputTokens, u.CacheWriteInputTokens)
	return &anthropicCacheCreation{
		Ephemeral5mInputTokens: u.CacheWriteInputTokens - write1h,
		Ephemeral1hInputTokens: write1h,
	}
}

// anthropicSSEUsageFrom builds the on-wire usage block for a stream chunk.
// Returns the zero value when chunk.Usage is nil so omitempty fields stay absent.
func anthropicSSEUsageFrom(u *CanonicalUsage) anthropicSSEUsage {
	if u == nil {
		return anthropicSSEUsage{}
	}
	return anthropicSSEUsage{
		InputTokens:              anthropicWireInputTokens(u),
		OutputTokens:             u.OutputTokens,
		CacheCreationInputTokens: u.CacheWriteInputTokens,
		CacheReadInputTokens:     u.CachedInputTokens,
		CacheCreation:            anthropicCacheCreationFrom(u),
	}
}

// Stream event types — Decode (incoming)

type anthropicStreamEvent struct {
	Type         string          `json:"type"`
	Message      json.RawMessage `json:"message,omitempty"`
	Delta        json.RawMessage `json:"delta,omitempty"`
	Index        int             `json:"index,omitempty"`
	ContentBlock json.RawMessage `json:"content_block,omitempty"`
	Usage        *anthropicUsage `json:"usage,omitempty"`
}

type anthropicMessageStart struct {
	ID    string          `json:"id"`
	Model string          `json:"model"`
	Role  string          `json:"role"`
	Usage *anthropicUsage `json:"usage,omitempty"`
}

type anthropicDelta struct {
	Type        string `json:"type,omitempty"`
	Text        string `json:"text,omitempty"`
	Thinking    string `json:"thinking,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"` // for input_json_delta (tool_use streaming)
	StopReason  string `json:"stop_reason,omitempty"`
}

// Stream event types — Encode (outgoing, faithful to Anthropic API)

type anthropicSSEMessageStartPayload struct {
	Type    string                  `json:"type"`
	Message anthropicSSEMessageInfo `json:"message"`
}

type anthropicSSEMessageInfo struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Role         string            `json:"role"`
	Content      []interface{}     `json:"content"`
	Model        string            `json:"model"`
	StopReason   *string           `json:"stop_reason"`
	StopSequence *string           `json:"stop_sequence"`
	Usage        anthropicSSEUsage `json:"usage"`
}

type anthropicSSEUsage struct {
	InputTokens              int                     `json:"input_tokens"`
	OutputTokens             int                     `json:"output_tokens"`
	CacheCreationInputTokens int                     `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int                     `json:"cache_read_input_tokens,omitempty"`
	CacheCreation            *anthropicCacheCreation `json:"cache_creation,omitempty"`
}

type anthropicSSEContentBlockDelta struct {
	Type  string         `json:"type"`
	Index int            `json:"index"`
	Delta anthropicDelta `json:"delta"`
}

type anthropicSSEContentBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type anthropicSSEMessageDelta struct {
	Type  string                       `json:"type"`
	Delta anthropicSSEMessageDeltaBody `json:"delta"`
	Usage anthropicSSEUsage            `json:"usage"`
}

type anthropicSSEMessageDeltaBody struct {
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
}

type anthropicSSESimple struct {
	Type string `json:"type"`
}

// decodeAnthropicMessageContent turns one Anthropic message into one or more canonical
// messages. User messages with content blocks of type "tool_result" become separate
// canonical messages with Role="tool" so the target (e.g. OpenAI) receives proper
// tool result messages; without this, tool results are lost and the model never sees
// them (causing repeated tool calls / loops).
func decodeAnthropicMessageContent(role string, content json.RawMessage) []CanonicalMessage {
	if content == nil {
		return []CanonicalMessage{{Role: role, Content: ""}}
	}
	// Plain string
	var s string
	if json.Unmarshal(content, &s) == nil {
		return []CanonicalMessage{{Role: role, Content: s}}
	}
	// Array of content blocks
	var blocks []anthropicContentBlock
	if json.Unmarshal(content, &blocks) != nil {
		return []CanonicalMessage{{Role: role, Content: contentToString(content)}}
	}
	var out []CanonicalMessage
	var text cacheTextJoin
	switch role {
	case "user":
		var images []CanonicalImage
		var toolMessages []CanonicalMessage
		for i, b := range blocks {
			last := i == len(blocks)-1
			switch b.Type {
			case "image":
				if img, ok := anthropicImageToCanonical(b.Source); ok {
					images = append(images, img)
					text.addImage()
					text.markImage(anthropicCacheBreakpoint(b.CacheControl), last)
				}
			case "tool_result":
				content := anthropicToolResultText(b.Content)
				if b.IsError && content != "" {
					content = "error: " + content
				}
				cache := anthropicCacheBreakpoint(b.CacheControl)
				if cache != nil {
					cache.clientLast = last
				}
				toolMessages = append(toolMessages, CanonicalMessage{
					Role:       "tool",
					ToolCallID: b.ToolUseID,
					Content:    content,
					Cache:      cache,
				})
			case "text":
				text.add(b.Text)
				text.markText(anthropicCacheBreakpoint(b.CacheControl), last)
			}
		}
		out = append(out, toolMessages...)
		if len(text.parts) > 0 || len(images) > 0 {
			out = append(out, CanonicalMessage{
				Role:    "user",
				Content: text.String(),
				Images:  images,
				Cache:   text.breakpoint(),
			})
		}
	case "assistant":
		var toolCalls []CanonicalToolCall
		for i, b := range blocks {
			last := i == len(blocks)-1
			switch b.Type {
			case "text":
				text.add(b.Text)
				text.markText(anthropicCacheBreakpoint(b.CacheControl), last)
			case "tool_use":
				toolCalls = append(toolCalls, CanonicalToolCall{
					ID:        b.ID,
					Name:      b.Name,
					Arguments: string(b.Input),
				})
				text.markEnd(anthropicCacheBreakpoint(b.CacheControl), last)
			}
		}
		out = append(out, CanonicalMessage{
			Role:      "assistant",
			Content:   text.String(),
			ToolCalls: toolCalls,
			Cache:     text.breakpoint(),
		})
	default:
		out = append(out, CanonicalMessage{
			Role:    role,
			Content: contentToString(content),
		})
	}
	return out
}

func anthropicTextBlocks(text string, bp *CanonicalCacheBreakpoint) ([]anthropicContentBlock, bool) {
	parts, placed := cachedTextParts(text, bp)
	if len(parts) == 0 {
		return nil, false
	}
	blocks := make([]anthropicContentBlock, 0, len(parts))
	for _, part := range parts {
		blocks = append(blocks, anthropicContentBlock{Type: "text", Text: part})
	}
	if placed {
		blocks[0].CacheControl = anthropicCacheControlFrom(bp)
	}
	return blocks, placed
}

func anthropicImageToCanonical(raw json.RawMessage) (CanonicalImage, bool) {
	var src anthropicImageSource
	if len(raw) == 0 || json.Unmarshal(raw, &src) != nil {
		return CanonicalImage{}, false
	}
	switch src.Type {
	case "base64":
		if src.Data == "" {
			return CanonicalImage{}, false
		}
		return CanonicalImage{MediaType: normalizeImageMediaType(src.MediaType), Data: src.Data}, true
	case "url":
		if src.URL == "" {
			return CanonicalImage{}, false
		}
		return CanonicalImage{URL: src.URL}, true
	default:
		return CanonicalImage{}, false
	}
}

func anthropicImageBlock(img CanonicalImage) (anthropicContentBlock, error) {
	src := anthropicImageSource{Type: "base64", MediaType: img.MediaType, Data: img.Data}
	if img.Data == "" {
		if !isHTTPImageURL(img.URL) {
			return anthropicContentBlock{}, &UnsupportedContentError{Reason: "image must be inline base64 data or an http(s) URL"}
		}
		src = anthropicImageSource{Type: "url", URL: img.URL}
	}
	raw, err := json.Marshal(src)
	if err != nil {
		return anthropicContentBlock{}, err
	}
	return anthropicContentBlock{Type: "image", Source: raw}, nil
}

func anthropicMessageBlocks(m CanonicalMessage) ([]anthropicContentBlock, error) {
	images := m.Images
	if m.Role != "user" {
		images = nil
	}
	if len(images) == 0 && (m.Cache == nil || m.Content == "") {
		return nil, nil
	}
	blocks := make([]anthropicContentBlock, 0, len(images)+2)
	for _, img := range images {
		b, err := anthropicImageBlock(img)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
	}
	cache := m.Cache
	if cache.onImage() {
		if at, ok := cachedImageIndex(cache, len(images)); ok {
			blocks[at].CacheControl = anthropicCacheControlFrom(cache)
		}
		cache = nil
	}
	text, placed := anthropicTextBlocks(m.Content, cache)
	blocks = append(blocks, text...)
	if !placed && cache != nil {
		blocks[len(blocks)-1].CacheControl = anthropicCacheControlFrom(cache)
	}
	return blocks, nil
}

// anthropicMessages sends tool results as tool_result blocks of one user
// message and tool calls as tool_use blocks after the assistant text, so
// Anthropic can match each tool_result to the previous message's tool_use.
func anthropicMessages(msgs []CanonicalMessage, opts *CanonicalCacheOptions) ([]anthropicMessage, error) {
	type turn struct {
		role   string
		text   string
		blocks []anthropicContentBlock
		cache  *CanonicalCacheBreakpoint
	}
	turns := make([]turn, 0, len(msgs))
	for i := 0; i < len(msgs); i++ {
		m := msgs[i]
		switch {
		case m.Role == "tool":
			var blocks []anthropicContentBlock
			for ; i < len(msgs) && msgs[i].Role == "tool"; i++ {
				content, _ := json.Marshal(msgs[i].Content)
				blocks = append(blocks, anthropicContentBlock{
					Type:         "tool_result",
					ToolUseID:    msgs[i].ToolCallID,
					Content:      content,
					CacheControl: anthropicCacheControlFrom(msgs[i].Cache),
				})
			}
			i--
			turns = append(turns, turn{role: "user", blocks: blocks, cache: msgs[i].Cache})
		case m.Role == "assistant" && len(m.ToolCalls) > 0:
			blocks, placed := anthropicTextBlocks(m.Content, m.Cache)
			for _, tc := range m.ToolCalls {
				blocks = append(blocks, anthropicContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Name,
					Input: anthropicToolInput(tc.Arguments),
				})
			}
			if !placed {
				blocks[len(blocks)-1].CacheControl = anthropicCacheControlFrom(m.Cache)
			}
			turns = append(turns, turn{role: "assistant", blocks: blocks, cache: m.Cache})
		default:
			blocks, err := anthropicMessageBlocks(m)
			if err != nil {
				return nil, err
			}
			turns = append(turns, turn{role: m.Role, text: m.Content, blocks: blocks, cache: m.Cache})
		}
	}
	if n := len(turns); n > 0 && opts != nil {
		dropCacheControlConflictingWithAuto(turns[n-1].blocks, turns[n-1].cache, opts.Auto)
	}

	out := make([]anthropicMessage, 0, len(turns))
	for _, t := range turns {
		content := stringToContent(t.text)
		if t.blocks != nil {
			raw, err := json.Marshal(t.blocks)
			if err != nil {
				return nil, fmt.Errorf("encode anthropic %s message: %w", t.role, err)
			}
			content = raw
		}
		out = append(out, anthropicMessage{Role: t.role, Content: content})
	}
	return out, nil
}

// dropCacheControlConflictingWithAuto removes an explicit marker from the last
// block when top-level automatic caching puts a different TTL on that same
// block, a pair Anthropic answers with 400, but only when the gateway put it
// there: a fallback from its block boundary, a TTL raised by merging markers,
// or a marker a plugin added. A raised TTL goes back to the one the client
// sent on that block when that one does not conflict. A client that sent the
// pair itself gets the same answer as on passthrough.
func dropCacheControlConflictingWithAuto(blocks []anthropicContentBlock, cache, auto *CanonicalCacheBreakpoint) {
	if auto == nil || len(blocks) == 0 || (cache != nil && cache.clientLast) {
		return
	}
	last := &blocks[len(blocks)-1]
	autoTTL := anthropicEffectiveTTL(auto.TTL)
	if last.CacheControl == nil || anthropicEffectiveTTL(CacheTTL(last.CacheControl.TTL)) == autoTTL {
		return
	}
	if cache != nil && cache.raisedLast && anthropicEffectiveTTL(cache.clientTTL) == autoTTL {
		last.CacheControl = anthropicCacheControlFrom(&CanonicalCacheBreakpoint{TTL: cache.clientTTL})
		return
	}
	last.CacheControl = nil
}

func anthropicEffectiveTTL(ttl CacheTTL) CacheTTL {
	if ttl == "" {
		return CacheTTL5m
	}
	return ttl
}

// Request: Decode (Anthropic → Canonical)

func (a *AnthropicAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	system, systemCache := anthropicSystem(req.System)
	cr := &CanonicalRequest{
		Model:       req.Model,
		System:      system,
		SystemCache: systemCache,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
		Stop:        req.StopSeqs,
		Metadata:    req.Metadata,
	}

	if req.Stream != nil {
		cr.Stream = *req.Stream
	}
	if auto := anthropicCacheBreakpoint(req.CacheControl); auto != nil {
		cr.CacheOptions = &CanonicalCacheOptions{Auto: auto}
	}

	// Messages: decode content blocks so tool_result (user) and tool_use (assistant) are preserved
	for _, m := range req.Messages {
		cr.Messages = append(cr.Messages, decodeAnthropicMessageContent(m.Role, m.Content)...)
	}

	// Tools (support both flat and type+custom shapes)
	for _, t := range req.Tools {
		name, desc, schema := t.Name, t.Description, t.InputSchema
		if t.Custom != nil {
			name, desc, schema = t.Custom.Name, t.Custom.Description, t.Custom.InputSchema
		}
		cr.Tools = append(cr.Tools, CanonicalTool{
			Name:        name,
			Description: desc,
			Schema:      schema,
			Cache:       anthropicCacheBreakpoint(t.CacheControl),
		})
	}

	// ToolChoice
	if req.ToolChoice != nil {
		cr.ToolChoice = &CanonicalToolChoice{
			Type: req.ToolChoice.Type,
			Name: req.ToolChoice.Name,
		}
	}

	return cr, nil
}

// Request: Encode (Canonical → Anthropic)

func (a *AnthropicAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := anthropicRequest{
		Model:       req.Model,
		System:      anthropicSystemRaw(req.System, req.SystemCache),
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
		StopSeqs:    req.Stop,
		Metadata:    req.Metadata,
	}

	if req.Stream {
		out.Stream = boolPtr(true)
	}
	if req.CacheOptions != nil {
		out.CacheControl = anthropicCacheControlFrom(req.CacheOptions.Auto)
	}

	// max_tokens (required by Anthropic)
	if req.MaxTokens > 0 {
		out.MaxTokens = req.MaxTokens
	} else {
		out.MaxTokens = defaultAnthropicMaxTokens
	}

	messages, err := anthropicMessages(req.Messages, req.CacheOptions)
	if err != nil {
		return nil, err
	}
	out.Messages = messages

	// Tools: use flat format (name, input_schema, description at top level) — matches working Anthropic requests
	for i, t := range req.Tools {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = fmt.Sprintf("tool_%d", i)
		}
		schema := t.Schema
		if len(schema) == 0 {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		out.Tools = append(out.Tools, anthropicTool{
			Name:         name,
			Description:  t.Description,
			InputSchema:  schema,
			CacheControl: anthropicCacheControlFrom(t.Cache),
		})
	}

	// ToolChoice
	if req.ToolChoice != nil {
		tc := &anthropicToolChoice{
			Type: req.ToolChoice.Type,
			Name: req.ToolChoice.Name,
		}
		// Map "required" (OpenAI) → "any" (Anthropic)
		if tc.Type == "required" {
			tc.Type = "any"
		}
		out.ToolChoice = tc
	}

	return json.Marshal(out)
}

// Response: Decode (Anthropic response → Canonical)

func (a *AnthropicAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	cr := &CanonicalResponse{
		ID:    resp.ID,
		Model: resp.Model,
		Role:  "assistant",
	}

	// Content blocks (including extended thinking)
	var thinkingBlocks []string
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			cr.Content += block.Text
		case "thinking":
			if block.Thinking != "" {
				thinkingBlocks = append(thinkingBlocks, block.Thinking)
			}
		case "tool_use":
			cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
				ID:        block.ID,
				Name:      block.Name,
				Arguments: string(block.Input),
			})
		}
	}
	if len(thinkingBlocks) > 0 {
		cr.Reasoning = &CanonicalReasoning{
			ThinkingText: strings.Join(thinkingBlocks, "\n\n"),
		}
	}

	// stop_reason → finish_reason
	switch resp.StopReason {
	case "end_turn":
		cr.FinishReason = "stop"
	case "max_tokens":
		cr.FinishReason = "length"
	case "tool_use":
		cr.FinishReason = "tool_calls"
	default:
		cr.FinishReason = resp.StopReason
	}

	if resp.Usage != nil {
		cr.Usage = anthropicUsageToCanonical(*resp.Usage)
	}

	return cr, nil
}

// Response: Encode (Canonical → Anthropic response)

func (a *AnthropicAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	var content []anthropicContentBlock
	// Prepend thinking blocks if present (Anthropic extended thinking)
	if resp.Reasoning != nil && resp.Reasoning.ThinkingText != "" {
		content = append(content, anthropicContentBlock{
			Type:     "thinking",
			Thinking: resp.Reasoning.ThinkingText,
		})
	}
	if resp.Content != "" {
		content = append(content, anthropicContentBlock{
			Type: "text",
			Text: resp.Content,
		})
	}
	for _, tc := range resp.ToolCalls {
		content = append(content, anthropicContentBlock{
			Type:  "tool_use",
			ID:    tc.ID,
			Name:  tc.Name,
			Input: anthropicToolInput(tc.Arguments),
		})
	}

	out := anthropicResponse{
		ID:         resp.ID,
		Type:       "message",
		Role:       "assistant",
		Model:      resp.Model,
		Content:    content,
		StopReason: anthropicStopReason(resp.FinishReason),
	}

	if resp.Usage != nil {
		out.Usage = &anthropicUsage{
			InputTokens:              anthropicWireInputTokens(resp.Usage),
			OutputTokens:             resp.Usage.OutputTokens,
			CacheCreationInputTokens: resp.Usage.CacheWriteInputTokens,
			CacheReadInputTokens:     resp.Usage.CachedInputTokens,
			CacheCreation:            anthropicCacheCreationFrom(resp.Usage),
			ServiceTier:              resp.Usage.ServiceTier,
		}
	}

	return json.Marshal(out)
}

// Stream: Decode (Anthropic SSE event → Canonical)

func (a *AnthropicAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var event anthropicStreamEvent
	if err := json.Unmarshal(chunk, &event); err != nil {
		return nil, nil // skip non-JSON
	}

	switch event.Type {
	case "content_block_delta":
		var delta anthropicDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil {
			return nil, nil
		}
		if delta.Type == "text_delta" && delta.Text != "" {
			return &CanonicalStreamChunk{Delta: delta.Text}, nil
		}
		// Forwarded so the stream is not silent during the reasoning phase, which proxies close as idle.
		if delta.Type == "thinking_delta" && delta.Thinking != "" {
			return &CanonicalStreamChunk{ReasoningDelta: delta.Thinking}, nil
		}
		if delta.Type == "input_json_delta" {
			return &CanonicalStreamChunk{
				ToolCallDeltas: []StreamToolCallDelta{{
					Index:          event.Index,
					ArgumentsDelta: delta.PartialJSON,
				}},
			}, nil
		}
		return nil, nil

	case "content_block_start":
		if len(event.ContentBlock) == 0 {
			return nil, nil
		}
		var cb anthropicContentBlock
		if err := json.Unmarshal(event.ContentBlock, &cb); err != nil {
			return nil, nil
		}
		if cb.Type == "tool_use" {
			inputStr := strings.TrimSpace(string(cb.Input))
			// Anthropic sends "input": {} (empty object) in content_block_start; do not pass
			// "{}" as first delta or the OpenAI client merges "{}" + partial_json → invalid JSON.
			if inputStr == "" || inputStr == "{}" {
				inputStr = ""
			}
			return &CanonicalStreamChunk{
				ToolCallDeltas: []StreamToolCallDelta{{
					Index:          event.Index,
					ID:             cb.ID,
					Name:           cb.Name,
					ArgumentsDelta: inputStr,
				}},
			}, nil
		}
		return nil, nil // text/thinking block start: no delta yet, skip

	case "message_start":
		var msg anthropicMessageStart
		if err := json.Unmarshal(event.Message, &msg); err != nil {
			return nil, nil
		}
		sc := &CanonicalStreamChunk{
			ID:    msg.ID,
			Model: msg.Model,
			Role:  "assistant",
		}
		if msg.Usage != nil {
			sc.Usage = anthropicUsageToCanonical(*msg.Usage)
		}
		return sc, nil

	case "message_delta":
		var delta anthropicDelta
		if err := json.Unmarshal(event.Delta, &delta); err != nil {
			return nil, nil
		}
		sc := &CanonicalStreamChunk{}
		if delta.StopReason != "" {
			fr := delta.StopReason
			switch fr {
			case "end_turn":
				fr = "stop"
			case "max_tokens":
				fr = "length"
			case "tool_use":
				fr = "tool_calls"
			}
			sc.FinishReason = fr
		}
		if event.Usage != nil {
			sc.Usage = anthropicUsageToCanonical(*event.Usage)
		}
		if sc.FinishReason == "" && sc.Usage == nil {
			return nil, nil
		}
		return sc, nil

	default:
		return nil, nil // skip ping, message_stop, content_block_start, etc.
	}
}

// Stream: Encode (Canonical → Anthropic SSE event)
//
// Produces a faithful Anthropic SSE stream with event: lines, including the
// structural events that the Anthropic API emits (content_block_start,
// content_block_stop, message_stop, etc.).

// TODO(ENG-416): propagate ServiceTier through Anthropic stream events to SSE encode — deferred from ENG-417.
func emitToolUseBlocks(deltas []StreamToolCallDelta) [][]byte {
	var lines [][]byte
	for _, tc := range deltas {
		if tc.ID != "" || tc.Name != "" {
			lines = append(lines, anthropicToolUseBlockStartEvent(tc.Index, tc.ID, tc.Name)...)
		}
		if tc.ArgumentsDelta != "" {
			lines = append(lines, anthropicContentBlockDeltaEvent(tc.Index, anthropicBlockToolUse, tc.ArgumentsDelta)...)
		}
	}
	return lines
}

// EncodeStreamChunk encodes chunk on its own, as if the stream had a single
// text block at index 0. A stream with several blocks, tool calls or a finish
// that must close them needs an AnthropicStreamEncoder instead.
func (a *AnthropicAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	// --- message_start (when role is set) ------------------------------------
	if chunk.Role != "" {
		lines := anthropicMessageStartEvent(chunk.ID, chunk.Model, chunk.Usage)

		// If this chunk has tool_calls, emit tool_use block(s) instead of text block.
		if len(chunk.ToolCallDeltas) > 0 {
			lines = append(lines, emitToolUseBlocks(chunk.ToolCallDeltas)...)
		} else if chunk.Delta != "" {
			// Role + text in same chunk
			lines = append(lines, anthropicTextBlockStartEvent(0)...)
			lines = append(lines, anthropicContentBlockDeltaEvent(0, anthropicBlockText, chunk.Delta)...)
		} else {
			// Role only (text response will follow in next chunks)
			lines = append(lines, anthropicTextBlockStartEvent(0)...)
		}
		return lines, nil
	}

	// --- tool_call deltas only (no role in this chunk) -----------------------
	if len(chunk.ToolCallDeltas) > 0 {
		if lines := emitToolUseBlocks(chunk.ToolCallDeltas); len(lines) > 0 {
			return lines, nil
		}
	}

	// --- text content_block_delta --------------------------------------------
	if chunk.Delta != "" {
		return anthropicContentBlockDeltaEvent(0, anthropicBlockText, chunk.Delta), nil
	}

	// --- finish_reason → content_block_stop + message_delta + message_stop ----
	if chunk.FinishReason != "" {
		lines := anthropicContentBlockStopEvent(0)
		return append(lines, anthropicMessageEndEvents(chunk.FinishReason, chunk.Usage)...), nil
	}

	return nil, nil
}

// anthropicSystem keeps the system text byte-for-byte, as the OpenAI decoders
// do, so the same prompt reaches the upstream with the same cache prefix
// whichever client format sent it. Blank blocks are skipped because Anthropic
// rejects them: a marker on one moves to the text block before it, and a
// marker on a leading blank block is dropped, as it caches no text.
func anthropicSystem(raw json.RawMessage) (string, *CanonicalCacheBreakpoint) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if strings.TrimSpace(s) == "" {
			return "", nil
		}
		return s, nil
	}
	var blocks []anthropicContentBlock
	if json.Unmarshal(raw, &blocks) != nil {
		return contentToString(raw), nil
	}
	var text cacheTextJoin
	for _, b := range blocks {
		if b.Type != "" && b.Type != "text" {
			continue
		}
		if strings.TrimSpace(b.Text) != "" {
			text.add(b.Text)
		} else if len(text.parts) == 0 {
			continue
		}
		text.markText(anthropicCacheBreakpoint(b.CacheControl), false)
	}
	return text.String(), text.breakpoint()
}

func anthropicSystemRaw(system string, cache *CanonicalCacheBreakpoint) json.RawMessage {
	if strings.TrimSpace(system) == "" {
		return nil
	}
	var v any = system
	if cache != nil {
		blocks, placed := anthropicTextBlocks(system, cache)
		if !placed {
			blocks[len(blocks)-1].CacheControl = anthropicCacheControlFrom(cache)
		}
		v = blocks
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

func anthropicToolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []anthropicContentBlock
	if json.Unmarshal(raw, &blocks) == nil {
		parts := make([]string, 0, len(blocks))
		for _, b := range blocks {
			if b.Type == "text" || b.Type == "" {
				if t := strings.TrimSpace(b.Text); t != "" {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "\n")
	}
	return contentToString(raw)
}

// anthropicToolInput falls back to an empty object for arguments that are not
// a JSON object: Anthropic requires one, and invalid raw JSON would fail to
// marshal the whole message.
func anthropicToolInput(arguments string) json.RawMessage {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" {
		return json.RawMessage("{}")
	}
	if trimmed[0] != '{' || !json.Valid([]byte(trimmed)) {
		return json.RawMessage("{}")
	}
	return json.RawMessage(trimmed)
}
