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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// BedrockAdapter converts between the canonical model and the Bedrock Converse
// wire format. Converse is one request, response and stream schema for every
// model Bedrock hosts: AWS translates to the model's native shape server-side,
// so nothing here depends on which family sits behind a model ID. That is what
// makes a cross-region inference profile or an application inference profile
// ARN — identifiers that carry no family at all — work like a plain model ID.
type BedrockAdapter struct{}

// ConverseRequest is the body of a Converse or ConverseStream call, minus the
// model, which travels in the URL.
type ConverseRequest struct {
	Messages        []ConverseMessage        `json:"messages"`
	System          []ConverseSystemBlock    `json:"system,omitempty"`
	InferenceConfig *ConverseInferenceConfig `json:"inferenceConfig,omitempty"`
	ToolConfig      *ConverseToolConfig      `json:"toolConfig,omitempty"`
}

// ConverseMessage is one conversation turn. Roles are user and assistant only;
// system instructions ride in ConverseRequest.System.
type ConverseMessage struct {
	Role    string                 `json:"role"`
	Content []ConverseContentBlock `json:"content"`
}

// ConverseContentBlock is a tagged union: exactly one field is set.
type ConverseContentBlock struct {
	Text             string                    `json:"text,omitempty"`
	Image            *ConverseImageBlock       `json:"image,omitempty"`
	ToolUse          *ConverseToolUse          `json:"toolUse,omitempty"`
	ToolResult       *ConverseToolResult       `json:"toolResult,omitempty"`
	ReasoningContent *ConverseReasoningContent `json:"reasoningContent,omitempty"`
	CachePoint       *ConverseCachePoint       `json:"cachePoint,omitempty"`
}

// ConverseCachePoint marks the end of a prompt prefix Bedrock may cache. It is
// its own entry in content, system and tools, covering everything before it.
type ConverseCachePoint struct {
	Type string `json:"type"`
	TTL  string `json:"ttl,omitempty"`
}

// ConverseImageBlock is an inline image; Bedrock takes bytes only, never URLs.
type ConverseImageBlock struct {
	Format string              `json:"format"`
	Source ConverseImageSource `json:"source"`
}

// ConverseImageSource carries the raw image; encoding/json renders it as base64.
type ConverseImageSource struct {
	Bytes []byte `json:"bytes,omitempty"`
}

// ConverseSystemBlock is one system instruction.
type ConverseSystemBlock struct {
	Text         string                `json:"text,omitempty"`
	GuardContent *ConverseGuardContent `json:"guardContent,omitempty"`
	CachePoint   *ConverseCachePoint   `json:"cachePoint,omitempty"`
}

// ConverseGuardContent is content a guardrail assesses: text, with the
// qualifiers of the contextual grounding filter, or an image.
type ConverseGuardContent struct {
	Text  *ConverseGuardText  `json:"text,omitempty"`
	Image *ConverseImageBlock `json:"image,omitempty"`
}

// ConverseGuardText is the text of a guardContent block.
type ConverseGuardText struct {
	Text       string   `json:"text"`
	Qualifiers []string `json:"qualifiers,omitempty"`
}

// ConverseToolUse is a tool call requested by the model.
type ConverseToolUse struct {
	ToolUseID string          `json:"toolUseId"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

// ConverseToolResult carries the caller's answer to a ConverseToolUse.
type ConverseToolResult struct {
	ToolUseID string                      `json:"toolUseId"`
	Content   []ConverseToolResultContent `json:"content"`
	Status    string                      `json:"status,omitempty"`
}

// ConverseToolResultContent is a tagged union: exactly one field is set.
type ConverseToolResultContent struct {
	Text string          `json:"text,omitempty"`
	JSON json.RawMessage `json:"json,omitempty"`
}

// ConverseReasoningContent is a model's reasoning, either readable or redacted.
type ConverseReasoningContent struct {
	ReasoningText   *ConverseReasoningText `json:"reasoningText,omitempty"`
	RedactedContent []byte                 `json:"redactedContent,omitempty"`
}

// ConverseReasoningText is readable reasoning plus the signature some models
// need to accept it back in a later turn.
type ConverseReasoningText struct {
	Text      string `json:"text"`
	Signature string `json:"signature,omitempty"`
}

// ConverseInferenceConfig holds the sampling knobs Converse models for every
// family. Anything else is model-specific and has no place here.
type ConverseInferenceConfig struct {
	MaxTokens     int      `json:"maxTokens,omitempty"`
	Temperature   *float64 `json:"temperature,omitempty"`
	TopP          *float64 `json:"topP,omitempty"`
	StopSequences []string `json:"stopSequences,omitempty"`
}

// ConverseToolConfig declares the tools a model may call and how freely.
type ConverseToolConfig struct {
	Tools      []ConverseTool      `json:"tools"`
	ToolChoice *ConverseToolChoice `json:"toolChoice,omitempty"`
}

// ConverseTool is a tagged union: exactly one field is set.
type ConverseTool struct {
	ToolSpec   *ConverseToolSpec   `json:"toolSpec,omitempty"`
	CachePoint *ConverseCachePoint `json:"cachePoint,omitempty"`
}

// ConverseToolSpec describes one callable tool.
type ConverseToolSpec struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	InputSchema ConverseToolInputSchema `json:"inputSchema"`
}

// ConverseToolInputSchema wraps the JSON Schema of a tool's arguments.
type ConverseToolInputSchema struct {
	JSON map[string]interface{} `json:"json"`
}

// ConverseToolChoice is a tagged union: exactly one field is set.
type ConverseToolChoice struct {
	Auto *ConverseEmpty        `json:"auto,omitempty"`
	Any  *ConverseEmpty        `json:"any,omitempty"`
	Tool *ConverseSpecificTool `json:"tool,omitempty"`
}

// ConverseEmpty is the {} payload of the parameterless tool-choice members.
type ConverseEmpty struct{}

// ConverseSpecificTool forces one named tool.
type ConverseSpecificTool struct {
	Name string `json:"name"`
}

// ConverseResponse is the body of a buffered Converse answer.
type ConverseResponse struct {
	Output     ConverseOutput   `json:"output"`
	StopReason string           `json:"stopReason"`
	Usage      *ConverseUsage   `json:"usage,omitempty"`
	Metrics    *ConverseMetrics `json:"metrics,omitempty"`
}

// ConverseOutput wraps the assistant turn of a ConverseResponse.
type ConverseOutput struct {
	Message *ConverseMessage `json:"message,omitempty"`
}

// ConverseUsage is the token accounting Converse reports for every family.
type ConverseUsage struct {
	InputTokens           int `json:"inputTokens"`
	OutputTokens          int `json:"outputTokens"`
	TotalTokens           int `json:"totalTokens"`
	CacheReadInputTokens  int `json:"cacheReadInputTokens,omitempty"`
	CacheWriteInputTokens int `json:"cacheWriteInputTokens,omitempty"`

	CacheDetails []ConverseCacheDetail `json:"cacheDetails,omitempty"`
}

// ConverseCacheDetail is the share of cacheWriteInputTokens written with one TTL.
type ConverseCacheDetail struct {
	InputTokens int    `json:"inputTokens"`
	TTL         string `json:"ttl"`
}

// ConverseMetrics is the latency Bedrock measured for the call.
type ConverseMetrics struct {
	LatencyMs int64 `json:"latencyMs"`
}

// ConverseStreamEvent is one ConverseStream event, keyed by its type the way
// the Bedrock REST API frames it. Exactly one field is set.
type ConverseStreamEvent struct {
	MessageStart      *ConverseMessageStart      `json:"messageStart,omitempty"`
	ContentBlockStart *ConverseContentBlockStart `json:"contentBlockStart,omitempty"`
	ContentBlockDelta *ConverseContentBlockDelta `json:"contentBlockDelta,omitempty"`
	ContentBlockStop  *ConverseContentBlockStop  `json:"contentBlockStop,omitempty"`
	MessageStop       *ConverseMessageStop       `json:"messageStop,omitempty"`
	Metadata          *ConverseMetadata          `json:"metadata,omitempty"`
}

// ConverseMessageStart opens the assistant turn.
type ConverseMessageStart struct {
	Role string `json:"role"`
}

// ConverseContentBlockStart opens a content block; only tool-use blocks carry
// anything at this point.
type ConverseContentBlockStart struct {
	ContentBlockIndex int                     `json:"contentBlockIndex"`
	Start             ConverseBlockStartValue `json:"start"`
}

// ConverseBlockStartValue is a tagged union with a single member today.
type ConverseBlockStartValue struct {
	ToolUse *ConverseToolUseStart `json:"toolUse,omitempty"`
}

// ConverseToolUseStart names the tool whose arguments the following deltas
// stream in.
type ConverseToolUseStart struct {
	ToolUseID string `json:"toolUseId"`
	Name      string `json:"name"`
}

// ConverseContentBlockDelta appends to an open content block.
type ConverseContentBlockDelta struct {
	ContentBlockIndex int                `json:"contentBlockIndex"`
	Delta             ConverseDeltaValue `json:"delta"`
}

// ConverseDeltaValue is a tagged union: exactly one field is set.
type ConverseDeltaValue struct {
	Text             string                  `json:"text,omitempty"`
	ToolUse          *ConverseToolUseDelta   `json:"toolUse,omitempty"`
	ReasoningContent *ConverseReasoningDelta `json:"reasoningContent,omitempty"`
}

// ConverseToolUseDelta is a fragment of a tool call's JSON arguments.
type ConverseToolUseDelta struct {
	Input string `json:"input"`
}

// ConverseReasoningDelta is a fragment of the model's reasoning.
type ConverseReasoningDelta struct {
	Text            string `json:"text,omitempty"`
	Signature       string `json:"signature,omitempty"`
	RedactedContent []byte `json:"redactedContent,omitempty"`
}

// ConverseContentBlockStop closes a content block.
type ConverseContentBlockStop struct {
	ContentBlockIndex int `json:"contentBlockIndex"`
}

// ConverseMessageStop closes the assistant turn.
type ConverseMessageStop struct {
	StopReason string `json:"stopReason"`
}

// ConverseMetadata closes the stream with the token accounting.
type ConverseMetadata struct {
	Usage   *ConverseUsage   `json:"usage,omitempty"`
	Metrics *ConverseMetrics `json:"metrics,omitempty"`
}

const (
	converseRoleUser      = "user"
	converseRoleAssistant = "assistant"

	converseCacheTTL5m = "5m"
	converseCacheTTL1h = "1h"

	converseCachePointDefault = "default"
)

func (a *BedrockAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	// model and stream are not Converse keys — the gateway grafts them onto the
	// adapted body (EnforceModel, the stream flag) and plugins that decode it
	// expect to read them back.
	var req struct {
		ConverseRequest
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	cr := &CanonicalRequest{
		Model:    req.Model,
		Stream:   req.Stream,
		Messages: make([]CanonicalMessage, 0, len(req.Messages)),
	}
	cr.System, cr.SystemCache = converseSystemText(req.System)
	for _, m := range req.Messages {
		cr.Messages = append(cr.Messages, converseMessageToCanonical(m)...)
	}
	if ic := req.InferenceConfig; ic != nil {
		cr.MaxTokens = ic.MaxTokens
		cr.Temperature = ic.Temperature
		cr.TopP = ic.TopP
		cr.Stop = ic.StopSequences
	}
	if tc := req.ToolConfig; tc != nil {
		for _, t := range tc.Tools {
			if t.CachePoint != nil {
				if n := len(cr.Tools); n > 0 {
					cr.Tools[n-1].Cache = laterCacheBreakpoint(cr.Tools[n-1].Cache, converseCacheBreakpoint(t.CachePoint))
				}
				continue
			}
			if t.ToolSpec == nil {
				continue
			}
			cr.Tools = append(cr.Tools, CanonicalTool{
				Name:        t.ToolSpec.Name,
				Description: t.ToolSpec.Description,
				Schema:      t.ToolSpec.InputSchema.JSON,
			})
		}
		cr.ToolChoice = converseToolChoiceToCanonical(tc.ToolChoice)
	}
	return cr, nil
}

func converseCacheBreakpoint(cp *ConverseCachePoint) *CanonicalCacheBreakpoint {
	if cp == nil {
		return nil
	}
	return &CanonicalCacheBreakpoint{TTL: CacheTTL(cp.TTL)}
}

// converseCachePointFrom sends ttl only for 1h: omitting it is the 5m default,
// and it keeps the request valid on models that take no ttl at all.
func converseCachePointFrom(bp *CanonicalCacheBreakpoint) *ConverseCachePoint {
	if bp == nil {
		return nil
	}
	cp := &ConverseCachePoint{Type: converseCachePointDefault}
	if bp.TTL == CacheTTL1h {
		cp.TTL = converseCacheTTL1h
	}
	return cp
}

// converseSystemText joins the system blocks with "\n\n", spelled as an empty
// part between two "\n" joiners so a cachePoint keeps the newline index of the
// block it followed. Guarded text joins as plain text: the gateway sends no
// guardrailConfig.
func converseSystemText(blocks []ConverseSystemBlock) (string, *CanonicalCacheBreakpoint) {
	var (
		text   cacheTextJoin
		marked bool
	)
	for _, b := range blocks {
		if b.CachePoint != nil {
			if marked {
				bp := converseCacheBreakpoint(b.CachePoint)
				bp.joinerTail = 1
				text.markText(bp, false)
			}
			continue
		}
		part := b.Text
		if part == "" && b.GuardContent != nil && b.GuardContent.Text != nil {
			part = b.GuardContent.Text.Text
		}
		marked = part != ""
		if !marked {
			continue
		}
		if len(text.parts) > 0 {
			text.add("")
		}
		text.add(part)
	}
	return text.String(), text.breakpoint()
}

// converseMessageToCanonical splits one Converse turn into canonical messages:
// text and tool-use blocks fold into a single message, while every tool result
// becomes its own "tool" message placed first, so that on re-encoding the
// results still directly follow the assistant turn that requested them. Image
// blocks of a user turn go into Images; their order relative to the text is not
// kept, since the encoders always emit images first.
//
// The canonical model has no slot for reasoning blocks or structured tool
// results, so a round trip through it renders reasoning away and JSON results
// as text. Only bodies a plugin rewrites take that trip; a plain proxy pass
// never decodes the Converse body.
//
// Text blocks are joined with "\n", like the other decoders do, so a
// cachePoint after one of them keeps its block boundary. A cachePoint marks
// the block before it; after a block the canonical model drops, or first in
// the turn, it is dropped too.
func converseMessageToCanonical(m ConverseMessage) []CanonicalMessage {
	var (
		out  []CanonicalMessage
		turn = CanonicalMessage{Role: m.Role}
		text cacheTextJoin
		mark func(*CanonicalCacheBreakpoint, bool)
	)
	for i, b := range m.Content {
		if b.CachePoint != nil {
			if mark != nil {
				mark(converseCacheBreakpoint(b.CachePoint), i == len(m.Content)-1)
			}
			continue
		}
		mark = nil
		switch {
		case b.ToolResult != nil:
			content := converseToolResultText(b.ToolResult.Content)
			if b.ToolResult.Status == "error" && content != "" {
				content = "error: " + content
			}
			out = append(out, CanonicalMessage{
				Role:       "tool",
				ToolCallID: b.ToolResult.ToolUseID,
				Content:    content,
			})
			at := len(out) - 1
			mark = func(bp *CanonicalCacheBreakpoint, last bool) {
				bp.clientLast = last
				out[at].Cache = laterCacheBreakpoint(out[at].Cache, bp)
			}
		case b.Image != nil:
			if m.Role == converseRoleUser && len(b.Image.Source.Bytes) > 0 {
				turn.Images = append(turn.Images, CanonicalImage{
					MediaType: "image/" + b.Image.Format,
					Data:      base64.StdEncoding.EncodeToString(b.Image.Source.Bytes),
				})
				text.addImage()
				mark = text.markImage
			}
		case b.ToolUse != nil:
			turn.ToolCalls = append(turn.ToolCalls, CanonicalToolCall{
				ID:        b.ToolUse.ToolUseID,
				Name:      b.ToolUse.Name,
				Arguments: converseToolInputArguments(b.ToolUse.Input),
			})
			mark = text.markEnd
		case b.Text != "":
			text.add(b.Text)
			mark = text.markText
		}
	}
	turn.Content, turn.Cache = text.String(), text.breakpoint()
	if turn.Content != "" || len(turn.ToolCalls) > 0 || len(turn.Images) > 0 {
		out = append(out, turn)
	}
	return out
}

func converseToolResultText(content []ConverseToolResultContent) string {
	var sb strings.Builder
	for _, c := range content {
		if len(c.JSON) > 0 {
			sb.Write(c.JSON)
			continue
		}
		sb.WriteString(c.Text)
	}
	return sb.String()
}

func converseToolInputArguments(input json.RawMessage) string {
	if len(input) == 0 {
		return "{}"
	}
	return string(input)
}

func converseToolChoiceToCanonical(tc *ConverseToolChoice) *CanonicalToolChoice {
	switch {
	case tc == nil:
		return nil
	case tc.Tool != nil:
		return &CanonicalToolChoice{Type: "tool", Name: tc.Tool.Name}
	case tc.Any != nil:
		return &CanonicalToolChoice{Type: "any"}
	default:
		return &CanonicalToolChoice{Type: "auto"}
	}
}

func (a *BedrockAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := ConverseRequest{
		Messages: make([]ConverseMessage, 0, len(req.Messages)),
		System:   converseSystemBlocks(nil, req.System, req.SystemCache),
	}
	var lastCache *CanonicalCacheBreakpoint
	for _, m := range req.Messages {
		// Converse has no system turn; instructions found in the conversation
		// join the dedicated field rather than being dropped.
		if m.Role == "system" {
			out.System = converseSystemBlocks(out.System, m.Content, m.Cache)
			continue
		}
		msg, err := converseMessageFromCanonical(m)
		if err != nil {
			return nil, err
		}
		if len(msg.Content) > 0 {
			lastCache = m.Cache
		}
		out.Messages = appendConverseMessage(out.Messages, msg)
	}
	if o := req.CacheOptions; o != nil && o.Auto != nil {
		addConverseAutoCachePoint(out.Messages, lastCache, o.Auto)
	}
	out.InferenceConfig = converseInferenceConfigFrom(req)
	out.ToolConfig = converseToolConfigFrom(req)
	return json.Marshal(out)
}

// addConverseAutoCachePoint maps automatic caching onto a cachePoint after the
// last block of the last message, where Anthropic puts it. Bedrock rejects two
// cachePoints in a row, so an explicit one already there is kept once: with
// the client's TTL when the client sent it on its last block, otherwise with
// the automatic TTL, the way the Anthropic encoder settles that pair.
func addConverseAutoCachePoint(msgs []ConverseMessage, last, auto *CanonicalCacheBreakpoint) {
	n := len(msgs)
	if n == 0 {
		return
	}
	content := msgs[n-1].Content
	if k := len(content); k > 0 && content[k-1].CachePoint != nil {
		if last == nil || !last.clientLast {
			content[k-1].CachePoint = converseCachePointFrom(auto)
		}
		return
	}
	msgs[n-1].Content = append(content, ConverseContentBlock{CachePoint: converseCachePointFrom(auto)})
}

func converseSystemBlocks(system []ConverseSystemBlock, text string, bp *CanonicalCacheBreakpoint) []ConverseSystemBlock {
	if text == "" {
		return system
	}
	parts, placed := cachedTextParts(text, bp)
	for i, part := range parts {
		system = append(system, ConverseSystemBlock{Text: part})
		if i == 0 && placed {
			system = append(system, ConverseSystemBlock{CachePoint: converseCachePointFrom(bp)})
		}
	}
	if !placed && bp != nil {
		system = append(system, ConverseSystemBlock{CachePoint: converseCachePointFrom(bp)})
	}
	return system
}

// appendConverseMessage merges msg into the previous turn when both share a
// role. Converse requires user and assistant turns to alternate, and every tool
// result answering one assistant turn must arrive in the same user message. A
// turn with nothing to say is dropped: Bedrock rejects an empty content list.
func appendConverseMessage(msgs []ConverseMessage, msg ConverseMessage) []ConverseMessage {
	if len(msg.Content) == 0 {
		return msgs
	}
	if n := len(msgs); n > 0 && msgs[n-1].Role == msg.Role {
		msgs[n-1].Content = append(msgs[n-1].Content, msg.Content...)
		return msgs
	}
	return append(msgs, msg)
}

// converseMessageFromCanonical puts a cachePoint right after the block the
// breakpoint sat on: the marked image, the marked text block (split back out
// of the joined text) or the tool result. When that boundary is lost it goes
// last. A marker whose image is gone is dropped rather than moved onto the
// text after it.
func converseMessageFromCanonical(m CanonicalMessage) (ConverseMessage, error) {
	if m.Role == "tool" {
		blocks := []ConverseContentBlock{{ToolResult: &ConverseToolResult{
			ToolUseID: m.ToolCallID,
			Content:   []ConverseToolResultContent{{Text: m.Content}},
		}}}
		if m.Cache != nil {
			blocks = append(blocks, ConverseContentBlock{CachePoint: converseCachePointFrom(m.Cache)})
		}
		return ConverseMessage{Role: converseRoleUser, Content: blocks}, nil
	}
	role := converseRoleUser
	if m.Role == converseRoleAssistant {
		role = converseRoleAssistant
	}
	var images []CanonicalImage
	if m.Role == converseRoleUser {
		images = m.Images
	}
	cache := m.Cache
	imageAt := -1
	if cache.onImage() {
		if at, ok := cachedImageIndex(cache, len(images)); ok {
			imageAt = at
		}
	}
	blocks := make([]ConverseContentBlock, 0, len(images)+3+len(m.ToolCalls))
	for i, img := range images {
		block, err := converseImageFromCanonical(img)
		if err != nil {
			return ConverseMessage{}, err
		}
		blocks = append(blocks, ConverseContentBlock{Image: block})
		if i == imageAt {
			blocks = append(blocks, ConverseContentBlock{CachePoint: converseCachePointFrom(cache)})
		}
	}
	if cache.onImage() {
		cache = nil
	}
	parts, placed := cachedTextParts(m.Content, cache)
	for i, part := range parts {
		blocks = append(blocks, ConverseContentBlock{Text: part})
		if i == 0 && placed {
			blocks = append(blocks, ConverseContentBlock{CachePoint: converseCachePointFrom(cache)})
		}
	}
	for _, tc := range m.ToolCalls {
		blocks = append(blocks, ConverseContentBlock{ToolUse: &ConverseToolUse{
			ToolUseID: tc.ID,
			Name:      tc.Name,
			Input:     converseToolInput(tc.Arguments),
		}})
	}
	if !placed && cache != nil && len(blocks) > 0 {
		blocks = append(blocks, ConverseContentBlock{CachePoint: converseCachePointFrom(cache)})
	}
	return ConverseMessage{Role: role, Content: blocks}, nil
}

func converseImageFromCanonical(img CanonicalImage) (*ConverseImageBlock, error) {
	if img.Data == "" {
		return nil, &UnsupportedContentError{Reason: "image URLs are not supported by the target; send inline base64 image data"}
	}
	format, ok := converseImageFormat(img.MediaType)
	if !ok {
		return nil, &UnsupportedContentError{Reason: "image media type is missing or not an image/* type"}
	}
	raw, err := base64.StdEncoding.DecodeString(img.Data)
	if err != nil {
		return nil, &UnsupportedContentError{Reason: "image data is not valid base64"}
	}
	return &ConverseImageBlock{Format: format, Source: ConverseImageSource{Bytes: raw}}, nil
}

func converseImageFormat(mediaType string) (string, bool) {
	format, ok := strings.CutPrefix(mediaType, "image/")
	return format, ok && format != ""
}

// converseToolInput turns the canonical arguments string into the JSON object
// Converse requires. A model that streamed malformed arguments gets an empty
// object rather than a body Bedrock rejects wholesale.
func converseToolInput(arguments string) json.RawMessage {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" || trimmed[0] != '{' || !json.Valid([]byte(trimmed)) {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(trimmed)
}

// converseInferenceConfigFrom maps the sampling knobs Converse understands.
// TopK is deliberately absent: Converse only accepts it under the model's own
// name in additionalModelRequestFields, which would tie the encoder back to the
// family this adapter exists to stop caring about.
func converseInferenceConfigFrom(req *CanonicalRequest) *ConverseInferenceConfig {
	if req.MaxTokens <= 0 && req.Temperature == nil && req.TopP == nil && len(req.Stop) == 0 {
		return nil
	}
	return &ConverseInferenceConfig{
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		StopSequences: req.Stop,
	}
}

// converseToolConfigFrom declares the tools. A "none" choice has no Converse
// spelling, so it withholds the tools instead — the only way to guarantee the
// model calls nothing. The exception is a conversation that already carries
// tool calls or results: Bedrock rejects those blocks without a toolConfig, so
// the tools stay declared and the choice relaxes to auto, and a request with
// no tools at all declares a placeholder tool no caller implements.
func converseToolConfigFrom(req *CanonicalRequest) *ConverseToolConfig {
	if len(req.Tools) == 0 {
		if !conversationUsesTools(req.Messages) {
			return nil
		}
		return &ConverseToolConfig{Tools: []ConverseTool{{ToolSpec: &ConverseToolSpec{
			Name:        converseToolPlaceholder,
			Description: "No tools are available for this request. Do not call this tool.",
			InputSchema: ConverseToolInputSchema{JSON: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}},
		}}}}
	}
	choice := req.ToolChoice
	if choice != nil && choice.Type == "none" {
		if !conversationUsesTools(req.Messages) {
			return nil
		}
		choice = nil
	}
	cfg := &ConverseToolConfig{Tools: make([]ConverseTool, 0, len(req.Tools))}
	for i, t := range req.Tools {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = fmt.Sprintf("tool_%d", i)
		}
		schema := t.Schema
		if len(schema) == 0 {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		cfg.Tools = append(cfg.Tools, ConverseTool{ToolSpec: &ConverseToolSpec{
			Name:        name,
			Description: t.Description,
			InputSchema: ConverseToolInputSchema{JSON: schema},
		}})
		if t.Cache != nil {
			cfg.Tools = append(cfg.Tools, ConverseTool{CachePoint: converseCachePointFrom(t.Cache)})
		}
	}
	cfg.ToolChoice = converseToolChoiceFrom(choice)
	return cfg
}

// converseToolPlaceholder names the tool declared for a conversation that
// carries tool blocks but no tools, which Bedrock refuses without a
// toolConfig.
const converseToolPlaceholder = "no_tools_available"

func conversationUsesTools(msgs []CanonicalMessage) bool {
	for _, m := range msgs {
		if m.Role == "tool" || len(m.ToolCalls) > 0 {
			return true
		}
	}
	return false
}

func converseToolChoiceFrom(tc *CanonicalToolChoice) *ConverseToolChoice {
	if tc == nil {
		return nil
	}
	switch tc.Type {
	case "tool":
		return &ConverseToolChoice{Tool: &ConverseSpecificTool{Name: tc.Name}}
	case "any", "required":
		return &ConverseToolChoice{Any: &ConverseEmpty{}}
	default:
		return &ConverseToolChoice{Auto: &ConverseEmpty{}}
	}
}

func (a *BedrockAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp ConverseResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{
		Role:         converseRoleAssistant,
		FinishReason: converseFinishReason(resp.StopReason),
		Usage:        converseUsageToCanonical(resp.Usage),
	}
	if msg := resp.Output.Message; msg != nil {
		if msg.Role != "" {
			cr.Role = msg.Role
		}
		var thinking []string
		for _, b := range msg.Content {
			switch {
			case b.ToolUse != nil:
				cr.ToolCalls = append(cr.ToolCalls, CanonicalToolCall{
					ID:        b.ToolUse.ToolUseID,
					Name:      b.ToolUse.Name,
					Arguments: converseToolInputArguments(b.ToolUse.Input),
				})
			case b.ReasoningContent != nil && b.ReasoningContent.ReasoningText != nil:
				thinking = append(thinking, b.ReasoningContent.ReasoningText.Text)
			default:
				cr.Content += b.Text
			}
		}
		if len(thinking) > 0 {
			cr.Reasoning = &CanonicalReasoning{ThinkingText: strings.Join(thinking, "\n\n")}
		}
	}
	return cr, nil
}

func (a *BedrockAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	msg := &ConverseMessage{Role: converseRoleAssistant, Content: []ConverseContentBlock{}}
	if resp.Role != "" {
		msg.Role = resp.Role
	}
	if resp.Reasoning != nil && resp.Reasoning.ThinkingText != "" {
		msg.Content = append(msg.Content, ConverseContentBlock{ReasoningContent: &ConverseReasoningContent{
			ReasoningText: &ConverseReasoningText{Text: resp.Reasoning.ThinkingText},
		}})
	}
	if resp.Content != "" {
		msg.Content = append(msg.Content, ConverseContentBlock{Text: resp.Content})
	}
	for _, tc := range resp.ToolCalls {
		msg.Content = append(msg.Content, ConverseContentBlock{ToolUse: &ConverseToolUse{
			ToolUseID: tc.ID,
			Name:      tc.Name,
			Input:     converseToolInput(tc.Arguments),
		}})
	}
	return json.Marshal(ConverseResponse{
		Output:     ConverseOutput{Message: msg},
		StopReason: converseStopReason(resp.FinishReason, len(resp.ToolCalls) > 0),
		Usage:      converseUsageFromCanonical(resp.Usage),
	})
}

func (a *BedrockAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var ev ConverseStreamEvent
	if err := json.Unmarshal(chunk, &ev); err != nil {
		return nil, nil
	}
	switch {
	case ev.MessageStart != nil:
		return &CanonicalStreamChunk{Role: converseRoleAssistant}, nil
	case ev.ContentBlockStart != nil:
		start := ev.ContentBlockStart
		if start.Start.ToolUse == nil {
			return nil, nil
		}
		return &CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{
			Index: start.ContentBlockIndex,
			ID:    start.Start.ToolUse.ToolUseID,
			Name:  start.Start.ToolUse.Name,
		}}}, nil
	case ev.ContentBlockDelta != nil:
		return converseDeltaToCanonical(ev.ContentBlockDelta), nil
	case ev.MessageStop != nil:
		return &CanonicalStreamChunk{FinishReason: converseFinishReason(ev.MessageStop.StopReason)}, nil
	case ev.Metadata != nil:
		usage := converseUsageToCanonical(ev.Metadata.Usage)
		if usage == nil {
			return nil, nil
		}
		return &CanonicalStreamChunk{Usage: usage}, nil
	default:
		return nil, nil
	}
}

func converseDeltaToCanonical(d *ConverseContentBlockDelta) *CanonicalStreamChunk {
	switch {
	case d.Delta.ToolUse != nil:
		if d.Delta.ToolUse.Input == "" {
			return nil
		}
		return &CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{
			Index:          d.ContentBlockIndex,
			ArgumentsDelta: d.Delta.ToolUse.Input,
		}}}
	case d.Delta.ReasoningContent != nil:
		if d.Delta.ReasoningContent.Text == "" {
			return nil
		}
		return &CanonicalStreamChunk{ReasoningDelta: d.Delta.ReasoningContent.Text}
	case d.Delta.Text != "":
		return &CanonicalStreamChunk{Delta: d.Delta.Text}
	default:
		return nil
	}
}

func (a *BedrockAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	var events []ConverseStreamEvent
	if chunk.Role != "" {
		events = append(events, ConverseStreamEvent{MessageStart: &ConverseMessageStart{Role: chunk.Role}})
	}
	if chunk.ReasoningDelta != "" {
		events = append(events, ConverseStreamEvent{ContentBlockDelta: &ConverseContentBlockDelta{
			Delta: ConverseDeltaValue{ReasoningContent: &ConverseReasoningDelta{Text: chunk.ReasoningDelta}},
		}})
	}
	if chunk.Delta != "" {
		events = append(events, ConverseStreamEvent{ContentBlockDelta: &ConverseContentBlockDelta{
			Delta: ConverseDeltaValue{Text: chunk.Delta},
		}})
	}
	for _, tc := range chunk.ToolCallDeltas {
		if tc.ID != "" || tc.Name != "" {
			events = append(events, ConverseStreamEvent{ContentBlockStart: &ConverseContentBlockStart{
				ContentBlockIndex: tc.Index,
				Start:             ConverseBlockStartValue{ToolUse: &ConverseToolUseStart{ToolUseID: tc.ID, Name: tc.Name}},
			}})
		}
		if tc.ArgumentsDelta != "" {
			events = append(events, ConverseStreamEvent{ContentBlockDelta: &ConverseContentBlockDelta{
				ContentBlockIndex: tc.Index,
				Delta:             ConverseDeltaValue{ToolUse: &ConverseToolUseDelta{Input: tc.ArgumentsDelta}},
			}})
		}
	}
	if chunk.FinishReason != "" {
		// The deltas of a streamed tool call arrive in earlier chunks, so only
		// the finish reason itself can tell tool_use from end_turn here.
		events = append(events, ConverseStreamEvent{MessageStop: &ConverseMessageStop{
			StopReason: converseStopReason(chunk.FinishReason, false),
		}})
	}
	if chunk.Usage != nil {
		events = append(events, ConverseStreamEvent{Metadata: &ConverseMetadata{Usage: converseUsageFromCanonical(chunk.Usage)}})
	}

	lines := make([][]byte, 0, 2*len(events))
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		lines = append(lines, append([]byte("data: "), data...), []byte{})
	}
	return lines, nil
}

// converseFinishReason maps a Converse stop reason onto the canonical
// vocabulary shared by the buffered and streamed paths. Reasons with no
// canonical equivalent pass through unchanged: model_context_window_exceeded
// in particular must not read as "length", which clients retry with a bigger
// max_tokens.
func converseFinishReason(stop string) string {
	switch stop {
	case "end_turn", "stop_sequence", "":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "guardrail_intervened", "content_filtered":
		return "content_filter"
	default:
		return stop
	}
}

// converseStopReason is the inverse of converseFinishReason. A "stop" that
// carries tool calls is reported as tool_use, which is what a Converse client
// keys its tool loop on.
func converseStopReason(finish string, hasToolCalls bool) string {
	switch finish {
	case "stop", "":
		if hasToolCalls {
			return "tool_use"
		}
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "content_filter":
		return "content_filtered"
	default:
		return finish
	}
}

func converseUsageToCanonical(u *ConverseUsage) *CanonicalUsage {
	if u == nil {
		return nil
	}
	read, write := u.CacheReadInputTokens, u.CacheWriteInputTokens
	cu := newCanonicalUsage(u.InputTokens+read+write, u.OutputTokens, u.TotalTokens)
	if cu == nil {
		return nil
	}
	var write1h int
	for _, d := range u.CacheDetails {
		switch d.TTL {
		case converseCacheTTL1h:
			write1h += d.InputTokens
			cu.cacheTTLKnown = true
		case converseCacheTTL5m:
			cu.cacheTTLKnown = true
		}
	}
	cu.setCache(read, write, write1h)
	return cu
}

func converseUsageFromCanonical(u *CanonicalUsage) *ConverseUsage {
	if u == nil {
		return nil
	}
	out := &ConverseUsage{
		InputTokens:           u.PlainInputTokens(),
		OutputTokens:          u.OutputTokens,
		TotalTokens:           u.TotalTokens,
		CacheReadInputTokens:  u.CachedInputTokens,
		CacheWriteInputTokens: u.CacheWriteInputTokens,
	}
	if u.hasCacheTTLBreakdown() {
		out.CacheDetails = converseCacheDetails(u.CacheWriteInputTokens, u.CacheWrite1hInputTokens)
	}
	return out
}

func converseCacheDetails(write, write1h int) []ConverseCacheDetail {
	var details []ConverseCacheDetail
	write1h = min(write1h, write)
	if write1h > 0 {
		details = append(details, ConverseCacheDetail{InputTokens: write1h, TTL: converseCacheTTL1h})
	}
	if rest := write - write1h; rest > 0 {
		details = append(details, ConverseCacheDetail{InputTokens: rest, TTL: converseCacheTTL5m})
	}
	return details
}
