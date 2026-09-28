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
	"fmt"
	"strings"
)

type openaiResponsesRequest struct {
	Model                string            `json:"model,omitempty"`
	Input                json.RawMessage   `json:"input"`
	Instructions         string            `json:"instructions,omitempty"`
	MaxOutputTokens      *int              `json:"max_output_tokens,omitempty"`
	Temperature          *float64          `json:"temperature,omitempty"`
	TopP                 *float64          `json:"top_p,omitempty"`
	Stream               *bool             `json:"stream,omitempty"`
	Tools                []json.RawMessage `json:"tools,omitempty"`
	Text                 *openaiTextFormat `json:"text,omitempty"`
	PromptCacheKey       string            `json:"prompt_cache_key,omitempty"`
	PromptCacheRetention string            `json:"prompt_cache_retention,omitempty"`
	PromptCacheOptions   json.RawMessage   `json:"prompt_cache_options,omitempty"`
	Store                json.RawMessage   `json:"store,omitempty"`
	PreviousResponseID   json.RawMessage   `json:"previous_response_id,omitempty"`
	Include              json.RawMessage   `json:"include,omitempty"`
	Reasoning            json.RawMessage   `json:"reasoning,omitempty"`
}

// responsesCarriedKeys are the Responses keys a re-encode carries through
// RequestExtensions: they hold no prompt text, and dropping them changes what
// the upstream keeps or links. Without store the upstream stores a response
// the client asked it not to keep. metadata, which may hold personal data, is
// left out.
var responsesCarriedKeys = []string{"store", "previous_response_id", "include", "reasoning"}

func (r *openaiResponsesRequest) carried() []*json.RawMessage {
	return []*json.RawMessage{&r.Store, &r.PreviousResponseID, &r.Include, &r.Reasoning}
}

// carryRequestKeys records in req the raw values of keys, one per slot, that
// the client set to something other than null.
func carryRequestKeys(req *CanonicalRequest, keys []string, slots []*json.RawMessage) {
	for i, slot := range slots {
		if len(*slot) == 0 || isEmptyOrNull(*slot) {
			continue
		}
		if req.RequestExtensions == nil {
			req.RequestExtensions = make(map[string]json.RawMessage, len(slots))
		}
		req.RequestExtensions[keys[i]] = *slot
	}
}

// carriedRequestKeys fills each slot with the value req carries for its key.
func carriedRequestKeys(req *CanonicalRequest, keys []string, slots []*json.RawMessage) {
	for i, slot := range slots {
		if v, ok := req.RequestExtensions[keys[i]]; ok && json.Valid(v) {
			*slot = v
		}
	}
}

type openaiTextFormat struct {
	Format *openaiRespFormat `json:"format,omitempty"`
}

type openaiResponsesInputItem struct {
	Role      string          `json:"role,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	Type      string          `json:"type,omitempty"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
	Status    string          `json:"status,omitempty"`

	PromptCacheBreakpoint *openaiPromptCacheBreakpoint `json:"prompt_cache_breakpoint,omitempty"`
}

var responsesExplicitBreakpoint = &openaiPromptCacheBreakpoint{Mode: "explicit"}

func responsesPartBreakpoint(p openaiContentPart) *CanonicalCacheBreakpoint {
	return responsesBreakpoint(p.PromptCacheBreakpoint)
}

func responsesBreakpoint(b *openaiPromptCacheBreakpoint) *CanonicalCacheBreakpoint {
	if b == nil {
		return nil
	}
	return &CanonicalCacheBreakpoint{}
}

const responsesNonTextToolOutput = "[tool output without text]"

type openaiResponsesTool struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Format      json.RawMessage        `json:"format,omitempty"`
	Strict      *bool                  `json:"strict,omitempty"`
}

type openaiResponsesResponse struct {
	ID                string                            `json:"id"`
	Object            string                            `json:"object"`
	Model             string                            `json:"model"`
	Status            string                            `json:"status"`
	IncompleteDetails *openaiResponsesIncompleteDetails `json:"incomplete_details,omitempty"`
	Output            []openaiResponsesItem             `json:"output"`
	Usage             *openaiResponsesUsage             `json:"usage,omitempty"`
}

type openaiResponsesIncompleteDetails struct {
	Reason string `json:"reason"`
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
	InputTokens         int                                 `json:"input_tokens"`
	OutputTokens        int                                 `json:"output_tokens"`
	TotalTokens         int                                 `json:"total_tokens"`
	InputTokensDetails  *openaiResponsesInputTokensDetails  `json:"input_tokens_details,omitempty"`
	OutputTokensDetails *openaiResponsesOutputTokensDetails `json:"output_tokens_details,omitempty"`
}

type openaiResponsesInputTokensDetails struct {
	CachedTokens     int `json:"cached_tokens"`
	CacheWriteTokens int `json:"cache_write_tokens,omitempty"`
}

type openaiResponsesOutputTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens"`
}

func openaiResponsesUsageToCanonical(u openaiResponsesUsage) *CanonicalUsage {
	cu := newCanonicalUsage(u.InputTokens, u.OutputTokens, u.TotalTokens)
	if cu == nil {
		return nil
	}
	if d := u.InputTokensDetails; d != nil && d.CachedTokens+d.CacheWriteTokens > 0 {
		cu.setCache(d.CachedTokens, d.CacheWriteTokens, 0)
	}
	if u.OutputTokensDetails != nil {
		cu.ReasoningOutputTokens = u.OutputTokensDetails.ReasoningTokens
	}
	return cu
}

func openaiResponsesUsageFromCanonical(u *CanonicalUsage) *openaiResponsesUsage {
	if u == nil {
		return nil
	}
	return &openaiResponsesUsage{
		InputTokens:  u.InputTokens,
		OutputTokens: u.OutputTokens,
		TotalTokens:  u.TotalTokens,
		InputTokensDetails: &openaiResponsesInputTokensDetails{
			CachedTokens:     u.CachedInputTokens,
			CacheWriteTokens: u.CacheWriteInputTokens,
		},
		OutputTokensDetails: &openaiResponsesOutputTokensDetails{ReasoningTokens: u.ReasoningOutputTokens},
	}
}

type openaiResponsesStreamEvent struct {
	Type         string          `json:"type"`
	Delta        string          `json:"delta,omitempty"`
	ItemID       string          `json:"item_id,omitempty"`
	OutputIndex  int             `json:"output_index,omitempty"`
	ContentIndex int             `json:"content_index,omitempty"`
	Item         json.RawMessage `json:"item,omitempty"`
	Part         json.RawMessage `json:"part,omitempty"`
	Response     json.RawMessage `json:"response,omitempty"`
}

// The output item types this encoder names. A message item and a function_call
// item both open at output index 0, so the kind is what tells a cut which of
// them it is closing.
const (
	responsesItemKindMessage      = "message"
	responsesItemKindFunctionCall = "function_call"
)

// responsesPartDoneEvent and responsesItemDoneEvent close what a cut
// interrupted. They exist beside openaiResponsesStreamEvent rather than reusing
// it because their indices are not omitempty: output index 0 is the first item
// and content index 0 the first part of it, and to a client reading the field
// an absent index is not the first one. An item is not a part of itself, so
// only the part events carry a content index.
type responsesPartDoneEvent struct {
	Type         string          `json:"type"`
	OutputIndex  int             `json:"output_index"`
	ContentIndex int             `json:"content_index"`
	Part         json.RawMessage `json:"part,omitempty"`
}

type responsesItemDoneEvent struct {
	Type        string          `json:"type"`
	OutputIndex int             `json:"output_index"`
	Item        json.RawMessage `json:"item"`
}

// responsesCloseMessage and responsesCloseFunctionCall are the items those
// events carry. They do not reuse openaiResponsesItem because that struct omits
// every empty field, and the SDK types a client decodes these into are strict:
// ResponseOutputMessage requires id and content, ResponseFunctionToolCall
// requires arguments, call_id and name. An omitted field raises a validation
// error there instead of delivering the refusal the cut exists to deliver, so a
// cut that produced no arguments has to say so as "" rather than by silence.
type responsesCloseMessage struct {
	ID      string                   `json:"id"`
	Type    string                   `json:"type"`
	Role    string                   `json:"role"`
	Status  string                   `json:"status"`
	Content []openaiResponsesContent `json:"content"`
}

type responsesCloseFunctionCall struct {
	ID        string `json:"id,omitempty"`
	Type      string `json:"type"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
	Status    string `json:"status"`
}

func decodeResponsesRequest(body []byte) (*CanonicalRequest, error) {
	var req openaiResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	cr := &CanonicalRequest{
		Model:        req.Model,
		Temperature:  req.Temperature,
		TopP:         req.TopP,
		CacheOptions: openAICacheOptions(req.PromptCacheKey, req.PromptCacheRetention, req.PromptCacheOptions),
	}
	carryRequestKeys(cr, responsesCarriedKeys, req.carried())

	if req.Stream != nil {
		cr.Stream = *req.Stream
	}

	if req.MaxOutputTokens != nil {
		cr.MaxTokens = *req.MaxOutputTokens
	}

	if req.Text != nil && req.Text.Format != nil {
		cr.ResponseFormat = decodeResponsesTextFormat(req.Text.Format)
	}

	cr.Tools = decodeResponsesTools(req.Tools)
	var system cacheTextJoin
	if req.Instructions != "" {
		system.add(req.Instructions)
	}
	if err := decodeResponsesInput(req.Input, cr, &system); err != nil {
		return nil, err
	}
	cr.System, cr.SystemCache = system.String(), system.breakpoint()
	return cr, nil
}

// decodeResponsesTools decodes the function and custom tools of a request.
// The type may be omitted, as shorthand for a function tool.
func decodeResponsesTools(raws []json.RawMessage) []CanonicalTool {
	var tools []CanonicalTool
	for _, raw := range raws {
		var tool openaiResponsesTool
		if json.Unmarshal(raw, &tool) != nil || tool.Name == "" {
			continue
		}
		switch tool.Type {
		case "custom":
			tools = append(tools, CanonicalTool{
				Kind:        ToolKindCustom,
				Name:        tool.Name,
				Description: tool.Description,
				Format:      tool.Format,
			})
		case "", "function":
			tools = append(tools, CanonicalTool{
				Name:        tool.Name,
				Description: tool.Description,
				Schema:      tool.Parameters,
			})
		}
	}
	return tools
}

// decodeResponsesInput appends the messages of input, a string or a list of
// items, to cr. Items are decoded one by one so that one item of a shape the
// gateway does not know is counted in cr.DroppedInputItems instead of failing
// the request or dropping the rest of the history.
func decodeResponsesInput(input json.RawMessage, cr *CanonicalRequest, system *cacheTextJoin) error {
	if len(input) == 0 || string(input) == "null" {
		return nil
	}
	var text string
	if json.Unmarshal(input, &text) == nil {
		cr.Messages = append(cr.Messages, CanonicalMessage{Role: "user", Content: text})
		return nil
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(input, &raws); err != nil {
		return fmt.Errorf("decode responses input: %w", err)
	}
	turn := false
	for _, raw := range raws {
		var item openaiResponsesInputItem
		if json.Unmarshal(raw, &item) != nil {
			cr.DroppedInputItems++
			continue
		}
		turn = appendResponsesInputItem(cr, system, item, turn)
	}
	return nil
}

// appendResponsesInputItem returns whether cr ends with an assistant message
// that later assistant items join, so a Chat Completions upstream gets one
// assistant message per turn. Only a user message, an input_text or a
// function_call_output ends a turn; developer and system text goes to the
// system prompt wherever it appears.
func appendResponsesInputItem(cr *CanonicalRequest, system *cacheTextJoin, item openaiResponsesInputItem, turn bool) bool {
	switch {
	case item.Type == "function_call":
		callID := item.CallID
		if callID == "" {
			callID = item.ID
		}
		return appendResponsesAssistant(cr, turn, "", CanonicalToolCall{ID: callID, Name: item.Name, Arguments: responsesCallArguments(item.Arguments)})
	case item.Type == "function_call_output":
		output, cache := responsesToolOutput(item.Output)
		cr.Messages = append(cr.Messages, CanonicalMessage{Role: "tool", Content: output, ToolCallID: item.CallID, Cache: cache})
		return false
	case item.Type == "reasoning":
		return turn
	case item.Role == "assistant":
		return appendResponsesAssistant(cr, turn, contentToString(item.Content))
	case item.Role == "system", item.Role == "developer":
		appendOpenAISystem(system, item.Content, responsesPartBreakpoint)
		return turn
	case item.Role != "":
		var text cacheTextJoin
		decodeOpenAIParts(item.Content, &text, responsesPartBreakpoint, false)
		cr.Messages = append(cr.Messages, CanonicalMessage{Role: item.Role, Content: text.String(), Cache: text.breakpoint()})
		return false
	case item.Type == "input_text":
		cr.Messages = append(cr.Messages, CanonicalMessage{Role: "user", Content: item.Text, Cache: responsesBreakpoint(item.PromptCacheBreakpoint)})
		return false
	default:
		return turn
	}
}

// responsesCallArguments keeps a call whose arguments are not the JSON string
// the API specifies as the compact JSON text of the value, so its
// function_call_output is not left without a call.
func responsesCallArguments(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return responsesEmptyArguments
	}
	var arguments string
	if json.Unmarshal(raw, &arguments) != nil {
		var compact bytes.Buffer
		if json.Compact(&compact, raw) != nil {
			return responsesEmptyArguments
		}
		return compact.String()
	}
	if strings.TrimSpace(arguments) == "" {
		return responsesEmptyArguments
	}
	return arguments
}

// responsesToolOutput returns the text of a function_call_output and the
// breakpoint of its text parts; parts that are not text (images, files) are
// left out with their breakpoints, and a value that is neither a string nor a
// list of parts is passed on as its JSON text. An output with no text gets a
// placeholder, since upstreams reject an empty tool result, and a breakpoint
// on its blank text then marks the end of the placeholder.
func responsesToolOutput(output json.RawMessage) (string, *CanonicalCacheBreakpoint) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return responsesNonTextToolOutput, nil
	}
	var text cacheTextJoin
	decodeOpenAIParts(trimmed, &text, responsesPartBreakpoint, false)
	cache := text.breakpoint()
	if strings.TrimSpace(text.String()) == "" {
		if cache != nil {
			cache = &CanonicalCacheBreakpoint{TTL: cache.TTL}
		}
		return responsesNonTextToolOutput, cache
	}
	return text.String(), cache
}

// appendResponsesAssistant folds an assistant item into the last message of
// cr when turn reports it is an assistant message of the same turn, and
// returns whether cr now ends with an assistant message of this turn.
// OpenAI-compatible upstreams such as DeepSeek reject an assistant message
// with tool calls that is not followed by their results, and an empty
// assistant message, so an empty item is dropped and leaves turn unchanged
// (ENG-1618).
func appendResponsesAssistant(cr *CanonicalRequest, turn bool, content string, calls ...CanonicalToolCall) bool {
	if content == "" && len(calls) == 0 {
		return turn
	}
	if n := len(cr.Messages); turn && n > 0 && cr.Messages[n-1].Role == "assistant" {
		last := &cr.Messages[n-1]
		if content != "" && last.Content != "" {
			last.Content += "\n"
		}
		last.Content += content
		last.ToolCalls = append(last.ToolCalls, calls...)
		return true
	}
	cr.Messages = append(cr.Messages, CanonicalMessage{Role: "assistant", Content: content, ToolCalls: calls})
	return true
}

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
		if resp.IncompleteDetails != nil && resp.IncompleteDetails.Reason == "content_filter" {
			cr.FinishReason = "content_filter"
		}
	default:
		cr.FinishReason = "stop"
	}

	if resp.Usage != nil {
		cr.Usage = openaiResponsesUsageToCanonical(*resp.Usage)
	}

	return cr, nil
}

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
				Type   string `json:"type"`
				Role   string `json:"role"`
				ID     string `json:"id"`
				CallID string `json:"call_id"`
				Name   string `json:"name"`
			}
			if json.Unmarshal(event.Item, &item) == nil {
				switch item.Type {
				case "message":
					return &CanonicalStreamChunk{
						Role: item.Role,
					}, nil
				case "function_call":
					return &CanonicalStreamChunk{
						ToolCallDeltas: []StreamToolCallDelta{{
							Index: event.OutputIndex,
							ID:    item.CallID,
							Name:  item.Name,
						}},
					}, nil
				}
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
					sc.Usage = openaiResponsesUsageToCanonical(*completed.Usage)
				}
			}
		}
		return sc, nil

	// Without this case the event decodes to nil, and a nil decode classifies
	// as an opaque unit, which the stream guard releases immediately. Our own
	// cut terminator would then overtake the text it is meant to hold back.
	case "response.incomplete":
		sc := &CanonicalStreamChunk{
			FinishReason: "length",
		}
		if event.Response != nil {
			var incomplete struct {
				ID                string                            `json:"id"`
				Model             string                            `json:"model"`
				Usage             *openaiResponsesUsage             `json:"usage"`
				IncompleteDetails *openaiResponsesIncompleteDetails `json:"incomplete_details"`
			}
			if json.Unmarshal(event.Response, &incomplete) == nil {
				sc.ID = incomplete.ID
				sc.Model = incomplete.Model
				if incomplete.Usage != nil {
					sc.Usage = openaiResponsesUsageToCanonical(*incomplete.Usage)
				}
				if incomplete.IncompleteDetails != nil && incomplete.IncompleteDetails.Reason == "content_filter" {
					sc.FinishReason = "content_filter"
				}
			}
		}
		return sc, nil

	default:
		return nil, nil
	}
}

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

	if format, ok := encodeResponsesTextFormat(req.ResponseFormat); ok {
		out.Text = &openaiTextFormat{Format: format}
	}
	if o := req.CacheOptions; o != nil {
		out.PromptCacheKey, out.PromptCacheRetention = o.Key, o.Retention
		out.PromptCacheOptions = o.openAIOptions()
	}
	carriedRequestKeys(req, responsesCarriedKeys, out.carried())

	// Pre-pass: ensure every tool call has a stable call_id so that
	// function_call and function_call_output items can be linked even when
	// the source format (e.g. Gemini) does not provide IDs.
	idMap := make(map[string]string) // original (possibly empty) ID → generated call_id
	tcCounter := 0
	for mi := range req.Messages {
		m := &req.Messages[mi]
		for ti := range m.ToolCalls {
			tc := &m.ToolCalls[ti]
			if tc.ID == "" {
				tc.ID = fmt.Sprintf("call_%s_%d", tc.Name, tcCounter)
				tcCounter++
			}
			idMap[tc.ID] = tc.ID
		}
	}
	for mi := range req.Messages {
		m := &req.Messages[mi]
		if m.Role == "tool" && m.ToolCallID == "" {
			// Match by position: find the Nth unmatched tool call
			for _, msg := range req.Messages {
				for _, tc := range msg.ToolCalls {
					if _, used := idMap[tc.ID]; used {
						m.ToolCallID = tc.ID
						delete(idMap, tc.ID)
						break
					}
				}
				if m.ToolCallID != "" {
					break
				}
			}
		}
	}

	var inputItems []json.RawMessage
	if system := responsesInputParts(req.System, req.SystemCache); system != nil {
		out.Instructions = ""
		raw, _ := json.Marshal(map[string]any{"role": "developer", "content": system})
		inputItems = append(inputItems, raw)
	}
	if len(inputItems) == 0 && len(req.Messages) == 1 && req.Messages[0].Role == "user" &&
		len(req.Messages[0].ToolCalls) == 0 && req.Messages[0].Cache == nil {
		out.Input, _ = json.Marshal(req.Messages[0].Content)
	} else if len(req.Messages) > 0 || len(inputItems) > 0 {
		for _, m := range req.Messages {
			switch {
			case m.Role == "tool":
				var output any = m.Content
				if parts := responsesInputParts(m.Content, m.Cache); parts != nil {
					output = parts
				}
				raw, _ := json.Marshal(map[string]any{
					"type":    "function_call_output",
					"call_id": m.ToolCallID,
					"output":  output,
				})
				inputItems = append(inputItems, raw)

			case m.Role == "assistant" && len(m.ToolCalls) > 0:
				for _, tc := range m.ToolCalls {
					name := tc.Name
					if name == "" {
						name = tc.ID
					}
					fcID := tc.ID
					if !strings.HasPrefix(fcID, "fc_") {
						fcID = "fc_" + fcID
					}
					item := map[string]string{
						"type":      "function_call",
						"id":        fcID,
						"call_id":   tc.ID,
						"name":      name,
						"arguments": tc.Arguments,
						"status":    "completed",
					}
					raw, _ := json.Marshal(item)
					inputItems = append(inputItems, raw)
				}

			case m.Role == "system" || m.Role == "developer":
				if out.Instructions != "" {
					out.Instructions += "\n"
				}
				out.Instructions += m.Content

			default:
				var content any = m.Content
				if parts := responsesInputParts(m.Content, m.Cache); parts != nil && m.Role != "assistant" {
					content = parts
				}
				item := map[string]interface{}{
					"role":    m.Role,
					"content": content,
				}
				raw, _ := json.Marshal(item)
				inputItems = append(inputItems, raw)
			}
		}
		out.Input, _ = json.Marshal(inputItems)
	}

	for _, t := range req.Tools {
		tool := openaiResponsesTool{
			Type:        "function",
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Schema,
		}
		if t.Kind == ToolKindCustom {
			tool.Type = "custom"
			tool.Parameters = nil
			tool.Format = t.Format
		}
		raw, _ := json.Marshal(tool)
		out.Tools = append(out.Tools, raw)
	}

	return json.Marshal(out)
}

// responsesInputParts writes text as input_text parts with the breakpoint on
// the part it was decoded from, or on the last one. It returns nil when there
// is no breakpoint or no text to carry it; an assistant message cannot carry
// one, as its parts are output_text, and a breakpoint on an image falls
// back to the text marker behind it because the encoder sends no images.
func responsesInputParts(text string, cache *CanonicalCacheBreakpoint) []openaiContentPart {
	cache = cache.withoutImages()
	if cache == nil {
		return nil
	}
	texts, placed := cachedTextParts(text, cache)
	if len(texts) == 0 {
		return nil
	}
	parts := make([]openaiContentPart, 0, len(texts))
	for _, t := range texts {
		parts = append(parts, openaiContentPart{Type: "input_text", Text: t})
	}
	at := len(parts) - 1
	if placed {
		at = 0
	}
	parts[at].PromptCacheBreakpoint = responsesExplicitBreakpoint
	return parts
}

// canonicalFinishToResponsesStatus maps a canonical finish reason onto the
// Responses status and, where the status needs one, the incomplete_details
// reason that explains it. The buffered encode, the stateless chunk encode and
// ResponsesStreamEncoder all share it, so a response cannot end one way
// buffered and another way streamed.
//
// A cut must not land on "completed": the Responses SDKs read that status as a
// clean finish, which is the whole failure this maps away from. A token-limit
// or context-window finish is incomplete for max_output_tokens, the reason
// OpenAI itself reports, and every refusal finish maps like content_filter, so
// a Gemini SAFETY stop reads the same buffered and streamed.
func canonicalFinishToResponsesStatus(reason string) (status, incompleteReason string) {
	switch {
	case truncatedFinish(reason):
		return responsesStatusIncomplete, "max_output_tokens"
	case refusalFinish(reason):
		return responsesStatusIncomplete, "content_filter"
	default:
		return responsesStatusCompleted, ""
	}
}

func encodeResponsesResponse(resp *CanonicalResponse) ([]byte, error) {
	out := openaiResponsesResponse{
		ID:     resp.ID,
		Object: "response",
		Model:  resp.Model,
	}

	status, incompleteReason := canonicalFinishToResponsesStatus(resp.FinishReason)
	out.Status = status
	if incompleteReason != "" {
		out.IncompleteDetails = &openaiResponsesIncompleteDetails{Reason: incompleteReason}
	}

	if resp.Content != "" {
		messageStatus := "completed"
		if incompleteReason != "" {
			messageStatus = "incomplete"
		}
		out.Output = append(out.Output, openaiResponsesItem{
			Type: "message",
			Role: "assistant",
			Content: []openaiResponsesContent{{
				Type: "output_text",
				Text: resp.Content,
			}},
			Status: messageStatus,
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

	out.Usage = openaiResponsesUsageFromCanonical(resp.Usage)

	return json.Marshal(out)
}

// responsesCutCloseEvents closes the message item a cut interrupts, in the
// order the Responses protocol nests it: the text, then the content part, then
// the item. It closes an item for event-tracking clients only; snapshot
// reconstruction is out of reach until this encoder emits response.created,
// which it never does.
//
// The item it closes is the one the caller carries on OpenItem. The adapter is
// a stateless shared singleton, so a synthesised terminator that names no item
// closes none: a message item and a function_call item both open at output
// index 0, and closing index 0 as a message would leave the real item
// unterminated and close one that was never added. A cut chunk that carries
// text of its own proves a message item open on its own account, which is the
// one case the adapter can answer without being told.
func responsesCutCloseEvents(chunk *CanonicalStreamChunk) [][]byte {
	item := chunk.OpenItem
	if item == nil {
		if len(chunk.ToolCallDeltas) > 0 || (chunk.Delta == "" && chunk.Role == "") {
			return nil
		}
		item = &StreamOpenItem{Kind: responsesItemKindMessage}
	}
	switch item.Kind {
	case responsesItemKindMessage:
		return responsesCloseMessageItem(item)
	case responsesItemKindFunctionCall:
		return responsesCloseFunctionCallItem(item)
	default:
		return nil
	}
}

func responsesCloseMessageItem(item *StreamOpenItem) [][]byte {
	var lines [][]byte

	textDone, _ := json.Marshal(responsesPartDoneEvent{
		Type:        "response.output_text.done",
		OutputIndex: item.Index,
	})
	lines = append(lines, SSEEvent("response.output_text.done", textDone)...)

	partEvent := responsesPartDoneEvent{
		Type:        "response.content_part.done",
		OutputIndex: item.Index,
	}
	partEvent.Part, _ = json.Marshal(openaiResponsesContent{Type: "output_text"})
	partDone, _ := json.Marshal(partEvent)
	lines = append(lines, SSEEvent("response.content_part.done", partDone)...)

	closed, _ := json.Marshal(responsesCloseMessage{
		ID:      item.ID,
		Type:    responsesItemKindMessage,
		Role:    "assistant",
		Status:  "incomplete",
		Content: []openaiResponsesContent{},
	})
	return append(lines, responsesCloseItemEvent(item.Index, closed)...)
}

// responsesCloseFunctionCallItem closes a tool call the cut interrupted. There
// is no text part to close: the arguments ride
// response.function_call_arguments.delta, and their .done event asserts a
// complete argument string, which a cut has not produced. The arguments the
// item itself carries are "" for the same reason — absent is not a valid
// ResponseFunctionToolCall, and a partial string would be a lie.
func responsesCloseFunctionCallItem(item *StreamOpenItem) [][]byte {
	closed, _ := json.Marshal(responsesCloseFunctionCall{
		ID:        item.ID,
		Type:      responsesItemKindFunctionCall,
		CallID:    item.CallID,
		Name:      item.Name,
		Arguments: "",
		Status:    "incomplete",
	})
	return responsesCloseItemEvent(item.Index, closed)
}

func responsesCloseItemEvent(outputIndex int, item json.RawMessage) [][]byte {
	data, _ := json.Marshal(responsesItemDoneEvent{
		Type:        "response.output_item.done",
		OutputIndex: outputIndex,
		Item:        item,
	})
	return SSEEvent("response.output_item.done", data)
}

func encodeResponsesStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	var allLines [][]byte

	if chunk.Role != "" {
		allLines = append(allLines, responsesMessageAdded(0, chunk.Role)...)
	}

	if chunk.Delta != "" {
		// A caller that knows which item the wire has open says so, and a delta
		// that names none belongs to output item 0 with no identity at all — a
		// client accumulating by item_id attaches it to nothing. Only a caller
		// writing into a stream it did not start can know this, which today is
		// the guard's masked delta; every other caller opens its own item at
		// index 0 and keeps the shape it has.
		index, itemID := 0, ""
		if chunk.OpenItem != nil {
			index, itemID = chunk.OpenItem.Index, chunk.OpenItem.ID
		}
		allLines = append(allLines, responsesTextDelta(index, itemID, chunk.Delta)...)
	}

	for _, tc := range chunk.ToolCallDeltas {
		if tc.Name != "" {
			allLines = append(allLines, responsesFunctionCallAdded(tc.Index, tc)...)
		}
		if tc.ArgumentsDelta != "" {
			allLines = append(allLines, responsesArgumentsDelta(tc.Index, tc.ArgumentsDelta)...)
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
		status, incompleteReason := canonicalFinishToResponsesStatus(chunk.FinishReason)

		terminator := "response.completed"
		if incompleteReason != "" {
			terminator = "response.incomplete"
			allLines = append(allLines, responsesCutCloseEvents(chunk)...)
		}

		respObj := map[string]interface{}{
			"status": status,
			"object": "response",
			"output": []interface{}{},
		}
		if incompleteReason != "" {
			respObj["incomplete_details"] = map[string]string{"reason": incompleteReason}
		}
		if chunk.ID != "" {
			respObj["id"] = chunk.ID
		}
		if chunk.Model != "" {
			respObj["model"] = chunk.Model
		}
		if chunk.Usage != nil {
			respObj["usage"] = openaiResponsesUsageFromCanonical(chunk.Usage)
		}

		event := openaiResponsesStreamEvent{
			Type: terminator,
		}
		event.Response, _ = json.Marshal(respObj)
		data, _ := json.Marshal(event)
		allLines = append(allLines, SSEEvent(terminator, data)...)
	}

	if len(allLines) == 0 {
		return nil, nil
	}

	return allLines, nil
}

func responsesMessageAdded(index int, role string) [][]byte {
	itemJSON, _ := json.Marshal(map[string]string{
		"type": "message",
		"role": role,
	})
	data, _ := json.Marshal(openaiResponsesStreamEvent{
		Type:        "response.output_item.added",
		OutputIndex: index,
		Item:        itemJSON,
	})
	return SSEEvent("response.output_item.added", data)
}

func responsesTextDelta(index int, itemID, delta string) [][]byte {
	data, _ := json.Marshal(openaiResponsesStreamEvent{
		Type:         "response.output_text.delta",
		ItemID:       itemID,
		Delta:        delta,
		OutputIndex:  index,
		ContentIndex: 0,
	})
	return SSEEvent("response.output_text.delta", data)
}

func responsesFunctionCallAdded(index int, tc StreamToolCallDelta) [][]byte {
	itemJSON, _ := json.Marshal(map[string]interface{}{
		"type":    "function_call",
		"id":      tc.ID,
		"name":    tc.Name,
		"call_id": tc.ID,
	})
	data, _ := json.Marshal(openaiResponsesStreamEvent{
		Type:        "response.output_item.added",
		OutputIndex: index,
		Item:        itemJSON,
	})
	return SSEEvent("response.output_item.added", data)
}

func responsesArgumentsDelta(index int, delta string) [][]byte {
	data, _ := json.Marshal(openaiResponsesStreamEvent{
		Type:        "response.function_call_arguments.delta",
		Delta:       delta,
		OutputIndex: index,
	})
	return SSEEvent("response.function_call_arguments.delta", data)
}

func decodeResponsesTextFormat(f *openaiRespFormat) *CanonicalRespFormat {
	out := &CanonicalRespFormat{Type: f.Type}
	if f.Type == responseFormatJSONSchema && len(f.Schema) > 0 {
		out.JSONSchema, _ = json.Marshal(f.openaiJSONSchema)
	}
	return out
}

// encodeResponsesTextFormat reports false for a json_schema format whose
// schema is missing or unreadable, which the Responses API rejects.
func encodeResponsesTextFormat(f *CanonicalRespFormat) (*openaiRespFormat, bool) {
	if f == nil {
		return nil, false
	}
	out := &openaiRespFormat{Type: f.Type}
	if f.Type != responseFormatJSONSchema {
		return out, true
	}
	if json.Unmarshal(f.JSONSchema, &out.openaiJSONSchema) != nil || len(out.Schema) == 0 {
		return nil, false
	}
	return out, true
}
