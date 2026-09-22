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

type openaiResponsesRequest struct {
	Model           string            `json:"model,omitempty"`
	Input           json.RawMessage   `json:"input"`
	Instructions    string            `json:"instructions,omitempty"`
	MaxOutputTokens *int              `json:"max_output_tokens,omitempty"`
	Temperature     *float64          `json:"temperature,omitempty"`
	TopP            *float64          `json:"top_p,omitempty"`
	Stream          *bool             `json:"stream,omitempty"`
	Tools           []json.RawMessage `json:"tools,omitempty"`
	Text            *openaiTextFormat `json:"text,omitempty"`
}

type openaiTextFormat struct {
	Format *openaiRespFormat `json:"format,omitempty"`
}

type openaiResponsesInputItem struct {
	Role      string          `json:"role,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"` // string or []contentPart
	Type      string          `json:"type,omitempty"`    // "input_text", "function_call", "function_call_output"
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments string          `json:"arguments,omitempty"`
	Output    string          `json:"output,omitempty"`
	Status    string          `json:"status,omitempty"`
}

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
	CachedTokens int `json:"cached_tokens"`
}

type openaiResponsesOutputTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens"`
}

func openaiResponsesUsageToCanonical(u openaiResponsesUsage) *CanonicalUsage {
	cu := newCanonicalUsage(u.InputTokens, u.OutputTokens, u.TotalTokens)
	if cu == nil {
		return nil
	}
	if u.InputTokensDetails != nil {
		cu.CachedInputTokens = u.InputTokensDetails.CachedTokens
	}
	if u.OutputTokensDetails != nil {
		cu.ReasoningOutputTokens = u.OutputTokensDetails.ReasoningTokens
	}
	return cu
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
		Model:       req.Model,
		System:      req.Instructions,
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}

	if req.Stream != nil {
		cr.Stream = *req.Stream
	}

	if req.MaxOutputTokens != nil {
		cr.MaxTokens = *req.MaxOutputTokens
	}

	if req.Text != nil && req.Text.Format != nil {
		cr.ResponseFormat = &CanonicalRespFormat{Type: req.Text.Format.Type}
	}

	// input: string or array of items
	if req.Input != nil {
		var inputStr string
		if json.Unmarshal(req.Input, &inputStr) == nil {
			cr.Messages = append(cr.Messages, CanonicalMessage{
				Role:    "user",
				Content: inputStr,
			})
		} else {
			var items []openaiResponsesInputItem
			if json.Unmarshal(req.Input, &items) == nil {
				for _, item := range items {
					switch {
					case item.Type == "function_call":
						callID := item.CallID
						if callID == "" {
							callID = item.ID
						}
						cr.Messages = append(cr.Messages, CanonicalMessage{
							Role: "assistant",
							ToolCalls: []CanonicalToolCall{{
								ID:        callID,
								Name:      item.Name,
								Arguments: item.Arguments,
							}},
						})

					case item.Type == "function_call_output":
						cr.Messages = append(cr.Messages, CanonicalMessage{
							Role:       "tool",
							Content:    item.Output,
							ToolCallID: item.CallID,
						})

					case item.Role != "":
						content := contentToString(item.Content)
						if item.Role == "system" || item.Role == "developer" {
							if cr.System != "" {
								cr.System += "\n"
							}
							cr.System += content
						} else {
							cr.Messages = append(cr.Messages, CanonicalMessage{
								Role:    item.Role,
								Content: content,
							})
						}

					case item.Type == "input_text":
						cr.Messages = append(cr.Messages, CanonicalMessage{
							Role:    "user",
							Content: item.Text,
						})
					}
				}
			}
		}
	}

	// tools: internally-tagged format (type may be omitted — shorthand for "function")
	for _, raw := range req.Tools {
		var tool openaiResponsesTool
		if json.Unmarshal(raw, &tool) != nil || tool.Name == "" {
			continue
		}
		switch tool.Type {
		case "custom":
			cr.Tools = append(cr.Tools, CanonicalTool{
				Kind:        ToolKindCustom,
				Name:        tool.Name,
				Description: tool.Description,
				Format:      tool.Format,
			})
		case "", "function":
			cr.Tools = append(cr.Tools, CanonicalTool{
				Name:        tool.Name,
				Description: tool.Description,
				Schema:      tool.Parameters,
			})
		}
	}

	return cr, nil
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

	if req.ResponseFormat != nil {
		out.Text = &openaiTextFormat{
			Format: &openaiRespFormat{Type: req.ResponseFormat.Type},
		}
	}

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

	if len(req.Messages) == 1 && req.Messages[0].Role == "user" && len(req.Messages[0].ToolCalls) == 0 {
		out.Input, _ = json.Marshal(req.Messages[0].Content)
	} else if len(req.Messages) > 0 {
		var inputItems []json.RawMessage
		for _, m := range req.Messages {
			switch {
			case m.Role == "tool":
				item := map[string]string{
					"type":    "function_call_output",
					"call_id": m.ToolCallID,
					"output":  m.Content,
				}
				raw, _ := json.Marshal(item)
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
				item := map[string]interface{}{
					"role":    m.Role,
					"content": m.Content,
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

// canonicalFinishToResponsesStatus maps a canonical finish reason onto the
// Responses status and, where the status needs one, the incomplete_details
// reason that explains it. The buffered and the streamed encode share it so a
// cut cannot be honest on one path and a lie on the other.
//
// A cut must not land on "completed": the Responses SDKs read that status as a
// clean finish, which is the whole failure this maps away from. length is left
// exactly as it was — its terminator is already malformed and fixing it would
// change what every truncated response emits, not just the cut ones.
func canonicalFinishToResponsesStatus(reason string) (status, incompleteReason string) {
	switch reason {
	case "length":
		return "incomplete", ""
	case "content_filter", "refusal":
		return "incomplete", "content_filter"
	default:
		return "completed", ""
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

	if resp.Usage != nil {
		out.Usage = &openaiResponsesUsage{
			InputTokens:  resp.Usage.InputTokens,
			OutputTokens: resp.Usage.OutputTokens,
			TotalTokens:  resp.Usage.TotalTokens,
		}
	}

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
		event := openaiResponsesStreamEvent{
			Type:        "response.output_item.added",
			OutputIndex: 0,
		}
		itemJSON, _ := json.Marshal(map[string]string{
			"type": "message",
			"role": chunk.Role,
		})
		event.Item = itemJSON
		data, _ := json.Marshal(event)
		allLines = append(allLines, SSEEvent("response.output_item.added", data)...)
	}

	if chunk.Delta != "" {
		event := openaiResponsesStreamEvent{
			Type:         "response.output_text.delta",
			Delta:        chunk.Delta,
			OutputIndex:  0,
			ContentIndex: 0,
		}
		// A caller that knows which item the wire has open says so, and a delta
		// that names none belongs to output item 0 with no identity at all — a
		// client accumulating by item_id attaches it to nothing. Only a caller
		// writing into a stream it did not start can know this, which today is
		// the guard's masked delta; every other caller opens its own item at
		// index 0 and keeps the shape it has.
		if chunk.OpenItem != nil {
			event.ItemID = chunk.OpenItem.ID
			event.OutputIndex = chunk.OpenItem.Index
		}
		data, _ := json.Marshal(event)
		allLines = append(allLines, SSEEvent("response.output_text.delta", data)...)
	}

	for _, tc := range chunk.ToolCallDeltas {
		if tc.Name != "" {
			event := openaiResponsesStreamEvent{
				Type:        "response.output_item.added",
				OutputIndex: tc.Index,
			}
			itemJSON, _ := json.Marshal(map[string]interface{}{
				"type":    "function_call",
				"id":      tc.ID,
				"name":    tc.Name,
				"call_id": tc.ID,
			})
			event.Item = itemJSON
			data, _ := json.Marshal(event)
			allLines = append(allLines, SSEEvent("response.output_item.added", data)...)
		}
		if tc.ArgumentsDelta != "" {
			event := openaiResponsesStreamEvent{
				Type:        "response.function_call_arguments.delta",
				Delta:       tc.ArgumentsDelta,
				OutputIndex: tc.Index,
			}
			data, _ := json.Marshal(event)
			allLines = append(allLines, SSEEvent("response.function_call_arguments.delta", data)...)
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
			respObj["usage"] = map[string]int{
				"input_tokens":  chunk.Usage.InputTokens,
				"output_tokens": chunk.Usage.OutputTokens,
				"total_tokens":  chunk.Usage.TotalTokens,
			}
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
