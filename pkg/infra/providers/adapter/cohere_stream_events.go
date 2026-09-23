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

import "encoding/json"

type cohereMessageStartEvent struct {
	ID    string                  `json:"id,omitempty"`
	Type  string                  `json:"type"`
	Delta cohereMessageStartDelta `json:"delta"`
}

type cohereMessageStartDelta struct {
	Message cohereMessageStartMessage `json:"message"`
}

type cohereMessageStartMessage struct {
	Role string `json:"role"`
}

type cohereIndexedEvent struct {
	Type  string          `json:"type"`
	Index int             `json:"index"`
	Delta json.RawMessage `json:"delta,omitempty"`
}

type cohereMessageEndEvent struct {
	Type  string                `json:"type"`
	Delta cohereMessageEndDelta `json:"delta"`
}

type cohereStreamContentDelta struct {
	Message cohereStreamContentMessage `json:"message"`
}

type cohereStreamContentMessage struct {
	Content cohereStreamContent `json:"content"`
}

type cohereStreamContent struct {
	Type string `json:"type,omitempty"`
	Text string `json:"text"`
}

type cohereToolCallsDelta struct {
	Message *cohereToolCallsDeltaMessage `json:"message,omitempty"`
}

type cohereToolCallsDeltaMessage struct {
	ToolCalls *cohereStreamToolCall `json:"tool_calls,omitempty"`
}

type cohereStreamToolCall struct {
	ID       string                    `json:"id,omitempty"`
	Type     string                    `json:"type,omitempty"`
	Function *cohereStreamToolFunction `json:"function,omitempty"`
}

type cohereStreamToolFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"`
}

func cohereMessageStart(id string) [][]byte {
	data, _ := json.Marshal(cohereMessageStartEvent{
		ID:    id,
		Type:  "message-start",
		Delta: cohereMessageStartDelta{Message: cohereMessageStartMessage{Role: "assistant"}},
	})
	return SSEEvent("message-start", data)
}

func cohereIndexed(eventType string, index int, delta any) [][]byte {
	ev := cohereIndexedEvent{Type: eventType, Index: index}
	if delta != nil {
		ev.Delta = mustMarshal(delta)
	}
	data, _ := json.Marshal(ev)
	return SSEEvent(eventType, data)
}

func cohereContentStart(index int) [][]byte {
	return cohereIndexed("content-start", index, cohereStreamContentDelta{
		Message: cohereStreamContentMessage{Content: cohereStreamContent{Type: "text"}},
	})
}

func cohereContentDeltaEvent(index int, text string) [][]byte {
	return cohereIndexed("content-delta", index, cohereStreamContentDelta{
		Message: cohereStreamContentMessage{Content: cohereStreamContent{Text: text}},
	})
}

func cohereContentEnd(index int) [][]byte {
	return cohereIndexed("content-end", index, nil)
}

func cohereToolCallStart(index int, id, name string) [][]byte {
	return cohereIndexed("tool-call-start", index, cohereToolCallsDelta{
		Message: &cohereToolCallsDeltaMessage{ToolCalls: &cohereStreamToolCall{
			ID:       id,
			Type:     "function",
			Function: &cohereStreamToolFunction{Name: name},
		}},
	})
}

func cohereToolCallDeltaEvent(index int, arguments string) [][]byte {
	return cohereIndexed("tool-call-delta", index, cohereToolCallsDelta{
		Message: &cohereToolCallsDeltaMessage{ToolCalls: &cohereStreamToolCall{
			Function: &cohereStreamToolFunction{Arguments: arguments},
		}},
	})
}

func cohereToolCallEnd(index int) [][]byte {
	return cohereIndexed("tool-call-end", index, nil)
}

// cohereMessageEnd always sends usage, zeroed when the upstream reported none,
// since Cohere clients read delta.usage.billed_units from every message-end.
func cohereMessageEnd(finishReason, errMessage string, usage *CanonicalUsage) [][]byte {
	cu := cohereUsageFromCanonical(usage)
	if cu == nil {
		cu = &cohereUsage{BilledUnits: &cohereUsageTokens{}, Tokens: &cohereUsageTokens{}}
	}
	data, _ := json.Marshal(cohereMessageEndEvent{
		Type:  "message-end",
		Delta: cohereMessageEndDelta{FinishReason: finishReason, Error: errMessage, Usage: cu},
	})
	return SSEEvent("message-end", data)
}

// cohereFinish maps a canonical finish to a Cohere finish_reason and the
// delta.error message that goes with ERROR. Cohere has no content-filter
// reason, and COMPLETE would hide that the answer was withheld, so a refusal
// or content filter ends with ERROR "content filtered".
func cohereFinish(reason string) (string, string) {
	if message, failed := FinishFailure(reason); failed {
		return "ERROR", message
	}
	if refusalFinish(reason) {
		return "ERROR", "content filtered"
	}
	return canonicalFinishToCohere(reason), ""
}
