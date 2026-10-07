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

package strategies

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type sr1Message struct {
	Role      string          `json:"role"`
	Type      string          `json:"type"`
	Content   json.RawMessage `json:"content"`
	Parts     json.RawMessage `json:"parts"`
	ToolCalls json.RawMessage `json:"tool_calls"`
}

type sr1ContentBlock struct {
	Type                  string          `json:"type"`
	Text                  string          `json:"text"`
	ToolUse               json.RawMessage `json:"toolUse"`
	ToolResult            json.RawMessage `json:"toolResult"`
	FunctionCall          json.RawMessage `json:"functionCall"`
	FunctionResponse      json.RawMessage `json:"functionResponse"`
	FunctionCallSnake     json.RawMessage `json:"function_call"`
	FunctionResponseSnake json.RawMessage `json:"function_response"`
}

func sr1Input(body []byte) (string, string, bool, error) {
	var request map[string]json.RawMessage
	if err := json.Unmarshal(body, &request); err != nil {
		return "", "", false, err
	}
	for _, field := range []string{"prompt", "input"} {
		var text string
		if json.Unmarshal(request[field], &text) == nil && strings.TrimSpace(text) != "" {
			return text, "prompt:" + text, true, nil
		}
	}
	messages := request["messages"]
	gemini := false
	if len(messages) == 0 {
		messages = request["input"]
	}
	if len(messages) == 0 {
		messages, gemini = request["contents"], true
	}
	var items []sr1Message
	if err := json.Unmarshal(messages, &items); err != nil {
		return "", "", false, err
	}
	for i := len(items) - 1; i >= 0; i-- {
		isUser := items[i].Role == "user" || (gemini && items[i].Role == "")
		if !isUser {
			continue
		}
		content := items[i].content()
		if sr1ToolOnly(content) {
			continue
		}
		text := sr1Text(content)
		if strings.TrimSpace(text) == "" {
			return "", "", false, errors.New("latest user turn has no text")
		}
		newUser := true
		for _, suffix := range items[i+1:] {
			if !suffix.prefill() {
				newUser = false
				break
			}
		}
		return text, fmt.Sprintf("%d:%s", i, text), newUser, nil
	}
	if len(items) > 0 {
		last := items[len(items)-1]
		if last.Role == "tool" || last.Type == "function_call_output" || sr1ToolOnly(last.content()) {
			return "", "continuation", false, nil
		}
	}
	return "", "", false, errors.New("no user turn")
}

func (m sr1Message) content() json.RawMessage {
	if len(m.Parts) != 0 {
		return m.Parts
	}
	return m.Content
}

func (m sr1Message) prefill() bool {
	if (m.Role != "assistant" && m.Role != "model") || m.Type == "function_call" || (sr1Present(m.ToolCalls) && string(m.ToolCalls) != "[]") {
		return false
	}
	var blocks []sr1ContentBlock
	if json.Unmarshal(m.content(), &blocks) == nil {
		for _, block := range blocks {
			if block.Type == "tool_use" || sr1Present(block.ToolUse) || sr1Present(block.FunctionCall) || sr1Present(block.FunctionCallSnake) {
				return false
			}
		}
	}
	return true
}

func sr1Text(content json.RawMessage) string {
	var text string
	if json.Unmarshal(content, &text) == nil {
		return text
	}
	var blocks []sr1ContentBlock
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	parts := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if block.Type == "text" || block.Type == "input_text" || (block.Type == "" && block.Text != "") {
			parts = append(parts, block.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func sr1ToolOnly(content json.RawMessage) bool {
	var blocks []sr1ContentBlock
	if json.Unmarshal(content, &blocks) != nil || len(blocks) == 0 {
		return false
	}
	for _, block := range blocks {
		if block.Type != "tool_result" && !sr1Present(block.ToolResult) && !sr1Present(block.FunctionResponse) && !sr1Present(block.FunctionResponseSnake) {
			return false
		}
	}
	return true
}

func sr1Present(value json.RawMessage) bool {
	return len(value) != 0 && strings.TrimSpace(string(value)) != "null"
}
