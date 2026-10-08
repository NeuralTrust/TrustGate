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
	"strings"
)

// invokeShape is the model-native shape of an InvokeModel body. It is read from
// the JSON itself, the only signal that works for every identifier: an ARN or an
// inference profile carries no model family to key on.
type invokeShape int

const (
	shapeConverse invokeShape = iota
	shapeAnthropic
	shapeTitan
	shapePrompt
	shapeCohereChat
	shapeOpenAI
	shapeUnknown
)

const (
	roleUser      = "user"
	roleAssistant = "assistant"

	invocationMetricsKey = "amazon-bedrock-invocationMetrics"
)

var converseRequestKeys = []string{"system", "inferenceConfig", "toolConfig", "additionalModelRequestFields", "guardrailConfig"}

var converseStreamKeys = []string{
	"messageStart", "contentBlockStart", "contentBlockDelta", "contentBlockStop", "messageStop", "metadata",
}

func jsonFields(body []byte) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

func hasField(fields map[string]json.RawMessage, keys ...string) bool {
	for _, k := range keys {
		if _, ok := fields[k]; ok {
			return true
		}
	}
	return false
}

func isStringField(fields map[string]json.RawMessage, key string) bool {
	raw := fields[key]
	return len(raw) > 0 && raw[0] == '"'
}

func stringField(fields map[string]json.RawMessage, key string) string {
	var s string
	if err := json.Unmarshal(fields[key], &s); err != nil {
		return ""
	}
	return s
}

func sniffInvokeRequest(fields map[string]json.RawMessage) invokeShape {
	switch {
	case hasField(fields, "anthropic_version"):
		return shapeAnthropic
	case hasField(fields, "inputText"):
		return shapeTitan
	case isStringField(fields, "prompt"):
		return shapePrompt
	case isStringField(fields, "message"):
		return shapeCohereChat
	case hasField(fields, "messages"):
		if messagesAreOpenAI(fields["messages"]) {
			return shapeOpenAI
		}
		return shapeConverse
	case hasField(fields, converseRequestKeys...):
		return shapeConverse
	default:
		return shapeUnknown
	}
}

func messagesAreOpenAI(raw json.RawMessage) bool {
	var messages []struct {
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &messages) != nil {
		return false
	}
	for _, m := range messages {
		if len(m.Content) == 0 {
			continue
		}
		if m.Content[0] == '"' {
			return true
		}
		var blocks []map[string]json.RawMessage
		if json.Unmarshal(m.Content, &blocks) != nil {
			continue
		}
		for _, b := range blocks {
			if _, ok := b["type"]; ok {
				return true
			}
		}
	}
	return false
}

func decodeTitanRequest(body []byte) *CanonicalRequest {
	var req struct {
		InputText            string `json:"inputText"`
		TextGenerationConfig struct {
			MaxTokenCount int      `json:"maxTokenCount"`
			Temperature   *float64 `json:"temperature"`
			TopP          *float64 `json:"topP"`
			StopSequences []string `json:"stopSequences"`
		} `json:"textGenerationConfig"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil
	}
	cfg := req.TextGenerationConfig
	return &CanonicalRequest{
		Messages:    []CanonicalMessage{{Role: roleUser, Content: req.InputText}},
		MaxTokens:   cfg.MaxTokenCount,
		Temperature: cfg.Temperature,
		TopP:        cfg.TopP,
		Stop:        cfg.StopSequences,
	}
}

func decodePromptRequest(body []byte) *CanonicalRequest {
	var req struct {
		Prompt            string   `json:"prompt"`
		MaxGenLen         int      `json:"max_gen_len"`
		MaxTokens         int      `json:"max_tokens"`
		MaxTokensToSample int      `json:"max_tokens_to_sample"`
		Temperature       *float64 `json:"temperature"`
		TopP              *float64 `json:"top_p"`
		P                 *float64 `json:"p"`
		Stop              []string `json:"stop"`
		StopSequences     []string `json:"stop_sequences"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil
	}
	cr := &CanonicalRequest{
		Messages:    []CanonicalMessage{{Role: roleUser, Content: req.Prompt}},
		MaxTokens:   firstPositive(req.MaxGenLen, req.MaxTokens, req.MaxTokensToSample),
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stop:        req.Stop,
	}
	if cr.TopP == nil {
		cr.TopP = req.P
	}
	if len(cr.Stop) == 0 {
		cr.Stop = req.StopSequences
	}
	return cr
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func decodeCohereChatRequest(body []byte) *CanonicalRequest {
	var req struct {
		Message     string `json:"message"`
		Preamble    string `json:"preamble"`
		ChatHistory []struct {
			Role    string `json:"role"`
			Message string `json:"message"`
		} `json:"chat_history"`
		MaxTokens     int      `json:"max_tokens"`
		Temperature   *float64 `json:"temperature"`
		P             *float64 `json:"p"`
		StopSequences []string `json:"stop_sequences"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil
	}
	cr := &CanonicalRequest{
		System:      req.Preamble,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.P,
		Stop:        req.StopSequences,
	}
	for _, turn := range req.ChatHistory {
		cr.Messages = append(cr.Messages, CanonicalMessage{Role: cohereChatRole(turn.Role), Content: turn.Message})
	}
	cr.Messages = append(cr.Messages, CanonicalMessage{Role: roleUser, Content: req.Message})
	return cr
}

func cohereChatRole(role string) string {
	switch strings.ToUpper(role) {
	case "CHATBOT":
		return roleAssistant
	case "SYSTEM":
		return "system"
	default:
		return roleUser
	}
}

func decodeTitanResponse(body []byte) *CanonicalResponse {
	var resp struct {
		InputTextTokenCount int `json:"inputTextTokenCount"`
		Results             []struct {
			TokenCount       int    `json:"tokenCount"`
			OutputText       string `json:"outputText"`
			CompletionReason string `json:"completionReason"`
		} `json:"results"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	cr := &CanonicalResponse{Role: roleAssistant}
	var out int
	for _, r := range resp.Results {
		cr.Content += r.OutputText
		out += r.TokenCount
		if cr.FinishReason == "" {
			cr.FinishReason = titanFinishReason(r.CompletionReason)
		}
	}
	cr.Usage = newCanonicalUsage(resp.InputTextTokenCount, out, 0)
	return cr
}

func titanFinishReason(reason string) string {
	switch strings.ToUpper(reason) {
	case "":
		return ""
	case "LENGTH":
		return "length"
	case "CONTENT_FILTERED":
		return "content_filter"
	default:
		return "stop"
	}
}

func decodeLlamaResponse(body []byte) *CanonicalResponse {
	var resp struct {
		Generation           string `json:"generation"`
		PromptTokenCount     int    `json:"prompt_token_count"`
		GenerationTokenCount int    `json:"generation_token_count"`
		StopReason           string `json:"stop_reason"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	return &CanonicalResponse{
		Role:         roleAssistant,
		Content:      resp.Generation,
		FinishReason: promptStopReason(resp.StopReason),
		Usage:        newCanonicalUsage(resp.PromptTokenCount, resp.GenerationTokenCount, 0),
	}
}

func promptStopReason(reason string) string {
	switch reason {
	case "":
		return ""
	case "length", "max_tokens":
		return "length"
	default:
		return "stop"
	}
}

func decodeMistralResponse(body []byte) *CanonicalResponse {
	var resp struct {
		Outputs []struct {
			Text       string `json:"text"`
			StopReason string `json:"stop_reason"`
		} `json:"outputs"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	cr := &CanonicalResponse{Role: roleAssistant}
	for _, o := range resp.Outputs {
		cr.Content += o.Text
		if cr.FinishReason == "" {
			cr.FinishReason = promptStopReason(o.StopReason)
		}
	}
	return cr
}

func decodeCohereResponse(body []byte) *CanonicalResponse {
	var resp struct {
		Text         string `json:"text"`
		FinishReason string `json:"finish_reason"`
		Generations  []struct {
			Text         string `json:"text"`
			FinishReason string `json:"finish_reason"`
		} `json:"generations"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	cr := &CanonicalResponse{Role: roleAssistant, Content: resp.Text, FinishReason: cohereFinishReason(resp.FinishReason)}
	for _, g := range resp.Generations {
		cr.Content += g.Text
		if cr.FinishReason == "" {
			cr.FinishReason = cohereFinishReason(g.FinishReason)
		}
	}
	return cr
}

func cohereFinishReason(reason string) string {
	switch strings.ToUpper(reason) {
	case "":
		return ""
	case "MAX_TOKENS":
		return "length"
	default:
		return "stop"
	}
}

func decodeTitanChunk(chunk []byte) *CanonicalStreamChunk {
	var ev struct {
		OutputText                string  `json:"outputText"`
		CompletionReason          *string `json:"completionReason"`
		InputTextTokenCount       int     `json:"inputTextTokenCount"`
		TotalOutputTextTokenCount int     `json:"totalOutputTextTokenCount"`
	}
	if json.Unmarshal(chunk, &ev) != nil {
		return nil
	}
	out := &CanonicalStreamChunk{Delta: ev.OutputText}
	if ev.CompletionReason != nil {
		out.FinishReason = titanFinishReason(*ev.CompletionReason)
	}
	out.Usage = newCanonicalUsage(ev.InputTextTokenCount, ev.TotalOutputTextTokenCount, 0)
	return out
}

func decodeLlamaChunk(chunk []byte) *CanonicalStreamChunk {
	var ev struct {
		Generation           string  `json:"generation"`
		PromptTokenCount     *int    `json:"prompt_token_count"`
		GenerationTokenCount *int    `json:"generation_token_count"`
		StopReason           *string `json:"stop_reason"`
	}
	if json.Unmarshal(chunk, &ev) != nil {
		return nil
	}
	out := &CanonicalStreamChunk{Delta: ev.Generation}
	if ev.StopReason != nil {
		out.FinishReason = promptStopReason(*ev.StopReason)
	}
	if ev.PromptTokenCount != nil || ev.GenerationTokenCount != nil {
		out.Usage = newCanonicalUsage(derefInt(ev.PromptTokenCount), derefInt(ev.GenerationTokenCount), 0)
	}
	return out
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func decodeMistralChunk(chunk []byte) *CanonicalStreamChunk {
	var ev struct {
		Outputs []struct {
			Text       string  `json:"text"`
			StopReason *string `json:"stop_reason"`
		} `json:"outputs"`
	}
	if json.Unmarshal(chunk, &ev) != nil {
		return nil
	}
	out := &CanonicalStreamChunk{}
	for _, o := range ev.Outputs {
		out.Delta += o.Text
		if o.StopReason != nil && out.FinishReason == "" {
			out.FinishReason = promptStopReason(*o.StopReason)
		}
	}
	return out
}

func decodeCohereChunk(chunk []byte) *CanonicalStreamChunk {
	var ev struct {
		Text         string `json:"text"`
		FinishReason string `json:"finish_reason"`
	}
	if json.Unmarshal(chunk, &ev) != nil {
		return nil
	}
	return &CanonicalStreamChunk{Delta: ev.Text, FinishReason: cohereFinishReason(ev.FinishReason)}
}

func invocationMetricsUsage(raw json.RawMessage) *CanonicalUsage {
	if len(raw) == 0 {
		return nil
	}
	var m struct {
		InputTokenCount      int `json:"inputTokenCount"`
		OutputTokenCount     int `json:"outputTokenCount"`
		CacheReadTokenCount  int `json:"cacheReadInputTokenCount"`
		CacheWriteTokenCount int `json:"cacheWriteInputTokenCount"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	read, write := m.CacheReadTokenCount, m.CacheWriteTokenCount
	usage := newCanonicalUsage(m.InputTokenCount+read+write, m.OutputTokenCount, 0)
	if usage == nil {
		return nil
	}
	usage.setCache(read, write, 0)
	return usage
}
