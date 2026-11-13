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

package watsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"strings"
	"time"
)

// chatParams are the OpenAI Chat Completions fields watsonx takes under the
// same name, plus the watsonx-only sampling and guided-decoding fields a
// caller can send through an OpenAI SDK's extra body. Everything else is
// dropped: watsonx rejects fields it does not know.
var chatParams = []string{
	"temperature",
	"top_p",
	"frequency_penalty",
	"presence_penalty",
	"seed",
	"n",
	"logprobs",
	"top_logprobs",
	"logit_bias",
	"response_format",
	"reasoning_effort",
	"time_limit",
	"include_reasoning",
	"repetition_penalty",
	"length_penalty",
	"guided_choice",
	"guided_regex",
	"guided_grammar",
	"guided_json",
	"chat_template_kwargs",
}

var errNoModel = errors.New("watsonx: a model is required")

type object = map[string]json.RawMessage

// modelChoice is the model the gateway resolved for the call, and the
// application default used when neither it nor the body names one.
type modelChoice struct {
	configured string
	fallback   string
}

// buildChatRequest turns an OpenAI Chat Completions body into a watsonx
// text/chat body. The project always comes from the registry: a body that
// names its own project_id or space_id must not steer the registry's
// credentials to another project.
func buildChatRequest(body []byte, choice modelChoice, projectID string) ([]byte, error) {
	var in object
	if err := json.Unmarshal(body, &in); err != nil || in == nil {
		return nil, errors.New("watsonx: request body must be a JSON object")
	}
	model := choice.configured
	if model == "" {
		model = jsonString(in["model"])
	}
	if model == "" {
		model = choice.fallback
	}
	if model == "" {
		return nil, errNoModel
	}

	out := map[string]any{
		"model_id":   model,
		"project_id": projectID,
	}

	messages, err := translateMessages(in["messages"])
	if err != nil {
		return nil, err
	}
	out["messages"] = messages

	for _, key := range chatParams {
		if v, ok := in[key]; ok && !isNull(v) {
			out[key] = v
		}
	}

	if v := in["max_completion_tokens"]; !isNull(v) {
		out["max_tokens"] = v
	} else if v := in["max_tokens"]; !isNull(v) {
		out["max_tokens"] = v
	}

	if stop := in["stop"]; !isNull(stop) {
		if s, ok := asString(stop); ok {
			out["stop"] = []string{s}
		} else {
			out["stop"] = stop
		}
	}

	tools := translateTools(in["tools"])
	if len(tools) > 0 {
		out["tools"] = tools
		applyToolChoice(out, in["tool_choice"])
	}

	return json.Marshal(out)
}

func translateMessages(raw json.RawMessage) ([]object, error) {
	if isNull(raw) {
		return nil, errors.New("watsonx: messages are required")
	}
	var in []object
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, errors.New("watsonx: messages must be an array of objects")
	}
	out := make([]object, 0, len(in))
	for _, msg := range in {
		out = append(out, translateMessage(msg))
	}
	return out, nil
}

func translateMessage(msg object) object {
	role := jsonString(msg["role"])
	if role == "developer" {
		role = "system"
	}
	out := object{"role": mustJSON(role)}
	if name, ok := msg["name"]; ok && !isNull(name) {
		out["name"] = name
	}

	switch role {
	case "user":
		if content, ok := msg["content"]; ok {
			out["content"] = content
		}
	case "system":
		out["content"] = mustJSON(flattenText(msg["content"]))
	case "assistant":
		calls := translateToolCalls(msg["tool_calls"], false)
		text := flattenText(msg["content"])
		if text != "" || len(calls) == 0 {
			out["content"] = mustJSON(text)
		}
		if len(calls) > 0 {
			out["tool_calls"] = mustJSON(calls)
		}
	case "tool":
		out["tool_call_id"] = msg["tool_call_id"]
		out["content"] = mustJSON(flattenText(msg["content"]))
	default:
		for k, v := range msg {
			if k != "role" {
				out[k] = v
			}
		}
	}
	return out
}

// flattenText returns the text of an OpenAI content field: watsonx takes only
// a string on system, assistant and tool messages.
func flattenText(raw json.RawMessage) string {
	if s, ok := asString(raw); ok {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		if (p.Type == "text" || p.Type == "") && p.Text != "" {
			texts = append(texts, p.Text)
		}
	}
	return strings.Join(texts, "\n")
}

type toolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

type tool struct {
	Type     string       `json:"type"`
	Function toolFunction `json:"function"`
}

var emptyParameters = json.RawMessage(`{"type":"object","properties":{}}`)

func translateTools(raw json.RawMessage) []tool {
	if isNull(raw) {
		return nil
	}
	var in []struct {
		Type     string `json:"type"`
		Function *struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	out := make([]tool, 0, len(in))
	for _, t := range in {
		if (t.Type != "" && t.Type != "function") || t.Function == nil || t.Function.Name == "" {
			continue
		}
		params := t.Function.Parameters
		if isNull(params) {
			params = emptyParameters
		}
		out = append(out, tool{
			Type: "function",
			Function: toolFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  params,
			},
		})
	}
	return out
}

// applyToolChoice maps OpenAI's tool_choice onto watsonx, which takes the
// "none" / "auto" / "required" modes as tool_choice_option and a named
// function as tool_choice.
func applyToolChoice(out map[string]any, raw json.RawMessage) {
	if isNull(raw) {
		return
	}
	if mode, ok := asString(raw); ok {
		switch mode {
		case "none", "auto", "required":
			out["tool_choice_option"] = mode
		}
		return
	}
	var named struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &named) != nil || named.Type != "function" || named.Function.Name == "" {
		return
	}
	out["tool_choice"] = map[string]any{
		"type":     "function",
		"function": map[string]string{"name": named.Function.Name},
	}
}

// translateToolCalls normalises tool calls in either direction: arguments are
// always a JSON-encoded string, and stream deltas always carry an index.
func translateToolCalls(raw json.RawMessage, delta bool) []object {
	if isNull(raw) {
		return nil
	}
	var in []object
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	out := make([]object, 0, len(in))
	for i, call := range in {
		next := object{}
		for k, v := range call {
			next[k] = v
		}
		if !delta || !isNull(call["id"]) {
			if isNull(call["type"]) {
				next["type"] = mustJSON("function")
			}
		}
		if delta && isNull(call["index"]) {
			next["index"] = mustJSON(i)
		}
		if fn, ok := call["function"]; ok && !isNull(fn) {
			next["function"] = normalizeFunction(fn)
		}
		out = append(out, next)
	}
	return out
}

func normalizeFunction(raw json.RawMessage) json.RawMessage {
	var fn object
	if json.Unmarshal(raw, &fn) != nil {
		return raw
	}
	args, ok := fn["arguments"]
	if !ok || isNull(args) {
		return raw
	}
	if _, isString := asString(args); isString {
		return raw
	}
	fn["arguments"] = mustJSON(string(bytes.TrimSpace(args)))
	return mustJSON(fn)
}

// watsonxOnlyFields are top-level response fields OpenAI clients have no slot
// for.
var watsonxOnlyFields = []string{"model_id", "model_version", "created_at", "system"}

func translateResponse(body []byte) ([]byte, error) {
	out, err := translateEnvelope(body, "chat.completion", "message")
	if err != nil {
		return nil, fmt.Errorf("watsonx: decoding chat response: %w", err)
	}
	return out, nil
}

func translateStreamChunk(payload []byte) ([]byte, error) {
	return translateEnvelope(payload, "chat.completion.chunk", "delta")
}

func translateEnvelope(body []byte, kind, messageKey string) ([]byte, error) {
	var resp object
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("not a JSON object")
	}
	if isNull(resp["model"]) && !isNull(resp["model_id"]) {
		resp["model"] = resp["model_id"]
	}
	for _, field := range watsonxOnlyFields {
		delete(resp, field)
	}
	resp["object"] = mustJSON(kind)
	if isNull(resp["created"]) {
		resp["created"] = mustJSON(time.Now().Unix())
	}
	if choices, ok := resp["choices"]; ok && !isNull(choices) {
		resp["choices"] = translateChoices(choices, messageKey)
	}
	return json.Marshal(resp)
}

func translateChoices(raw json.RawMessage, messageKey string) json.RawMessage {
	var choices []object
	if json.Unmarshal(raw, &choices) != nil {
		return raw
	}
	delta := messageKey == "delta"
	for _, choice := range choices {
		if reason, ok := asString(choice["finish_reason"]); ok {
			choice["finish_reason"] = mustJSON(finishReason(reason))
		}
		var msg object
		if json.Unmarshal(choice[messageKey], &msg) != nil || msg == nil {
			continue
		}
		if calls := translateToolCalls(msg["tool_calls"], delta); calls != nil {
			msg["tool_calls"] = mustJSON(calls)
		}
		choice[messageKey] = mustJSON(msg)
	}
	return mustJSON(choices)
}

func finishReason(reason string) string {
	switch reason {
	case "stop", "length", "tool_calls", "content_filter", "function_call":
		return reason
	case "max_tokens", "token_limit", "time_limit":
		return "length"
	default:
		return "stop"
	}
}

// translateStream rewrites a watsonx chat_stream SSE body into OpenAI Chat
// Completions SSE lines. watsonx frames each chunk with id and event lines and
// never sends [DONE]; an `event: error` frame becomes OpenAI's in-band error
// chunk and ends the stream.
func translateStream(upstream iter.Seq2[[]byte, error]) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		errorFrame := false
		for line, err := range upstream {
			if err != nil {
				yield(nil, err)
				return
			}
			trimmed := bytes.TrimSpace(line)
			switch {
			case len(trimmed) == 0:
				errorFrame = false
				if !yield([]byte{}, nil) {
					return
				}
			case bytes.HasPrefix(trimmed, []byte("event:")):
				errorFrame = string(bytes.TrimSpace(trimmed[len("event:"):])) == "error"
			case bytes.HasPrefix(trimmed, []byte("data:")):
				payload := bytes.TrimSpace(trimmed[len("data:"):])
				if errorFrame {
					if yield(dataLine(streamErrorChunk(payload)), nil) {
						yield([]byte{}, nil)
					}
					return
				}
				if bytes.Equal(payload, []byte("[DONE]")) {
					yieldDone(yield)
					return
				}
				chunk, err := translateStreamChunk(payload)
				if err != nil {
					continue
				}
				if !yield(dataLine(chunk), nil) {
					return
				}
			}
		}
		yieldDone(yield)
	}
}

func yieldDone(yield func([]byte, error) bool) {
	if yield([]byte("data: [DONE]"), nil) {
		yield([]byte{}, nil)
	}
}

func dataLine(payload []byte) []byte {
	return append([]byte("data: "), payload...)
}

type ibmErrorBody struct {
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Trace      string `json:"trace"`
	StatusCode int    `json:"status_code"`
}

// openAIErrorBody rewrites a watsonx error body into OpenAI's error envelope,
// which is what the gateway relays to OpenAI-dialect callers unchanged.
func openAIErrorBody(status int, body []byte) []byte {
	var parsed ibmErrorBody
	if json.Unmarshal(body, &parsed) != nil || len(parsed.Errors) == 0 {
		var existing struct {
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(body, &existing) == nil && !isNull(existing.Error) {
			return body
		}
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = http.StatusText(status)
		}
		return encodeOpenAIError(status, "", msg)
	}
	messages := make([]string, 0, len(parsed.Errors))
	for _, e := range parsed.Errors {
		if m := strings.TrimSpace(e.Message); m != "" {
			messages = append(messages, m)
		}
	}
	msg := strings.Join(messages, "; ")
	if msg == "" {
		msg = http.StatusText(status)
	}
	if parsed.Trace != "" {
		msg += " (watsonx trace " + parsed.Trace + ")"
	}
	return encodeOpenAIError(status, parsed.Errors[0].Code, msg)
}

func streamErrorChunk(payload []byte) []byte {
	status := http.StatusInternalServerError
	var parsed ibmErrorBody
	if json.Unmarshal(payload, &parsed) == nil && parsed.StatusCode >= 400 {
		status = parsed.StatusCode
	}
	return openAIErrorBody(status, payload)
}

func encodeOpenAIError(status int, code, message string) []byte {
	errObj := map[string]any{
		"message": message,
		"type":    openAIErrorType(status),
	}
	if code != "" {
		errObj["code"] = code
	} else {
		errObj["code"] = nil
	}
	return mustJSON(map[string]any{"error": errObj})
}

func openAIErrorType(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "authentication_error"
	case status == http.StatusForbidden:
		return "permission_error"
	case status == http.StatusNotFound:
		return "not_found_error"
	case status == http.StatusTooManyRequests:
		return "rate_limit_error"
	case status >= 400 && status < 500:
		return "invalid_request_error"
	default:
		return "api_error"
	}
}

func isNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

func asString(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func jsonString(raw json.RawMessage) string {
	s, _ := asString(raw)
	return strings.TrimSpace(s)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
