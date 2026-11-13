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

package a2a

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// The OpenAI chat completions bridge: an application that speaks the OpenAI
// API calls an agent as a model. Each request sends its last user message as
// one A2A message through the same forwarder (policies, ownership, the
// registry's credential), and the agent's answer comes back as a chat
// completion, or as chunks when it streams. The agent keeps the conversation:
// its contextId comes back in the X-AG-A2A-Context-Id header (and on every
// chunk), and a request that sends it continues the conversation.

// HeaderA2AContextID carries the conversation of a chat completions call.
const HeaderA2AContextID = "X-AG-A2A-Context-Id"

// ChatRequest is the part of an OpenAI chat completions request the bridge reads.
type ChatRequest struct {
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Stream bool `json:"stream"`
}

// LastUserText is the text of the last user message: a string, or the text
// parts of a content array.
func (r ChatRequest) LastUserText() (string, bool) {
	for i := len(r.Messages) - 1; i >= 0; i-- {
		m := r.Messages[i]
		if m.Role != "user" {
			continue
		}
		var text string
		if json.Unmarshal(m.Content, &text) == nil {
			return text, strings.TrimSpace(text) != ""
		}
		var parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(m.Content, &parts) != nil {
			return "", false
		}
		var texts []string
		for _, p := range parts {
			if p.Type == "text" && p.Text != "" {
				texts = append(texts, p.Text)
			}
		}
		text = strings.Join(texts, "\n")
		return text, strings.TrimSpace(text) != ""
	}
	return "", false
}

// CanStream reports whether the gateway relays the agent's streams: its card
// says it streams and its provider's streams are relayed.
func CanStream(t *registrydomain.A2ATarget) bool {
	return Streaming(t.Card) && providerOf(t).capabilities().streams
}

// ChatCall is the A2A call that sends text: message/send or message/stream in
// 0.3, SendMessage or SendStreamingMessage in 1.0, continuing contextID when
// it is set.
func ChatCall(v Version, streaming bool, text, contextID string) []byte {
	messageID := uuid.NewString()
	var method string
	var message map[string]any
	if v == Version10 {
		method = map[bool]string{false: "SendMessage", true: "SendStreamingMessage"}[streaming]
		message = map[string]any{"messageId": messageID, "role": "ROLE_USER", "parts": []map[string]any{{"text": text}}}
	} else {
		method = map[bool]string{false: "message/send", true: "message/stream"}[streaming]
		message = map[string]any{"kind": "message", "messageId": messageID, "role": "user", "parts": []map[string]any{{"kind": "text", "text": text}}}
	}
	if contextID != "" {
		message["contextId"] = contextID
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": messageID, "method": method, "params": map[string]any{"message": message}})
	return raw
}

// ChatText is the agent's text in a result or a stream event, and the
// conversation it names. A task's answer is its artifacts, else its status
// message; a status update counts only its message once the task stops
// working, since a working status carries progress notes.
func ChatText(v Version, result json.RawMessage) (text, contextID string) {
	var o map[string]json.RawMessage
	if json.Unmarshal(result, &o) != nil {
		return "", ""
	}
	kind := ""
	body := o
	if v == Version10 {
		for _, w := range [][2]string{{"task", "task"}, {"message", "message"}, {"statusUpdate", "status-update"}, {"artifactUpdate", "artifact-update"}} {
			if inner, ok := o[w[0]]; ok && json.Unmarshal(inner, &body) == nil {
				kind = w[1]
				break
			}
		}
	} else {
		_ = json.Unmarshal(o["kind"], &kind)
	}
	_ = json.Unmarshal(body["contextId"], &contextID)
	var texts []string
	switch kind {
	case "message":
		texts = partsText(body["parts"])
	case "artifact-update":
		var art map[string]json.RawMessage
		_ = json.Unmarshal(body["artifact"], &art)
		texts = partsText(art["parts"])
	case "task":
		var artifacts []map[string]json.RawMessage
		_ = json.Unmarshal(body["artifacts"], &artifacts)
		for _, a := range artifacts {
			texts = append(texts, partsText(a["parts"])...)
		}
		if len(texts) == 0 {
			texts = statusText(body["status"], false)
		}
	case "status-update":
		texts = statusText(body["status"], true)
	}
	return strings.Join(texts, ""), contextID
}

func statusText(raw json.RawMessage, finalOnly bool) []string {
	var status struct {
		State   string `json:"state"`
		Message struct {
			Parts json.RawMessage `json:"parts"`
		} `json:"message"`
	}
	if json.Unmarshal(raw, &status) != nil {
		return nil
	}
	state := strings.ToLower(strings.TrimPrefix(status.State, "TASK_STATE_"))
	if finalOnly && (state == "working" || state == "submitted") {
		return nil
	}
	return partsText(status.Message.Parts)
}

// partsText is the text of the text parts, in either version.
func partsText(raw json.RawMessage) []string {
	var parts []struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &parts)
	var texts []string
	for _, p := range parts {
		if (p.Kind == "" || p.Kind == "text") && p.Text != "" {
			texts = append(texts, p.Text)
		}
	}
	return texts
}

// Version is the A2A version the call speaks.
func (x *Exchange) Version() Version {
	return x.version
}

// Tokens is what the agent reported it used on this call.
func (x *Exchange) Tokens() (input, output int) {
	return x.tokens.input, x.tokens.output
}

// ChatStatus is the HTTP status and OpenAI error type of an A2A error.
func ChatStatus(e *RPCError) (int, string) {
	switch e.Code {
	case CodePolicyBlocked:
		return http.StatusForbidden, "policy_blocked"
	case CodeRateLimited:
		return http.StatusTooManyRequests, "rate_limit_exceeded"
	case CodeIdentityRequired:
		return http.StatusUnauthorized, "authentication_error"
	case CodeGatewayFailure, codeAgentError:
		return http.StatusBadGateway, "upstream_error"
	case CodeTaskNotFound:
		return http.StatusNotFound, "not_found"
	default:
		return http.StatusBadRequest, "invalid_request_error"
	}
}
