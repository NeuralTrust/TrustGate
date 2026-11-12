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
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/google/uuid"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// Agents reached through their provider's API, not A2A: an Amazon Bedrock
// AgentCore harness (InvokeHarness) and a Databricks agent (the Responses
// shape of a ResponsesAgent). The gateway takes message/send only: it sends
// the message's text and answers with the agent's reply as an A2A 0.3
// message. The conversation is the call's contextId, or a new one the reply
// names, so the caller continues it by sending that contextId back.

// codeAgentError is the JSON-RPC code of an error the agent itself answered.
const codeAgentError = -32603

func agentError(message string) *RPCError {
	return &RPCError{Code: codeAgentError, Message: cmp.Or(strings.TrimSpace(message), "The agent failed to answer.")}
}

// conversation names the call's conversation: its contextId, or a new one.
func conversation(x *Exchange) string {
	if x.session == "" {
		x.session = cmp.Or(x.content.ContextID, uuid.NewString())
	}
	return x.session
}

// messageText is the text of the message the caller sent: its text parts,
// and its data parts as JSON. A file cannot be sent to these agents.
func messageText(x *Exchange) (string, *RPCError) {
	if x.kind != KindSend {
		return "", UnsupportedOperation(x.version)
	}
	var texts []string
	for _, part := range x.content.Parts {
		switch part.Type {
		case PartText:
			texts = append(texts, part.Text)
		case PartData:
			texts = append(texts, string(part.Data))
		default:
			return "", &RPCError{Code: -32005, Message: "This agent takes text only: send the file's content as text."}
		}
	}
	text := strings.TrimSpace(strings.Join(texts, "\n"))
	if text == "" {
		return "", invalidParams()
	}
	return text, nil
}

// replyMessage is the agent's answer as the A2A 0.3 message result.
func replyMessage(x *Exchange, text string) (json.RawMessage, *RPCError, bool) {
	raw, err := json.Marshal(map[string]any{
		"kind":      "message",
		"messageId": uuid.NewString(),
		"role":      "agent",
		"contextId": conversation(x),
		"parts":     []map[string]any{{"kind": "text", "text": text}},
	})
	if err != nil {
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse), false
	}
	return raw, nil, false
}

// failedCall maps an error status of the provider's API: its credential
// refused, a request it rejected (with its own message), or a failure.
func failedCall(status int, message string) (json.RawMessage, *RPCError, bool) {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, GatewayFailure(ReasonUpstreamAuthFailed), false
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity || status == http.StatusNotFound:
		return nil, agentError(message), true
	default:
		return nil, GatewayFailure(ReasonUpstreamError), false
	}
}

func post(ctx context.Context, endpoint string, h http.Header, payload any) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = h
	return req, nil
}

type translated struct{}

func (translated) retry(*RPCError, int) (time.Duration, bool) { return 0, false }

func (translated) capabilities() capabilities { return capabilities{jsonrpcOnlyCard: true} }

// harness is an Amazon Bedrock AgentCore harness. The conversation is its
// runtime session: the harness keeps the history of a session itself.
type harness struct{ translated }

// harnessSession is the runtime session of a conversation. AgentCore takes 33
// to 100 characters of [A-Za-z0-9_-], so a contextId that is not one of those
// is hashed.
func harnessSession(contextID string) string {
	session := "tgc-" + contextID
	if len(session) < 33 || len(session) > 100 || strings.Trim(session, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		sum := sha256.Sum256([]byte(contextID))
		session = "tgc-" + hex.EncodeToString(sum[:])
	}
	return session
}

func (harness) header(x *Exchange, h http.Header) {
	h.Set(registrydomain.AgentCoreSessionHeader, harnessSession(conversation(x)))
	h.Set("Accept", "application/vnd.amazon.eventstream")
}

func (harness) request(ctx context.Context, x *Exchange, endpoint string, h http.Header, _ []byte) (*http.Request, error) {
	text, rpcErr := messageText(x)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return post(ctx, endpoint, h, map[string]any{
		"messages": []map[string]any{{"role": "user", "content": []map[string]any{{"text": text}}}},
	})
}

// decode reads InvokeHarness's event stream: the text of the agent's messages,
// or the error it ended with.
func (harness) decode(x *Exchange, res *http.Response, body []byte) (json.RawMessage, *RPCError, bool) {
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var aws struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &aws)
		return failedCall(res.StatusCode, aws.Message)
	}
	var (
		texts   []string
		current strings.Builder
		role    string
	)
	flush := func() {
		if text := strings.TrimSpace(current.String()); text != "" && role != "user" {
			texts = append(texts, text)
		}
		current.Reset()
	}
	decoder := eventstream.NewDecoder()
	reader := bytes.NewReader(body)
	for {
		msg, err := decoder.Decode(reader, nil)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, GatewayFailure(ReasonInvalidUpstreamResponse), false
		}
		var event struct {
			Role    string `json:"role"`
			Message string `json:"message"`
			Delta   struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		_ = json.Unmarshal(msg.Payload, &event)
		messageType, eventType := eventHeader(msg.Headers, ":message-type"), eventHeader(msg.Headers, ":event-type")
		switch {
		case messageType == "exception" || messageType == "error":
			return nil, agentError(event.Message), true
		case eventType == "messageStart":
			flush()
			role = event.Role
		case eventType == "contentBlockDelta":
			current.WriteString(event.Delta.Text)
		case eventType == "contentBlockStop", eventType == "messageStop":
			flush()
		case eventType == "runtimeClientError" || eventType == "validationException" || eventType == "internalServerException":
			return nil, agentError(event.Message), true
		}
	}
	flush()
	if len(texts) == 0 {
		return nil, agentError("The agent finished without a text answer."), true
	}
	return replyMessage(x, strings.Join(texts, "\n\n"))
}

func eventHeader(headers eventstream.Headers, name string) string {
	if v := headers.Get(name); v != nil {
		return v.String()
	}
	return ""
}

// databricks is a Databricks agent (a ResponsesAgent on Model Serving or in a
// Databricks App). The conversation goes as context.conversation_id; an agent
// keeps its history only if it stores it under that id.
type databricks struct{ translated }

func (databricks) header(x *Exchange, _ http.Header) {
	conversation(x)
}

func (databricks) request(ctx context.Context, x *Exchange, endpoint string, h http.Header, _ []byte) (*http.Request, error) {
	text, rpcErr := messageText(x)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return post(ctx, endpoint, h, map[string]any{
		"input":   []map[string]any{{"role": "user", "content": text}},
		"context": map[string]any{"conversation_id": conversation(x)},
	})
}

// decode reads a Responses-shaped answer: the output_text of its message items.
func (databricks) decode(x *Exchange, res *http.Response, body []byte) (json.RawMessage, *RPCError, bool) {
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var dbx struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &dbx)
		return failedCall(res.StatusCode, dbx.Message)
	}
	var answer struct {
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse), false
	}
	var texts []string
	for _, item := range answer.Output {
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			if content.Type == "output_text" && strings.TrimSpace(content.Text) != "" {
				texts = append(texts, content.Text)
			}
		}
	}
	if len(texts) == 0 {
		return nil, agentError("The agent finished without a text answer."), true
	}
	return replyMessage(x, strings.Join(texts, "\n\n"))
}
