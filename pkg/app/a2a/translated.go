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
	"bufio"
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
//
// message/stream answers a task as A2A 0.3 streams one: the task working, the
// agent's text as one artifact appended chunk by chunk, then the task
// completed.

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
	if x.kind != KindSend && x.kind != KindStream {
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
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, GatewayFailure(ReasonUpstreamAuthFailed), false
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusNotFound:
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

func (translated) capabilities() capabilities {
	return capabilities{streams: true, jsonrpcOnlyCard: true}
}

// tokenUsage is what an agent reports it used.
type tokenUsage struct{ input, output int }

func (u *tokenUsage) add(input, output int) {
	u.input += input
	u.output += output
}

// streamTranslator reads a provider's own stream for a message/stream call and
// sends each A2A 0.3 event as a JSON-RPC response.
type streamTranslator interface {
	readStream(x *Exchange, body io.Reader, send func(sseEvent) bool)
}

// taskStream writes the events of a translated stream.
type taskStream struct {
	x          *Exchange
	send       func(sseEvent) bool
	taskID     string
	artifactID string
	started    bool
	chunked    bool
}

func newTaskStream(x *Exchange, send func(sseEvent) bool) *taskStream {
	return &taskStream{x: x, send: send, taskID: uuid.NewString(), artifactID: uuid.NewString()}
}

func (t *taskStream) emit(envelope map[string]any) bool {
	envelope["jsonrpc"] = "2.0"
	raw, err := json.Marshal(envelope)
	if err != nil {
		return t.send(sseEvent{err: err})
	}
	return t.send(sseEvent{data: raw})
}

func (t *taskStream) start() bool {
	if t.started {
		return true
	}
	t.started = true
	return t.emit(map[string]any{"result": map[string]any{
		"kind": "task", "id": t.taskID, "contextId": conversation(t.x),
		"status": map[string]any{"state": "working", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}})
}

// text sends a chunk of the agent's answer, appended to the one artifact.
func (t *taskStream) text(chunk string) bool {
	if chunk == "" {
		return true
	}
	if !t.start() {
		return false
	}
	ok := t.emit(map[string]any{"result": map[string]any{
		"kind": "artifact-update", "taskId": t.taskID, "contextId": conversation(t.x), "append": t.chunked,
		"artifact": map[string]any{"artifactId": t.artifactID, "name": "answer", "parts": []map[string]any{{"kind": "text", "text": chunk}}},
	}})
	t.chunked = true
	return ok
}

func (t *taskStream) completed() {
	if !t.start() {
		return
	}
	t.emit(map[string]any{"result": map[string]any{
		"kind": "status-update", "taskId": t.taskID, "contextId": conversation(t.x), "final": true,
		"status": map[string]any{"state": "completed", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}})
}

// fail ends the stream with the error the agent answered.
func (t *taskStream) fail(message string) {
	e := agentError(message)
	t.emit(map[string]any{"error": map[string]any{"code": e.Code, "message": e.Message}})
}

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

// harnessEvents reads InvokeHarness's event stream from r, calling text with
// each chunk of an assistant message's text (and "" between messages) until
// the stream ends, the agent ends it with an error, or text returns false. It
// records the tokens the metadata events report.
func harnessEvents(x *Exchange, r io.Reader, text func(chunk string, boundary bool) bool) (agentErr string, err error) {
	decoder := eventstream.NewDecoder()
	role := ""
	for {
		msg, err := decoder.Decode(r, nil)
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		var event struct {
			Role    string `json:"role"`
			Message string `json:"message"`
			Delta   struct {
				Text string `json:"text"`
			} `json:"delta"`
			Usage struct {
				InputTokens  int `json:"inputTokens"`
				OutputTokens int `json:"outputTokens"`
			} `json:"usage"`
		}
		_ = json.Unmarshal(msg.Payload, &event)
		messageType, eventType := eventHeader(msg.Headers, ":message-type"), eventHeader(msg.Headers, ":event-type")
		switch {
		case messageType == "exception" || messageType == "error":
			return cmp.Or(event.Message, "The agent failed to answer."), nil
		case eventType == "messageStart":
			role = event.Role
			if !text("", true) {
				return "", nil
			}
		case eventType == "contentBlockDelta" && role != "user":
			if !text(event.Delta.Text, false) {
				return "", nil
			}
		case eventType == "metadata":
			x.tokens.add(event.Usage.InputTokens, event.Usage.OutputTokens)
		case eventType == "runtimeClientError" || eventType == "validationException" || eventType == "internalServerException":
			return cmp.Or(event.Message, "The agent failed to answer."), nil
		}
	}
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
	var texts []string
	var current strings.Builder
	flush := func() {
		if text := strings.TrimSpace(current.String()); text != "" {
			texts = append(texts, text)
		}
		current.Reset()
	}
	agentErr, err := harnessEvents(x, bytes.NewReader(body), func(chunk string, boundary bool) bool {
		if boundary {
			flush()
		}
		current.WriteString(chunk)
		return true
	})
	if err != nil {
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse), false
	}
	if agentErr != "" {
		return nil, agentError(agentErr), true
	}
	flush()
	if len(texts) == 0 {
		return nil, agentError("The agent finished without a text answer."), true
	}
	return replyMessage(x, strings.Join(texts, "\n\n"))
}

// readStream relays the harness's text as it comes, a blank line between its
// messages.
func (harness) readStream(x *Exchange, body io.Reader, send func(sseEvent) bool) {
	t := newTaskStream(x, send)
	ok, wrote, pending := true, false, false
	agentErr, err := harnessEvents(x, body, func(chunk string, boundary bool) bool {
		if boundary {
			pending = wrote
			return true
		}
		if chunk == "" {
			return true
		}
		// A blank line between messages, written before the next text only.
		if pending {
			pending = false
			if ok = t.text("\n\n"); !ok {
				return false
			}
		}
		wrote = true
		ok = t.text(chunk)
		return ok
	})
	switch {
	case !ok:
	case err != nil:
		send(sseEvent{err: err})
	case agentErr != "":
		t.fail(agentErr)
	default:
		t.completed()
	}
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
	payload := map[string]any{
		"input":   []map[string]any{{"role": "user", "content": text}},
		"context": map[string]any{"conversation_id": conversation(x)},
	}
	if x.kind.Streams() {
		payload["stream"] = true
	}
	for key, value := range databricksInputs(x) {
		payload[key] = value
	}
	return post(ctx, endpoint, h, payload)
}

// databricksInputs are the ResponsesAgent inputs a caller passes in A2A
// metadata: custom_inputs (the agent's own inputs) and databricks_options
// (return_trace…), from the message's metadata or else the call's.
func databricksInputs(x *Exchange) map[string]json.RawMessage {
	var params struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
		Message  struct {
			Metadata map[string]json.RawMessage `json:"metadata"`
		} `json:"message"`
	}
	_ = json.Unmarshal(x.call.Request.Params, &params)
	out := map[string]json.RawMessage{}
	for _, key := range []string{"custom_inputs", "databricks_options"} {
		for _, metadata := range []map[string]json.RawMessage{params.Message.Metadata, params.Metadata} {
			if value, ok := metadata[key]; ok && len(value) > 0 && value[0] == '{' {
				out[key] = value
				break
			}
		}
	}
	return out
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
		Output []responsesItem `json:"output"`
		Usage  responsesUsage  `json:"usage"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse), false
	}
	x.tokens.add(answer.Usage.InputTokens, answer.Usage.OutputTokens)
	var texts []string
	for _, item := range answer.Output {
		if text := item.text(); text != "" {
			texts = append(texts, text)
		}
	}
	if len(texts) == 0 {
		return nil, agentError("The agent finished without a text answer."), true
	}
	return replyMessage(x, strings.Join(texts, "\n\n"))
}

// responsesItem is an output item of a Responses-shaped answer.
type responsesItem struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// text is the output_text of a message item.
func (i responsesItem) text() string {
	if i.Type != "message" {
		return ""
	}
	var texts []string
	for _, content := range i.Content {
		if content.Type == "output_text" && strings.TrimSpace(content.Text) != "" {
			texts = append(texts, content.Text)
		}
	}
	return strings.Join(texts, "\n\n")
}

type responsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// readStream relays a Responses stream: the output_text deltas as they come,
// and the text of a message item that came without deltas when it is done.
func (databricks) readStream(x *Exchange, body io.Reader, send func(sseEvent) bool) {
	t := newTaskStream(x, send)
	streamed := map[string]bool{}
	wrote := false
	text := func(itemID, chunk string) bool {
		if chunk == "" {
			return true
		}
		if wrote && !streamed[itemID] {
			if !t.text("\n\n") {
				return false
			}
		}
		streamed[itemID], wrote = true, true
		return t.text(chunk)
	}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxEventBytes)
	for scanner.Scan() {
		data, ok := bytes.CutPrefix(scanner.Bytes(), []byte("data:"))
		data = bytes.TrimSpace(data)
		if !ok || len(data) == 0 || string(data) == "[DONE]" {
			continue
		}
		var event struct {
			Type    string        `json:"type"`
			ItemID  string        `json:"item_id"`
			Delta   string        `json:"delta"`
			Item    responsesItem `json:"item"`
			Message string        `json:"message"`
			Error   *struct {
				Message string `json:"message"`
			} `json:"error"`
			Response struct {
				Usage responsesUsage `json:"usage"`
			} `json:"response"`
		}
		if json.Unmarshal(data, &event) != nil {
			continue
		}
		switch {
		case event.Error != nil || event.Type == "error" || event.Type == "response.failed":
			message := event.Message
			if event.Error != nil {
				message = cmp.Or(event.Error.Message, message)
			}
			t.fail(message)
			return
		case event.Type == "response.output_text.delta":
			if !text(event.ItemID, event.Delta) {
				return
			}
		case event.Type == "response.output_item.done" && !streamed[event.Item.ID]:
			if !text(event.Item.ID, event.Item.text()) {
				return
			}
		case event.Type == "response.completed":
			x.tokens.add(event.Response.Usage.InputTokens, event.Response.Usage.OutputTokens)
		}
	}
	if err := scanner.Err(); err != nil {
		send(sseEvent{err: err})
		return
	}
	t.completed()
}
