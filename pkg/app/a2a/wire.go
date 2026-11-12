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
	"encoding/json"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// Version is an A2A protocol version a registry is pinned to.
type Version = registrydomain.A2AProtocolVersion

const (
	Version03 = registrydomain.A2AVersion03
	Version10 = registrydomain.A2AVersion10
)

// Kind is what a method does, whatever its name in the version.
type Kind string

const (
	KindSend         Kind = "send"
	KindStream       Kind = "stream"
	KindGet          Kind = "get"
	KindCancel       Kind = "cancel"
	KindSubscribe    Kind = "subscribe"
	KindList         Kind = "list"
	KindPush         Kind = "push"
	KindExtendedCard Kind = "extended_card"
)

var methods = map[Version]map[string]Kind{
	Version03: {
		"message/send":                        KindSend,
		"message/stream":                      KindStream,
		"tasks/get":                           KindGet,
		"tasks/cancel":                        KindCancel,
		"tasks/resubscribe":                   KindSubscribe,
		"tasks/pushNotificationConfig/set":    KindPush,
		"tasks/pushNotificationConfig/get":    KindPush,
		"tasks/pushNotificationConfig/list":   KindPush,
		"tasks/pushNotificationConfig/delete": KindPush,
		"agent/getAuthenticatedExtendedCard":  KindExtendedCard,
	},
	Version10: {
		"SendMessage":                      KindSend,
		"SendStreamingMessage":             KindStream,
		"GetTask":                          KindGet,
		"CancelTask":                       KindCancel,
		"SubscribeToTask":                  KindSubscribe,
		"ListTasks":                        KindList,
		"CreateTaskPushNotificationConfig": KindPush,
		"GetTaskPushNotificationConfig":    KindPush,
		"ListTaskPushNotificationConfigs":  KindPush,
		"DeleteTaskPushNotificationConfig": KindPush,
		"GetExtendedAgentCard":             KindExtendedCard,
	},
}

// MethodKind returns the kind of a method of version v, and false for a
// method the version does not define.
func MethodKind(v Version, method string) (Kind, bool) {
	k, ok := methods[v][method]
	return k, ok
}

// Streams reports whether the kind answers with an event stream.
func (k Kind) Streams() bool {
	return k == KindStream || k == KindSubscribe
}

// Refusal is the error the gateway answers a kind it never forwards with, and
// nil for a kind it forwards.
func (k Kind) Refusal(v Version) *RPCError {
	switch k {
	case KindList:
		return UnsupportedOperation(v)
	case KindPush:
		return PushNotificationNotSupported(v)
	case KindExtendedCard:
		return ExtendedCardNotConfigured(v)
	}
	return nil
}

// Request is a JSON-RPC request.
type Request struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
}

// Decode reads a JSON-RPC 2.0 request made of a single object. The error is
// an *RPCError: -32700 for a body that is not JSON, -32600 for any other body
// that is not one request. The request comes back with the error when its id
// could be read, so the error can answer that id.
func Decode(body []byte) (*Request, error) {
	if !json.Valid(body) {
		return nil, parseError()
	}
	o, ok := decodeObject(body)
	if !ok {
		return nil, InvalidRequest()
	}
	req := &Request{Method: o.str("method"), Params: o["params"]}
	if id := bytes.TrimSpace(o["id"]); len(id) > 0 && (id[0] == '"' || id[0] == '-' || (id[0] >= '0' && id[0] <= '9')) {
		req.ID = id
	}
	if o.str("jsonrpc") != "2.0" || req.Method == "" || req.ID == nil {
		return req, InvalidRequest()
	}
	return req, nil
}

// Part is a message or artifact part in the gateway's normalised form, the
// same for every version.
type Part struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	URL       string          `json:"url,omitempty"`
	Raw       string          `json:"raw,omitempty"`
	MediaType string          `json:"media_type,omitempty"`
	Filename  string          `json:"filename,omitempty"`
}

// Part types.
const (
	PartText = "text"
	PartData = "data"
	PartFile = "file"
)

// Content is what the gateway reads from the params of a call or from a
// result: the task and context it names, the task state, and the parts to
// inspect.
type Content struct {
	TaskID    string
	ContextID string
	State     string
	Parts     []Part
}

// RequestContent reads the params of a call of kind k. Send and stream
// calls name the message's task and context and carry its parts; get,
// cancel and subscribe name a task. The error is -32602 for params that do
// not carry what the kind needs, since ownership cannot be checked without it.
func RequestContent(v Version, k Kind, params json.RawMessage) (Content, error) {
	switch k {
	case KindSend, KindStream:
		p, _ := decodeObject(params)
		m, ok := decodeObject(p["message"])
		if !ok {
			return Content{}, invalidParams()
		}
		return Content{
			TaskID:    m.str("taskId", "task_id"),
			ContextID: m.str("contextId", "context_id"),
			Parts:     parts(v, m["parts"]),
		}, nil
	case KindGet, KindCancel, KindSubscribe:
		p, _ := decodeObject(params)
		id := p.str("id")
		if id == "" {
			return Content{}, invalidParams()
		}
		return Content{TaskID: id}, nil
	}
	return Content{}, nil
}

// ResultContent reads a result or a stream event: a task, a message, a
// status update or an artifact update. The parts of a task are those of its
// status message, of its artifacts and of the agent's messages in its
// history.
func ResultContent(v Version, result json.RawMessage) (Content, error) {
	o, ok := decodeObject(result)
	if !ok {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	kind, body := resultKind(v, o)
	if body == nil {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	c := Content{TaskID: body.str("taskId", "task_id"), ContextID: body.str("contextId", "context_id")}
	switch kind {
	case "task":
		c.TaskID = body.str("id")
		c.State, c.Parts = status(v, body)
		for _, a := range body.list("artifacts") {
			art, _ := decodeObject(a)
			c.Parts = append(c.Parts, parts(v, art["parts"])...)
		}
		for _, h := range body.list("history") {
			m, _ := decodeObject(h)
			if isAgent(v, m.str("role")) {
				c.Parts = append(c.Parts, parts(v, m["parts"])...)
			}
		}
	case "message":
		c.Parts = parts(v, body["parts"])
	case "status-update":
		c.State, c.Parts = status(v, body)
	case "artifact-update":
		art, _ := decodeObject(body["artifact"])
		c.Parts = parts(v, art["parts"])
	default:
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	return c, nil
}

func resultKind(v Version, o object) (string, object) {
	if v == Version03 {
		return o.str("kind"), o
	}
	for _, w := range [][2]string{{"task", "task"}, {"message", "message"}, {"statusUpdate", "status-update"}, {"artifactUpdate", "artifact-update"}} {
		if body, ok := decodeObject(o[w[0]]); ok {
			return w[1], body
		}
	}
	if _, ok := o["id"]; ok {
		return "task", o
	}
	return "", nil
}

func status(v Version, o object) (string, []Part) {
	st, _ := decodeObject(o["status"])
	m, _ := decodeObject(st["message"])
	return st.str("state"), parts(v, m["parts"])
}

func isAgent(v Version, role string) bool {
	if v == Version03 {
		return role == "agent"
	}
	return role == "ROLE_AGENT"
}

func parts(v Version, raw json.RawMessage) []Part {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	out := make([]Part, 0, len(list))
	for _, item := range list {
		o, ok := decodeObject(item)
		if !ok {
			continue
		}
		var p Part
		if v == Version03 {
			p = part03(o)
		} else {
			p = part10(o)
		}
		if p.Type != "" {
			out = append(out, p)
		}
	}
	return out
}

func part03(o object) Part {
	switch o.str("kind") {
	case PartText:
		return Part{Type: PartText, Text: o.str("text")}
	case PartData:
		return Part{Type: PartData, Data: o["data"]}
	case PartFile:
		f, _ := decodeObject(o["file"])
		return Part{
			Type:      PartFile,
			URL:       f.str("uri"),
			Raw:       f.str("bytes"),
			MediaType: f.str("mimeType", "mime_type"),
			Filename:  f.str("name"),
		}
	}
	return Part{}
}

func part10(o object) Part {
	p := Part{MediaType: o.str("mediaType", "media_type"), Filename: o.str("filename")}
	switch {
	case o.has("text"):
		p.Type, p.Text = PartText, o.str("text")
	case o.has("data"):
		p.Type, p.Data = PartData, o["data"]
	case o.has("url"):
		p.Type, p.URL = PartFile, o.str("url")
	case o.has("raw"):
		p.Type, p.Raw = PartFile, o.str("raw")
	}
	return p
}

// object is a JSON object read with exact keys. encoding/json matches struct
// fields case-insensitively, which the agents' parsers do not, so a struct
// could read a different value than the agent acts on.
type object map[string]json.RawMessage

func decodeObject(raw json.RawMessage) (object, bool) {
	var o object
	if json.Unmarshal(raw, &o) != nil || o == nil {
		return nil, false
	}
	return o, true
}

// decodeMap reads a JSON object keeping numbers as they were written.
func decodeMap(raw []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	return m, dec.Decode(&m) == nil && m != nil
}

func (o object) has(key string) bool {
	raw, ok := o[key]
	return ok && string(bytes.TrimSpace(raw)) != "null"
}

func (o object) str(keys ...string) string {
	for _, k := range keys {
		var s string
		if raw, ok := o[k]; ok && json.Unmarshal(raw, &s) == nil {
			return s
		}
	}
	return ""
}

func (o object) list(key string) []json.RawMessage {
	var list []json.RawMessage
	_ = json.Unmarshal(o[key], &list)
	return list
}
