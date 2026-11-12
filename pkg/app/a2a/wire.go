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
	"errors"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
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
	KindSend         = Kind(registrydomain.A2AMethodSend)
	KindStream       = Kind(registrydomain.A2AMethodStream)
	KindGet          = Kind(registrydomain.A2AMethodGet)
	KindCancel       = Kind(registrydomain.A2AMethodCancel)
	KindSubscribe    = Kind(registrydomain.A2AMethodSubscribe)
	KindList         = Kind(registrydomain.A2AMethodList)
	KindPush         = Kind(registrydomain.A2AMethodPush)
	KindExtendedCard = Kind(registrydomain.A2AMethodExtendedCard)
)

// MethodKind returns the kind of a method of version v, and false for a
// method the version does not define.
func MethodKind(v Version, method string) (Kind, bool) {
	k, ok := registrydomain.A2AMethodKindOf(v, method)
	return Kind(k), ok
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
// -32700 for a body that is not JSON, -32600 for any other body that is not
// one request. The request comes back with the error when its id
// could be read, so the error can answer that id.
func Decode(body []byte) (*Request, *RPCError) {
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
	if o.str("jsonrpc") != "2.0" || req.Method == "" || req.ID == nil || !protocolKeysUnique(body) {
		return req, InvalidRequest()
	}
	return req, nil
}

// Part is a message or artifact part in the gateway's normalised form, the
// same for every version.
type Part = appplugins.A2APart

// Part types.
const (
	PartText = appplugins.A2APartText
	PartData = appplugins.A2APartData
	PartFile = appplugins.A2APartFile
)

// maxReferenceTaskIDs is how many other tasks one message may point to. Each
// is checked against its owner before the call is sent.
const maxReferenceTaskIDs = 32

// Content is what the gateway reads from the params of a call or from a
// result: the task and context it names, the task state, and the parts to
// inspect.
type Content struct {
	TaskID    string
	ContextID string
	// ReferenceTaskIDs are the other tasks a message points the agent to.
	ReferenceTaskIDs []string
	State            string
	Parts            []Part
}

// RequestContent reads the params of a call of kind k. Send and stream
// calls name the message's task and context and carry its parts; get,
// cancel and subscribe name a task. The error is -32602 for params that do
// not carry what the kind needs, since ownership cannot be checked without it,
// and for parts the gateway cannot read.
func RequestContent(v Version, k Kind, params json.RawMessage) (Content, *RPCError) {
	switch k {
	case KindSend, KindStream:
		p, _ := decodeObject(params)
		m, ok := decodeObject(p["message"])
		if !ok {
			return Content{}, invalidParams()
		}
		refs, ok := m.strings("referenceTaskIds", "reference_task_ids")
		if !ok || len(refs) > maxReferenceTaskIDs {
			return Content{}, invalidParams()
		}
		ps, err := parts(v, m["parts"])
		if err != nil {
			return Content{}, invalidParams()
		}
		return Content{
			TaskID:           m.str("taskId", "task_id"),
			ContextID:        m.str("contextId", "context_id"),
			ReferenceTaskIDs: refs,
			Parts:            ps,
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
func ResultContent(v Version, result json.RawMessage) (Content, *RPCError) {
	o, ok := decodeObject(result)
	if !ok {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	kind, body := resultKind(v, o)
	if body == nil {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	c := Content{TaskID: body.str("taskId", "task_id"), ContextID: body.str("contextId", "context_id")}
	var err error
	switch kind {
	case "task":
		c.TaskID = body.str("id")
		c.State, c.Parts, err = status(v, body)
		if err == nil {
			err = body.eachObject("artifacts", func(art object) error {
				return appendParts(&c.Parts, v, art["parts"])
			})
		}
		if err == nil {
			err = body.eachObject("history", func(m object) error {
				if !isAgent(v, m.str("role")) {
					return nil
				}
				return appendParts(&c.Parts, v, m["parts"])
			})
		}
	case "message":
		c.Parts, err = parts(v, body["parts"])
	case "status-update":
		c.State, c.Parts, err = status(v, body)
	case "artifact-update":
		art, ok := decodeObject(body["artifact"])
		if !ok && body.has("artifact") {
			err = errMalformedContent
		} else {
			c.Parts, err = parts(v, art["parts"])
		}
	default:
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	if err != nil {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	return c, nil
}

// StripTaskContent removes from a cancel answer the content a task carries:
// its artifacts, its history and its status message. A cancel only reports
// the task's state, and its content is read through get, where policies run.
func StripTaskContent(v Version, result json.RawMessage) (json.RawMessage, *RPCError) {
	m, ok := decodeMap(result)
	if !ok {
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	task := m
	if v == Version10 {
		if wrapped, ok := m["task"].(map[string]any); ok {
			task = wrapped
		}
	}
	delete(task, "artifacts")
	delete(task, "history")
	if status, ok := task["status"].(map[string]any); ok {
		delete(status, "message")
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	return out, nil
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

func status(v Version, o object) (string, []Part, error) {
	st, ok := decodeObject(o["status"])
	if !ok && o.has("status") {
		return "", nil, errMalformedContent
	}
	m, ok := decodeObject(st["message"])
	if !ok && st.has("message") {
		return "", nil, errMalformedContent
	}
	ps, err := parts(v, m["parts"])
	return st.str("state"), ps, err
}

func isAgent(v Version, role string) bool {
	if v == Version03 {
		return role == "agent"
	}
	return role == "ROLE_AGENT"
}

// errMalformedContent is a message, task or part whose shape the gateway
// cannot read. Content it cannot read is content the policies would not see,
// so the call fails instead.
var errMalformedContent = errors.New("a2a: malformed content")

// parts reads a list of parts. An absent list has no parts; a list that is
// not a JSON array, an item that is not an object, or a part of no known
// kind is malformed.
func parts(v Version, raw json.RawMessage) ([]Part, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil, errMalformedContent
	}
	out := make([]Part, 0, len(list))
	for _, item := range list {
		o, ok := decodeObject(item)
		if !ok {
			return nil, errMalformedContent
		}
		var p Part
		var err error
		if v == Version03 {
			p, err = part03(o)
		} else {
			p, err = part10(o)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func appendParts(dst *[]Part, v Version, raw json.RawMessage) error {
	ps, err := parts(v, raw)
	*dst = append(*dst, ps...)
	return err
}

func part03(o object) (Part, error) {
	switch o.str("kind") {
	case PartText:
		text, ok := o.text("text")
		if !ok {
			return Part{}, errMalformedContent
		}
		return Part{Type: PartText, Text: text}, nil
	case PartData:
		return Part{Type: PartData, Data: o["data"]}, nil
	case PartFile:
		f, ok := decodeObject(o["file"])
		if !ok {
			return Part{}, errMalformedContent
		}
		uri, okURI := f.text("uri")
		raw, okRaw := f.text("bytes")
		if !okURI || !okRaw {
			return Part{}, errMalformedContent
		}
		return Part{
			Type:      PartFile,
			URL:       uri,
			Raw:       raw,
			MediaType: f.str("mimeType", "mime_type"),
			Filename:  f.str("name"),
		}, nil
	}
	return Part{}, errMalformedContent
}

func part10(o object) (Part, error) {
	p := Part{MediaType: o.str("mediaType", "media_type"), Filename: o.str("filename")}
	var ok bool
	switch {
	case o.has("text"):
		p.Type = PartText
		p.Text, ok = o.text("text")
	case o.has("data"):
		p.Type, p.Data, ok = PartData, o["data"], true
	case o.has("url"):
		p.Type = PartFile
		p.URL, ok = o.text("url")
	case o.has("raw"):
		p.Type = PartFile
		p.Raw, ok = o.text("raw")
	}
	if !ok {
		return Part{}, errMalformedContent
	}
	return p, nil
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

// protocolKeysUnique reports whether the request, its params, the message
// and configuration in them, and each part of the message name every key
// once, ignoring case and underscores. The gateway reads keys exactly while
// some agents match them case-insensitively, accept a key in snake case, or
// keep the first of two duplicates, so a repeated key could make the agent act
// on a value the gateway never checked. The values of data parts and of
// metadata are the caller's own payload and are not inspected.
func protocolKeysUnique(body []byte) bool {
	if !uniqueKeys(body) {
		return false
	}
	o, _ := decodeObject(body)
	params, ok := decodeObject(o["params"])
	if !ok {
		return true
	}
	if !uniqueKeys(o["params"]) {
		return false
	}
	for _, key := range []string{"message", "configuration"} {
		if raw, ok := params[key]; ok && !uniqueKeys(raw) {
			return false
		}
	}
	message, _ := decodeObject(params["message"])
	var items []json.RawMessage
	if json.Unmarshal(message["parts"], &items) != nil {
		return true
	}
	for _, item := range items {
		if !uniqueKeys(item) {
			return false
		}
		part, _ := decodeObject(item)
		if raw, ok := part["file"]; ok && !uniqueKeys(raw) {
			return false
		}
	}
	return true
}

// uniqueKeys reports whether a JSON object names every key once, ignoring
// case and underscores. A value that is not an object has no keys to repeat.
func uniqueKeys(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return true
	}
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		key, _ := tok.(string)
		folded := strings.ReplaceAll(strings.ToLower(strings.ToUpper(key)), "_", "")
		if _, dup := seen[folded]; dup {
			return false
		}
		seen[folded] = struct{}{}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return false
		}
	}
	return true
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

// strings reads the first of keys that is present as a list of strings, and
// false when it is present but not one.
func (o object) strings(keys ...string) ([]string, bool) {
	for _, k := range keys {
		if !o.has(k) {
			continue
		}
		var out []string
		if json.Unmarshal(o[k], &out) != nil {
			return nil, false
		}
		return out, true
	}
	return nil, true
}

// text reads key as a string. An absent or null key is the empty string; a
// value of another type is not text.
func (o object) text(key string) (string, bool) {
	if !o.has(key) {
		return "", true
	}
	var s string
	return s, json.Unmarshal(o[key], &s) == nil
}

// eachObject calls fn with each object of the list under key. An absent list
// is empty; a list that is not an array, or an item that is not an object, is
// malformed.
func (o object) eachObject(key string, fn func(object) error) error {
	if !o.has(key) {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(o[key], &list) != nil {
		return errMalformedContent
	}
	for _, item := range list {
		obj, ok := decodeObject(item)
		if !ok {
			return errMalformedContent
		}
		if err := fn(obj); err != nil {
			return err
		}
	}
	return nil
}
