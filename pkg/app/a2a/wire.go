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
	// Notification marks a request that is valid but has no id member: a
	// JSON-RPC notification, which is not answered. A2A has no notification
	// method, so the gateway forwards none.
	Notification bool
}

// Decode reads a JSON-RPC 2.0 request made of a single object. The error is
// -32700 for a body that is not JSON, -32600 for any other body that is not
// one request. The request comes back with the error when its id
// could be read, so the error can answer that id, and with Notification set
// when the only thing missing is the id member.
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
	if o.str("jsonrpc") != "2.0" || req.Method == "" || !protocolKeysUnique(body) {
		return req, InvalidRequest()
	}
	if req.ID == nil {
		_, hasID := o["id"]
		req.Notification = !hasID
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
	// Parts are the content the policies read: the parts of the messages and
	// artifacts, then the text and data the protocol carries beside them (an
	// artifact's name and description, and every metadata object), as text and
	// data parts.
	Parts []Part
	// Paths places the inspected value of each part in the call's body (for a
	// request) or in the result, so a mask can be written back; nil for a part
	// whose value cannot be written (a file).
	Paths []Path
	// ArtifactID, Append and LastChunk describe an artifact-update event: the
	// artifact it adds to, whether its parts append to the ones sent before
	// (a chunk of a streamed artifact), and whether it is the last chunk.
	ArtifactID        string
	Append, LastChunk bool
}

// Path is where a value sits in a JSON document: object keys (string) and
// list indexes (int), from the root.
type Path []any

// to is p with segs appended, in a new slice.
func (p Path) to(segs ...any) Path {
	out := make(Path, 0, len(p)+len(segs))
	return append(append(out, p...), segs...)
}

// collector reads the parts of a call or a result with their paths. The
// parts of messages and artifacts come first, in order; the text and data the
// protocol carries beside them (names, descriptions, metadata) follow, so
// adding them leaves the place of every part unchanged.
type collector struct {
	v          Version
	parts      []Part
	paths      []Path
	extra      []Part
	extraPaths []Path
}

func (c *collector) content() ([]Part, []Path) {
	return append(c.parts, c.extra...), append(c.paths, c.extraPaths...)
}

// list reads the list of parts under key of o, which sits at at. An absent
// list has no parts; a list that is not a JSON array, an item that is not an
// object, or a part of no known kind is malformed. A part's own metadata is
// read too.
func (c *collector) list(o object, key string, at Path) error {
	raw := o[key]
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return errMalformedContent
	}
	for i, item := range items {
		po, ok := decodeObject(item)
		if !ok {
			return errMalformedContent
		}
		var p Part
		var err error
		if c.v == Version03 {
			p, err = part03(po)
		} else {
			p, err = part10(po)
		}
		if err != nil {
			return err
		}
		at := at.to(key, i)
		var path Path
		switch p.Type {
		case PartText:
			path = at.to("text")
		case PartData:
			path = at.to("data")
		}
		c.parts = append(c.parts, p)
		c.paths = append(c.paths, path)
		c.metadata(po, at)
	}
	return nil
}

// message reads a message's parts and metadata. o sits at at.
func (c *collector) message(o object, at Path) error {
	if err := c.list(o, "parts", at); err != nil {
		return err
	}
	c.metadata(o, at)
	return nil
}

// artifact reads an artifact's parts, name, description and metadata.
func (c *collector) artifact(o object, at Path) error {
	if err := c.list(o, "parts", at); err != nil {
		return err
	}
	c.text(o, "name", at)
	c.text(o, "description", at)
	c.metadata(o, at)
	return nil
}

// text reads the string under key of o as an extra text part. A missing,
// empty or non-string value adds none.
func (c *collector) text(o object, key string, at Path) {
	if s := o.str(key); strings.TrimSpace(s) != "" {
		c.extra = append(c.extra, Part{Type: PartText, Text: s})
		c.extraPaths = append(c.extraPaths, at.to(key))
	}
}

// metadata reads the metadata of o, the caller's or the agent's own payload
// the protocol carries beside the parts, as an extra data part. An absent,
// null or empty one adds none.
func (c *collector) metadata(o object, at Path) {
	raw := bytes.TrimSpace(o["metadata"])
	switch string(raw) {
	case "", "null", "{}", "[]", `""`:
		return
	}
	c.extra = append(c.extra, Part{Type: PartData, Data: json.RawMessage(raw)})
	c.extraPaths = append(c.extraPaths, at.to("metadata"))
}

// RequestContent reads the params of a call of kind k. Send and stream
// calls name the message's task and context and carry its parts; get,
// cancel and subscribe name a task. The paths of the parts are from the root
// of the call's body. The error is -32602 for params that do not carry what
// the kind needs, since ownership cannot be checked without it, and for parts
// the gateway cannot read.
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
		c := collector{v: v}
		if err := c.message(m, Path{"params", "message"}); err != nil {
			return Content{}, invalidParams()
		}
		c.metadata(p, Path{"params"})
		ps, paths := c.content()
		if !filesCarryContent(ps) {
			return Content{}, invalidParams()
		}
		return Content{
			TaskID:           m.str("taskId", "task_id"),
			ContextID:        m.str("contextId", "context_id"),
			ReferenceTaskIDs: refs,
			Parts:            ps,
			Paths:            paths,
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
// history; the paths of the parts are from the root of the result.
func ResultContent(v Version, result json.RawMessage) (Content, *RPCError) {
	o, ok := decodeObject(result)
	if !ok {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	kind, body, at := resultKind(v, o)
	if body == nil {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	c := Content{TaskID: body.str("taskId", "task_id"), ContextID: body.str("contextId", "context_id")}
	col := collector{v: v}
	var err error
	switch kind {
	case "task":
		c.TaskID = body.str("id")
		c.State, err = col.status(body, at)
		if err == nil {
			err = body.eachObject("artifacts", func(i int, art object) error {
				return col.artifact(art, at.to("artifacts", i))
			})
		}
		if err == nil {
			err = body.eachObject("history", func(i int, m object) error {
				if !isAgent(v, m.str("role")) {
					return nil
				}
				return col.message(m, at.to("history", i))
			})
		}
		col.metadata(body, at)
	case "message":
		err = col.message(body, at)
	case "status-update":
		c.State, err = col.status(body, at)
		col.metadata(body, at)
	case "artifact-update":
		art, ok := decodeObject(body["artifact"])
		if !ok && body.has("artifact") {
			err = errMalformedContent
		} else {
			err = col.artifact(art, at.to("artifact"))
			c.ArtifactID = art.str("artifactId", "artifact_id")
		}
		c.Append = body.flag("append")
		c.LastChunk = body.flag("lastChunk", "last_chunk")
		col.metadata(body, at)
	default:
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	if err != nil {
		return Content{}, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	c.Parts, c.Paths = col.content()
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

// resultKind is the kind of a result, the object that carries it and where
// that object sits: the result itself in 0.3, under its kind's key in 1.0.
func resultKind(v Version, o object) (string, object, Path) {
	if v == Version03 {
		return o.str("kind"), o, Path{}
	}
	for _, w := range [][2]string{{"task", "task"}, {"message", "message"}, {"statusUpdate", "status-update"}, {"artifactUpdate", "artifact-update"}} {
		if body, ok := decodeObject(o[w[0]]); ok {
			return w[1], body, Path{w[0]}
		}
	}
	if _, ok := o["id"]; ok {
		return "task", o, Path{}
	}
	return "", nil, nil
}

// status reads the state of a task or a status update o, which sits at at,
// and the parts and metadata of its status message.
func (c *collector) status(o object, at Path) (string, error) {
	st, ok := decodeObject(o["status"])
	if !ok && o.has("status") {
		return "", errMalformedContent
	}
	m, ok := decodeObject(st["message"])
	if !ok && st.has("message") {
		return "", errMalformedContent
	}
	if err := c.message(m, at.to("status", "message")); err != nil {
		return "", err
	}
	return st.str("state"), nil
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

// filesCarryContent reports whether every file part of a request is its bytes
// or its url, one of the two. A file with neither (such as fileWithBytes,
// Vertex's REST name, not A2A's) would reach the agent and the policies empty.
func filesCarryContent(ps []Part) bool {
	for _, p := range ps {
		if p.Type == PartFile && (p.URL == "") == (p.Raw == "") {
			return false
		}
	}
	return true
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

// flag reads the first of keys that is present as a boolean, false when
// none is or it is not one.
func (o object) flag(keys ...string) bool {
	for _, k := range keys {
		var b bool
		if raw, ok := o[k]; ok && json.Unmarshal(raw, &b) == nil {
			return b
		}
	}
	return false
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

// eachObject calls fn with the index and object of each item of the list
// under key. An absent list is empty; a list that is not an array, or an item
// that is not an object, is malformed.
func (o object) eachObject(key string, fn func(int, object) error) error {
	if !o.has(key) {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(o[key], &list) != nil {
		return errMalformedContent
	}
	for i, item := range list {
		obj, ok := decodeObject(item)
		if !ok {
			return errMalformedContent
		}
		if err := fn(i, obj); err != nil {
			return err
		}
	}
	return nil
}
