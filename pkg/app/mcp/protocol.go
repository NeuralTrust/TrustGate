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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

type Tool struct {
	Name string

	payload map[string]json.RawMessage
}

func (t Tool) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(t.payload, "name", t.Name)
}

func (t *Tool) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode tool: %w", err)
	}
	t.payload = payload
	t.Name = stringField(payload, "name")
	return nil
}

type Prompt struct {
	Name string

	payload map[string]json.RawMessage
}

func (p Prompt) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(p.payload, "name", p.Name)
}

func (p *Prompt) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode prompt: %w", err)
	}
	p.payload = payload
	p.Name = stringField(payload, "name")
	return nil
}

type Resource struct {
	Name string
	URI  string

	payload map[string]json.RawMessage
}

func (r Resource) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(r.payload, "name", r.Name, "uri", r.URI)
}

func (r *Resource) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode resource: %w", err)
	}
	r.payload = payload
	r.Name = stringField(payload, "name")
	r.URI = stringField(payload, "uri")
	return nil
}

type ResourceTemplate struct {
	Name        string
	URITemplate string

	payload map[string]json.RawMessage
}

func (rt ResourceTemplate) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(rt.payload, "name", rt.Name, "uriTemplate", rt.URITemplate)
}

func (rt *ResourceTemplate) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode resource template: %w", err)
	}
	rt.payload = payload
	rt.Name = stringField(payload, "name")
	rt.URITemplate = stringField(payload, "uriTemplate")
	return nil
}

func unmarshalEnvelope(data []byte) (map[string]json.RawMessage, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func marshalEnvelope(payload map[string]json.RawMessage, kv ...string) ([]byte, error) {
	out := make(map[string]json.RawMessage, len(payload)+len(kv)/2)
	for k, v := range payload {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		encoded, err := json.Marshal(kv[i+1])
		if err != nil {
			return nil, err
		}
		out[kv[i]] = encoded
	}
	return json.Marshal(out)
}

func stringField(payload map[string]json.RawMessage, key string) string {
	raw, ok := payload[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

type Target struct {
	URL     string
	Headers map[string]string
	PinKey  string
}

type RPCError struct {
	Code        int64
	Message     string
	Data        json.RawMessage
	HTTPHeaders map[string][]string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

func IsRPCError(err error) bool {
	var rpcErr *RPCError
	return errors.As(err, &rpcErr)
}

var ErrUnreachable = errors.New("mcp upstream unreachable")

var ErrNotSupported = errors.New("mcp upstream does not support this method")

type Upstream interface {
	ListTools(ctx context.Context) ([]Tool, error)
	CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error)
	ListResources(ctx context.Context) ([]Resource, error)
	ListResourceTemplates(ctx context.Context) ([]ResourceTemplate, error)
	ReadResource(ctx context.Context, uri string) (json.RawMessage, error)
	ListPrompts(ctx context.Context) ([]Prompt, error)
	GetPrompt(ctx context.Context, name string, arguments map[string]string) (json.RawMessage, error)
	SupportsResources() bool
	SupportsPrompts() bool
	Close(ctx context.Context)
}

type Dialer interface {
	Connect(ctx context.Context, target Target) (Upstream, error)
}

type DialerFunc func(ctx context.Context, target Target) (Upstream, error)

func (f DialerFunc) Connect(ctx context.Context, target Target) (Upstream, error) {
	return f(ctx, target)
}
