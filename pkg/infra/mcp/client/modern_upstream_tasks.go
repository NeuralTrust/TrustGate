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

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

const (
	base64SentinelPrefix = "=?base64?"
	base64SentinelSuffix = "?="
)

type modernRoutingKey struct{}

type modernRouting struct {
	method string
	name   string
}

// withModernRouting carries the southbound Mcp-Method/Mcp-Name pair. The headers
// are only reachable from the round tripper, and the SDK transport takes no
// per-request header argument, so the context is the only channel. Scoped to
// tasks/* in this change.
func withModernRouting(ctx context.Context, method, name string) context.Context {
	return context.WithValue(ctx, modernRoutingKey{}, modernRouting{method: method, name: name})
}

func setModernRoutingHeaders(req *http.Request) {
	routing, ok := req.Context().Value(modernRoutingKey{}).(modernRouting)
	if !ok || routing.method == "" {
		return
	}
	req.Header.Set("Mcp-Method", routing.method)
	if routing.name != "" {
		req.Header.Set("Mcp-Name", encodeHeaderValue(routing.name))
	}
}

// encodeHeaderValue mirrors the northbound sentinel form: a value that is not
// safe as a plain header field is wrapped as =?base64?<std b64>?=.
func encodeHeaderValue(value string) string {
	if plainModernHeaderValue(value) {
		return value
	}
	return base64SentinelPrefix + base64.StdEncoding.EncodeToString([]byte(value)) + base64SentinelSuffix
}

func plainModernHeaderValue(value string) bool {
	if value == "" || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// taskParams is the wire shape of every tasks/* request. go-sdk v1.7.0 ships no
// Tasks types, so the params are hand-rolled here.
type taskParams struct {
	Meta           sdk.Meta        `json:"_meta,omitempty"`
	TaskID         string          `json:"taskId"`
	InputResponses json.RawMessage `json:"inputResponses,omitempty"`
}

// GetTask polls one upstream task. ref carries the real upstream taskId; the
// northbound handle never reaches the wire.
func (m *modernUpstream) GetTask(ctx context.Context, ref appmcp.TaskRef) (json.RawMessage, error) {
	return m.callTask(ctx, appmcp.MethodTasksGet, ref, nil)
}

// UpdateTask answers an input_required task.
func (m *modernUpstream) UpdateTask(
	ctx context.Context,
	ref appmcp.TaskRef,
	inputResponses json.RawMessage,
) (json.RawMessage, error) {
	return m.callTask(ctx, appmcp.MethodTasksUpdate, ref, inputResponses)
}

// CancelTask requests cancellation of one upstream task.
func (m *modernUpstream) CancelTask(ctx context.Context, ref appmcp.TaskRef) (json.RawMessage, error) {
	return m.callTask(ctx, appmcp.MethodTasksCancel, ref, nil)
}

func (m *modernUpstream) callTask(
	ctx context.Context,
	method string,
	ref appmcp.TaskRef,
	inputResponses json.RawMessage,
) (json.RawMessage, error) {
	params := &taskParams{
		Meta:           m.metadataForTask(ctx),
		TaskID:         ref.TaskID,
		InputResponses: inputResponses,
	}
	return m.call(withModernRouting(ctx, method, ref.TaskID), method, params)
}

// metadataForTask declares the tasks extension southbound. An upstream that sees
// no extension may refuse to serve tasks/*, so it is declared unconditionally on
// these methods: reaching them at all means the northbound client declared it.
func (m *modernUpstream) metadataForTask(ctx context.Context) sdk.Meta {
	meta := m.metadata()
	caps := make(map[string]any, len(appmcp.ClientCapabilitiesFromContext(ctx))+1)
	for kind, value := range appmcp.ClientCapabilitiesFromContext(ctx) {
		caps[kind] = value
	}
	caps[appmcp.CapabilityKindExtensions] = map[string]any{
		appmcp.MetaKeyTasksExtension: map[string]any{},
	}
	meta[sdk.MetaKeyClientCapabilities] = caps
	return meta
}
