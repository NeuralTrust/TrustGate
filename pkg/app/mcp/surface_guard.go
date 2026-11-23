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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
)

// A prompt or a resource reaches the model just as a tool's result does: a
// server can put an injection or personal data in either, and a prompt's
// arguments are the user's words sent to the server. So prompts/get and
// resources/read run the request and response stages too, with the unscoped
// policies (a scope names tools, and these are not tools).
//
// The plugins know one MCP shape, a tools/call: {name, arguments} on the way
// in and a CallToolResult on the way out. Rather than teach every plugin two
// more, the runner is handed each call in that shape and what the plugins
// write back is carried into the real one:
//
//   - prompts/get goes in as {name: <prompt>, arguments: <its arguments>};
//     a masked argument is sent to the server masked.
//   - resources/read goes in as {name: "resources/read", arguments: {uri}}.
//     A policy may refuse the read, but the URI is an address the server
//     listed, not text: a mask of it is dropped, as discovery drops one.
//   - a GetPromptResult's description and each message's text or embedded
//     resource, and a ReadResourceResult's text contents, go out as the
//     content blocks of a CallToolResult; each masked block is written back
//     where it came from. Images, audio and blobs carry no text, as in a tool's
//     result.
//
// A request stage that answers in place of the server (a canned reply) has no
// meaning here, since what it supplies is a tool's result; it is taken as a
// refusal. So is a mask that cannot be written back: passing the original on
// would hand over what the policy asked to hide.

// resourcesReadName is the name a resources/read is shown to the plugins under.
const resourcesReadName = "resources/read"

// errSurfaceMask is the refusal when a policy's answer cannot be carried back
// into a prompt or a resource.
func errSurfaceMask(what string) *RPCError {
	return &RPCError{
		Code:       CodePolicyBlocked,
		Message:    "blocked by policy: " + what,
		HTTPStatus: http.StatusForbidden,
	}
}

// guardSurfaceRequest runs the request stage over a prompts/get or a
// resources/read. It returns the arguments a plugin rewrote (nil when none
// did) or the refusal.
func (d *RPCDispatcher) guardSurfaceRequest(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	call ToolCall,
) (json.RawMessage, error) {
	pre, err := d.plugins.PreRequest(ctx, rc, call)
	if err != nil {
		return nil, err
	}
	if pre == nil {
		return nil, nil
	}
	if pre.Result != nil {
		return nil, errSurfaceMask("a policy answered the request in place of the server")
	}
	return pre.Arguments, nil
}

// guardSurfaceResult runs the response stage over a prompt or resource
// result, returning it as the plugins left it.
func (d *RPCDispatcher) guardSurfaceResult(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	call ToolCall,
	result json.RawMessage,
	kind surfaceKind,
) (json.RawMessage, error) {
	view, err := newSurfaceView(result, kind)
	if err != nil {
		// Not a shape the gateway can read: inspect it whole as one text
		// block rather than let it through unseen, and refuse a mask of it.
		view = &surfaceView{raw: result}
		view.blocks = []any{map[string]any{"type": "text", "text": string(result)}}
	}
	asTool, err := json.Marshal(map[string]any{"content": view.blocks})
	if err != nil {
		return nil, err
	}
	post, err := d.plugins.PreResponse(ctx, rc, call, asTool)
	if err != nil {
		return nil, err
	}
	if post == nil || post.Result == nil || bytes.Equal(post.Result, asTool) {
		return result, nil
	}
	if view.decoded == nil {
		return nil, errSurfaceMask("a policy masked a result the gateway could not read")
	}
	masked, err := view.apply(post.Result)
	if err != nil {
		return nil, errSurfaceMask(err.Error())
	}
	return masked, nil
}

type surfaceKind int

const (
	surfacePrompt surfaceKind = iota
	surfaceResource
)

// surfaceView is a prompt or resource result held decoded, with the content
// blocks it is shown to the plugins as and, for each block, where its text
// goes back.
type surfaceView struct {
	raw     json.RawMessage
	decoded map[string]any
	blocks  []any
	setters []func(text string)
}

func newSurfaceView(raw json.RawMessage, kind surfaceKind) (*surfaceView, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded map[string]any
	if err := dec.Decode(&decoded); err != nil || decoded == nil {
		return nil, fmt.Errorf("mcp: result is not an object")
	}
	v := &surfaceView{raw: raw, decoded: decoded, blocks: []any{}}
	switch kind {
	case surfacePrompt:
		if desc, ok := decoded["description"].(string); ok && desc != "" {
			v.addText(desc, func(s string) { decoded["description"] = s })
		}
		messages, _ := decoded["messages"].([]any)
		for _, m := range messages {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			switch content := msg["content"].(type) {
			case map[string]any:
				v.addBlock(content)
			case []any:
				for _, item := range content {
					if block, ok := item.(map[string]any); ok {
						v.addBlock(block)
					}
				}
			case string:
				v.addText(content, func(s string) { msg["content"] = s })
			}
		}
	case surfaceResource:
		contents, _ := decoded["contents"].([]any)
		for _, c := range contents {
			item, ok := c.(map[string]any)
			if !ok {
				continue
			}
			v.addResource(item)
		}
	}
	return v, nil
}

func (v *surfaceView) addText(text string, set func(string)) {
	v.blocks = append(v.blocks, map[string]any{"type": "text", "text": text})
	v.setters = append(v.setters, set)
}

// addResource shows a resource's contents as an embedded resource block.
// Only its text is inspected or written back.
func (v *surfaceView) addResource(item map[string]any) {
	text, ok := item["text"].(string)
	if !ok {
		return
	}
	resource := map[string]any{"text": text}
	if uri, ok := item["uri"].(string); ok {
		resource["uri"] = uri
	}
	if mime, ok := item["mimeType"].(string); ok {
		resource["mimeType"] = mime
	}
	v.blocks = append(v.blocks, map[string]any{"type": "resource", "resource": resource})
	v.setters = append(v.setters, func(s string) { item["text"] = s })
}

// addBlock shows one of a prompt message's content blocks: its text, or the
// text of the resource it embeds.
func (v *surfaceView) addBlock(block map[string]any) {
	switch block["type"] {
	case "text":
		if text, ok := block["text"].(string); ok {
			v.addText(text, func(s string) { block["text"] = s })
		}
	case "resource":
		if resource, ok := block["resource"].(map[string]any); ok {
			v.addResource(resource)
		}
	}
}

// apply writes the text of the masked CallToolResult back into the result,
// block by block.
func (v *surfaceView) apply(masked json.RawMessage) (json.RawMessage, error) {
	var result struct {
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Resource *struct {
				Text string `json:"text"`
			} `json:"resource"`
		} `json:"content"`
	}
	if err := json.Unmarshal(masked, &result); err != nil {
		return nil, fmt.Errorf("a policy rewrote the result into something unreadable")
	}
	if len(result.Content) != len(v.setters) {
		return nil, fmt.Errorf("a policy rewrote the result into a different number of parts")
	}
	for i, block := range result.Content {
		text := block.Text
		if block.Type == "resource" {
			if block.Resource == nil {
				return nil, fmt.Errorf("a policy dropped an embedded resource's text")
			}
			text = block.Resource.Text
		}
		v.setters[i](text)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v.decoded); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}
