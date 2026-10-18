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
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// zoomRevokedErrorCode is Zoom's "a newer authorization replaced this token"
// code. Zoom issues one token per OAuth app, so authorizing a second Zoom
// server with the same app revokes the first.
const zoomRevokedErrorCode = 4741

// zoomRevokedConnectionText is the tool error a caller can act on. The
// upstream body is not included: it can carry the rejected token.
const zoomRevokedConnectionText = "Zoom revoked this connection because another Zoom server was authorized with the same Zoom app. Use a separate Zoom app per Zoom server, then reconnect."

func rewriteZoomRevokedCall(reg *registrydomain.Registry, result json.RawMessage, err error) (json.RawMessage, error) {
	if !isZoomUpstream(reg) || !zoomCallFailedWith(result, err, zoomRevokedErrorCode) {
		return result, err
	}
	raw, encErr := json.Marshal(map[string]any{
		"content": []map[string]string{{"type": "text", "text": zoomRevokedConnectionText}},
		"isError": true,
	})
	if encErr != nil {
		return result, err
	}
	return raw, nil
}

func isZoomUpstream(reg *registrydomain.Registry) bool {
	if reg == nil || reg.MCPTarget == nil {
		return false
	}
	code := strings.ToLower(strings.TrimSpace(reg.MCPTarget.Code))
	if strings.HasPrefix(code, "us.zoom/") {
		return true
	}
	parsed, err := url.Parse(strings.TrimSpace(reg.MCPTarget.URL))
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Hostname(), "mcp.zoom.us")
}

// zoomCallFailedWith reports a failed Zoom call whose payload is the Zoom
// error object. A successful result that mentions the number is not a failure,
// and no other code is recognized.
func zoomCallFailedWith(result json.RawMessage, err error, code int) bool {
	if code != zoomRevokedErrorCode {
		return false
	}
	if err != nil {
		return zoomRevokedPayload(result) || contentIsZoomRevoked(result) || errorIsZoomRevoked(err)
	}
	if !toolResultIsError(result) && !contentIsZoomRevoked(result) {
		return false
	}
	return zoomRevokedPayload(result) || contentIsZoomRevoked(result)
}

func errorIsZoomRevoked(err error) bool {
	if err == nil {
		return false
	}
	if zoomRevokedPayload([]byte(err.Error())) {
		return true
	}
	var rpc *RPCError
	if errors.As(err, &rpc) {
		return zoomRevokedPayload([]byte(rpc.Message)) || zoomRevokedPayload(rpc.Data)
	}
	return false
}

func toolResultIsError(result json.RawMessage) bool {
	var envelope struct {
		IsError bool `json:"isError"`
	}
	return json.Unmarshal(result, &envelope) == nil && envelope.IsError
}

// contentIsZoomRevoked reports a tool result whose single text block is the
// Zoom error object, which is how the call fails when the server does not
// set isError.
func contentIsZoomRevoked(result json.RawMessage) bool {
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(result, &envelope) != nil || len(envelope.Content) != 1 {
		return false
	}
	return zoomRevokedPayload([]byte(envelope.Content[0].Text))
}

// zoomRevokedPayload reports a Zoom error object: JSON whose own code field
// is the number 4741. Nested fields, values inside strings, and the string
// "4741" are not that object. Zoom pairs the code with a message.
func zoomRevokedPayload(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || dec.More() {
		return false
	}
	number, ok := obj["code"].(json.Number)
	if !ok {
		return false
	}
	code, err := number.Int64()
	if err != nil || code != int64(zoomRevokedErrorCode) {
		return false
	}
	_, ok = obj["message"].(string)
	return ok
}
