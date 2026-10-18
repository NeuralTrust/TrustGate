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
	"regexp"
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

// zoomErrorCodeField matches a JSON "code" field whose value is exactly 4741,
// not a longer number that merely starts with those digits.
var zoomErrorCodeField = regexp.MustCompile(`"code"\s*:\s*4741([^0-9]|$)`)

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

// zoomCallFailedWith reports a failed Zoom call whose payload names this Zoom
// error code. A successful result that merely quotes the number is not a
// failure, and no other code is recognized.
func zoomCallFailedWith(result json.RawMessage, err error, code int) bool {
	if code != zoomRevokedErrorCode {
		return false
	}
	if err != nil {
		return payloadHasZoomCode(result) || errorHasZoomCode(err)
	}
	if !toolResultIsError(result) && !contentIsZoomError(result) {
		return false
	}
	return payloadHasZoomCode(result)
}

func errorHasZoomCode(err error) bool {
	if err == nil {
		return false
	}
	if payloadHasZoomCode([]byte(err.Error())) {
		return true
	}
	var rpc *RPCError
	if errors.As(err, &rpc) {
		return payloadHasZoomCode([]byte(rpc.Message)) || payloadHasZoomCode(rpc.Data)
	}
	return false
}

func toolResultIsError(result json.RawMessage) bool {
	var envelope struct {
		IsError bool `json:"isError"`
	}
	return json.Unmarshal(result, &envelope) == nil && envelope.IsError
}

// contentIsZoomError reports a tool result whose text is the Zoom error
// object itself, which is how the call fails when the server does not set
// isError.
func contentIsZoomError(result json.RawMessage) bool {
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(result, &envelope) != nil || len(envelope.Content) != 1 {
		return false
	}
	text := strings.TrimSpace(envelope.Content[0].Text)
	return payloadHasZoomCode([]byte(text)) && json.Valid([]byte(text))
}

func payloadHasZoomCode(raw []byte) bool {
	return payloadHasZoomCodeAt(raw, 0)
}

func payloadHasZoomCodeAt(raw []byte, depth int) bool {
	if depth > 6 || len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	if zoomErrorCodeField.Match(raw) {
		return true
	}
	var parsed any
	if json.Unmarshal(raw, &parsed) != nil {
		return false
	}
	return valueHasZoomCode(parsed, depth)
}

func valueHasZoomCode(v any, depth int) bool {
	if depth > 6 {
		return false
	}
	switch typed := v.(type) {
	case map[string]any:
		if code, ok := zoomCodeValue(typed["code"]); ok && code == zoomRevokedErrorCode {
			return true
		}
		for _, child := range typed {
			if valueHasZoomCode(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if valueHasZoomCode(child, depth+1) {
				return true
			}
		}
	case string:
		return payloadHasZoomCodeAt([]byte(typed), depth+1)
	}
	return false
}

func zoomCodeValue(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	case string:
		if n == "4741" {
			return zoomRevokedErrorCode, true
		}
	}
	return 0, false
}
