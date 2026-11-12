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
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// vertex is a Vertex AI Agent Engine, which serves A2A 0.3 over the HTTP+JSON
// binding only. Callers keep JSON-RPC: each method is sent as its REST
// request, whose objects are the protobuf JSON form of the A2A ones, and the
// answer is turned back into the JSON-RPC result.
type vertex struct{}

func (vertex) header(*Exchange, http.Header) {}

func (vertex) request(ctx context.Context, endpoint string, h http.Header, body []byte) (*http.Request, error) {
	var call struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &call) != nil {
		return nil, invalidParams()
	}
	var task struct {
		ID            string `json:"id"`
		HistoryLength *int   `json:"historyLength"`
	}
	method, target, payload := http.MethodPost, "", []byte(nil)
	switch call.Method {
	case "message/send":
		params, ok := decodeMap(call.Params)
		if !ok {
			return nil, invalidParams()
		}
		payload, _ = json.Marshal(restSendRequest(params))
		target = endpoint + "/v1/message:send"
	case "tasks/get", "tasks/cancel":
		if json.Unmarshal(call.Params, &task) != nil || task.ID == "" {
			return nil, invalidParams()
		}
		target = endpoint + "/v1/tasks/" + url.PathEscape(task.ID)
		if call.Method == "tasks/cancel" {
			target += ":cancel"
		} else {
			method = http.MethodGet
			if task.HistoryLength != nil {
				target += "?historyLength=" + strconv.Itoa(*task.HistoryLength)
			}
		}
	default:
		return nil, UnsupportedOperation(Version03)
	}
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header = h
	return req, nil
}

func (vertex) decode(x *Exchange, res *http.Response, body []byte) (json.RawMessage, *RPCError) {
	switch s := res.StatusCode; {
	case s >= 200 && s <= 299:
		result, ok := rpcResult(x.kind, body)
		if !ok {
			return nil, GatewayFailure(ReasonInvalidUpstreamResponse)
		}
		return result, nil
	case s == http.StatusBadRequest || s == http.StatusUnprocessableEntity:
		x.agentError = true
		return nil, invalidParams()
	case s == http.StatusUnauthorized:
		return nil, IdentityRequired()
	case s == http.StatusForbidden:
		return nil, GatewayFailure(ReasonUpstreamAuthFailed)
	case s == http.StatusNotFound && (x.kind == KindGet || x.kind == KindCancel):
		x.agentError = true
		return nil, TaskNotFound(Version03)
	default:
		return nil, GatewayFailure(ReasonUpstreamError)
	}
}

func (vertex) retry(*RPCError, int) (time.Duration, bool) {
	return 0, false
}

func copyFields(from map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := from[k]; ok {
			out[k] = v
		}
	}
	return out
}

func each(v any, convert func(map[string]any) map[string]any) []any {
	list, _ := v.([]any)
	out := make([]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, convert(m))
		}
	}
	return out
}

// restSendRequest is message/send params as a SendMessageRequest. Push
// notification settings are dropped: the gateway turns them off.
func restSendRequest(params map[string]any) map[string]any {
	out := copyFields(params, "metadata")
	if m, ok := params["message"].(map[string]any); ok {
		out["message"] = restMessage(m)
	}
	if c, ok := params["configuration"].(map[string]any); ok {
		out["configuration"] = copyFields(c, "acceptedOutputModes", "historyLength", "blocking")
	}
	return out
}

var restRoles = map[string]string{"user": "ROLE_USER", "agent": "ROLE_AGENT"}

func restMessage(m map[string]any) map[string]any {
	out := copyFields(m, "messageId", "contextId", "taskId", "metadata", "extensions")
	if role, ok := restRoles[str(m["role"])]; ok {
		out["role"] = role
	}
	out["content"] = each(m["parts"], restPart)
	return out
}

func restPart(p map[string]any) map[string]any {
	switch str(p["kind"]) {
	case "file":
		f, _ := p["file"].(map[string]any)
		file := copyFields(f, "mimeType", "name")
		if uri, ok := f["uri"]; ok {
			file["fileWithUri"] = uri
		}
		if b, ok := f["bytes"].(string); ok {
			file["fileWithBytes"] = base64.StdEncoding.EncodeToString([]byte(b))
		}
		return map[string]any{"file": file}
	case "data":
		return map[string]any{"data": map[string]any{"data": p["data"]}}
	default:
		return map[string]any{"text": p["text"]}
	}
}

// rpcResult is the JSON-RPC result of a REST answer: the task or message of
// a SendMessageResponse, or the task of a get or cancel.
func rpcResult(k Kind, body []byte) (json.RawMessage, bool) {
	o, ok := decodeMap(body)
	if !ok {
		return nil, false
	}
	var result map[string]any
	switch {
	case k != KindSend:
		result = rpcTask(o)
	case o["task"] != nil:
		task, _ := o["task"].(map[string]any)
		result = rpcTask(task)
	default:
		msg, _ := o["message"].(map[string]any)
		result = rpcMessage(msg)
	}
	raw, err := json.Marshal(result)
	return raw, err == nil
}

var rpcStates = map[string]string{
	"TASK_STATE_SUBMITTED":      "submitted",
	"TASK_STATE_WORKING":        "working",
	"TASK_STATE_COMPLETED":      "completed",
	"TASK_STATE_FAILED":         "failed",
	"TASK_STATE_CANCELLED":      "canceled",
	"TASK_STATE_INPUT_REQUIRED": "input-required",
	"TASK_STATE_REJECTED":       "rejected",
	"TASK_STATE_AUTH_REQUIRED":  "auth-required",
}

func rpcTask(t map[string]any) map[string]any {
	out := copyFields(t, "id", "contextId", "metadata")
	out["kind"] = "task"
	s, _ := t["status"].(map[string]any)
	status := copyFields(s, "timestamp")
	status["state"] = "unknown"
	if state, ok := rpcStates[str(s["state"])]; ok {
		status["state"] = state
	}
	if m, ok := s["message"].(map[string]any); ok {
		status["message"] = rpcMessage(m)
	}
	out["status"] = status
	if _, ok := t["artifacts"]; ok {
		out["artifacts"] = each(t["artifacts"], func(a map[string]any) map[string]any {
			artifact := copyFields(a, "artifactId", "name", "description", "metadata", "extensions")
			artifact["parts"] = each(a["parts"], rpcPart)
			return artifact
		})
	}
	if _, ok := t["history"]; ok {
		out["history"] = each(t["history"], rpcMessage)
	}
	return out
}

func rpcMessage(m map[string]any) map[string]any {
	out := copyFields(m, "messageId", "contextId", "taskId", "metadata", "extensions")
	out["kind"] = "message"
	out["role"] = "agent"
	if str(m["role"]) == "ROLE_USER" {
		out["role"] = "user"
	}
	out["parts"] = each(m["content"], rpcPart)
	return out
}

func rpcPart(p map[string]any) map[string]any {
	if f, ok := p["file"].(map[string]any); ok {
		file := copyFields(f, "mimeType", "name")
		if uri, ok := f["fileWithUri"]; ok {
			file["uri"] = uri
		}
		if raw, ok := f["fileWithBytes"].(string); ok {
			if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
				file["bytes"] = string(b)
			}
		}
		return map[string]any{"kind": "file", "file": file}
	}
	if d, ok := p["data"].(map[string]any); ok {
		return map[string]any{"kind": "data", "data": d["data"]}
	}
	return map[string]any{"kind": "text", "text": p["text"]}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
