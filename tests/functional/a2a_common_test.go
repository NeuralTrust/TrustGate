//go:build functional

package functional_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// agentCall is a request the fake agent received.
type agentCall struct {
	Method string
	Header http.Header
	Params map[string]any
}

// fakeAgent is an A2A agent on httptest that speaks one protocol version. It
// answers every task as completed with an artifact echoing the message text.
type fakeAgent struct {
	srv     *httptest.Server
	version string

	mu     sync.Mutex
	skills []string
	calls  []agentCall
	tasks  int
	// hold, when set before the agent is called, keeps a stream open after
	// its first event until it is closed.
	hold chan struct{}
}

func startFakeAgent(t *testing.T, version string) *fakeAgent {
	t.Helper()
	a := &fakeAgent{version: version, skills: []string{"echo"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/rpc", a.rpc)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != a.cardPath() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(a.card())
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

// cardPath serves the 0.3 card only on the legacy path, so registering by base
// URL exercises the probe order.
func (a *fakeAgent) cardPath() string {
	if a.version == "0.3" {
		return "/.well-known/agent.json"
	}
	return "/.well-known/agent-card.json"
}

func (a *fakeAgent) endpoint() string { return a.srv.URL + "/rpc" }

func (a *fakeAgent) card() []byte {
	a.mu.Lock()
	skills := make([]map[string]any, 0, len(a.skills))
	for _, s := range a.skills {
		skills = append(skills, map[string]any{"id": s, "name": s, "description": s, "tags": []string{"test"}})
	}
	a.mu.Unlock()
	card := map[string]any{
		"name":               "Echo agent",
		"description":        "Echoes messages",
		"version":            "1.0.0",
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"capabilities":       map[string]any{"streaming": true, "pushNotifications": true},
		"skills":             skills,
	}
	if a.version == "0.3" {
		card["url"] = a.endpoint()
		card["protocolVersion"] = "0.3.0"
		card["preferredTransport"] = "JSONRPC"
	} else {
		card["supportedInterfaces"] = []map[string]any{{"url": a.endpoint(), "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}}
	}
	out, _ := json.Marshal(card)
	return out
}

func (a *fakeAgent) setSkills(skills ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.skills = skills
}

func (a *fakeAgent) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

func (a *fakeAgent) last() agentCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[len(a.calls)-1]
}

func (a *fakeAgent) rpc(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params map[string]any  `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	a.calls = append(a.calls, agentCall{Method: req.Method, Header: r.Header.Clone(), Params: req.Params})
	a.mu.Unlock()

	switch req.Method {
	case "message/send", "SendMessage":
		taskID, contextID, text := a.newTask(req.Params)
		writeRPCResult(w, req.ID, a.task(taskID, contextID, "completed", "echo: "+text))
	case "message/stream", "SendStreamingMessage":
		taskID, contextID, text := a.newTask(req.Params)
		w.Header().Set("Content-Type", "text/event-stream")
		for i, event := range a.streamEvents(taskID, contextID, text) {
			frame, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": event})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", frame)
			w.(http.Flusher).Flush()
			if i == 0 && a.hold != nil {
				select {
				case <-a.hold:
				case <-r.Context().Done():
					return
				}
			}
		}
	case "tasks/get", "GetTask":
		id, _ := req.Params["id"].(string)
		writeRPCResult(w, req.ID, a.task(id, "ctx-of-"+id, "completed", "done"))
	case "tasks/cancel", "CancelTask":
		id, _ := req.Params["id"].(string)
		writeRPCResult(w, req.ID, a.task(id, "ctx-of-"+id, "canceled", "canceled"))
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32601, "message": "Method not found"}})
	}
}

func (a *fakeAgent) newTask(params map[string]any) (string, string, string) {
	a.mu.Lock()
	a.tasks++
	n := a.tasks
	a.mu.Unlock()
	msg, _ := params["message"].(map[string]any)
	contextID, _ := msg["contextId"].(string)
	if contextID == "" {
		contextID = fmt.Sprintf("ctx-%d-%s", n, uniqueName("c"))
	}
	var text string
	parts, _ := msg["parts"].([]any)
	for _, p := range parts {
		part, _ := p.(map[string]any)
		if s, ok := part["text"].(string); ok {
			text += s
		}
	}
	return fmt.Sprintf("task-%d-%s", n, uniqueName("t")), contextID, text
}

func (a *fakeAgent) textPart(text string) map[string]any {
	if a.version == "0.3" {
		return map[string]any{"kind": "text", "text": text}
	}
	return map[string]any{"text": text}
}

func (a *fakeAgent) state(s string) string {
	if a.version == "0.3" {
		return s
	}
	return "TASK_STATE_" + strings.ToUpper(s)
}

func (a *fakeAgent) task(id, contextID, state, text string) map[string]any {
	task := map[string]any{
		"id":        id,
		"contextId": contextID,
		"status":    map[string]any{"state": a.state(state)},
		"artifacts": []map[string]any{{"artifactId": "a-" + id, "parts": []any{a.textPart(text)}}},
	}
	if a.version == "0.3" {
		task["kind"] = "task"
		return task
	}
	return map[string]any{"task": task}
}

func (a *fakeAgent) streamEvents(taskID, contextID, text string) []map[string]any {
	submitted := a.task(taskID, contextID, "submitted", "")
	status := func(state string, final bool) map[string]any {
		body := map[string]any{"taskId": taskID, "contextId": contextID, "final": final, "status": map[string]any{"state": a.state(state)}}
		if a.version == "0.3" {
			body["kind"] = "status-update"
			return body
		}
		return map[string]any{"statusUpdate": body}
	}
	artifact := map[string]any{"taskId": taskID, "contextId": contextID, "artifact": map[string]any{"artifactId": "a-" + taskID, "parts": []any{a.textPart("echo: " + text)}}}
	if a.version == "0.3" {
		artifact["kind"] = "artifact-update"
	} else {
		artifact = map[string]any{"artifactUpdate": artifact}
	}
	return []map[string]any{submitted, status("working", false), artifact, status("completed", true)}
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

// a2aMethods names the forwarded methods of each version.
var a2aMethods = map[string]map[string]string{
	"0.3": {"send": "message/send", "stream": "message/stream", "get": "tasks/get", "cancel": "tasks/cancel",
		"push": "tasks/pushNotificationConfig/set", "card": "agent/getAuthenticatedExtendedCard", "other": "SendMessage"},
	"1.0": {"send": "SendMessage", "stream": "SendStreamingMessage", "get": "GetTask", "cancel": "CancelTask",
		"push": "CreateTaskPushNotificationConfig", "card": "GetExtendedAgentCard", "list": "ListTasks", "other": "message/send"},
}

// a2aMessage is the params of a send or stream call with one text part.
func a2aMessage(version, text, contextID string) map[string]any {
	msg := map[string]any{"messageId": uniqueName("m")}
	if version == "0.3" {
		msg["kind"] = "message"
		msg["role"] = "user"
		msg["parts"] = []any{map[string]any{"kind": "text", "text": text}}
	} else {
		msg["role"] = "ROLE_USER"
		msg["parts"] = []any{map[string]any{"text": text}}
	}
	if contextID != "" {
		msg["contextId"] = contextID
	}
	return map[string]any{"message": msg}
}

// a2aRegistryPayload registers an agent by its base URL.
func a2aRegistryPayload(name, baseURL, version string, auth map[string]any) map[string]any {
	target := map[string]any{"card_url": baseURL, "protocol_version": version}
	if auth != nil {
		target["auth"] = auth
	}
	return map[string]any{"name": name, "type": "A2A", "a2a_target": target}
}

// createA2AConsumer creates an A2A consumer bound to registryIDs and attaches
// a fresh API key. It returns the consumer id and the key.
func createA2AConsumer(t *testing.T, gatewayID string, registryIDs ...string) (string, string) {
	t.Helper()
	bindings := make([]map[string]any, 0, len(registryIDs))
	for _, id := range registryIDs {
		bindings = append(bindings, map[string]any{"id": id})
	}
	consumerID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("a2a-consumer"), "type": "A2A", "registries": bindings})
	return consumerID, createAndAttachAPIKey(t, gatewayID, consumerID)
}

func agentPath(t *testing.T, consumerID, agent string) string {
	t.Helper()
	return "/" + ConsumerSlug(t, consumerID) + "/agents/" + agent
}

// agentRequest sends a request to an agent plane at base on the gateway's
// agent host.
func agentRequest(t *testing.T, base, gatewayID, method, path string, headers map[string]string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if host, ok := agentHosts.Load(gatewayID); ok {
		req.Host = host.(string)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// a2aRPC posts a JSON-RPC call and returns the HTTP status and the decoded
// response.
func a2aRPC(t *testing.T, base, gatewayID, path string, headers map[string]string, method string, params any) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
	require.NoError(t, err)
	resp := agentRequest(t, base, gatewayID, http.MethodPost, path, headers, body)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := map[string]any{}
	if len(raw) > 0 && json.Unmarshal(raw, &out) != nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, out
}

// a2aStream posts a streaming call and returns the decoded events.
func a2aStream(t *testing.T, base, gatewayID, path string, headers map[string]string, method string, params any) []map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
	require.NoError(t, err)
	resp := agentRequest(t, base, gatewayID, http.MethodPost, path, headers, body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	var events []map[string]any
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data: ")
		if !ok {
			continue
		}
		event := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(data), &event))
		events = append(events, event)
	}
	require.NoError(t, scanner.Err())
	return events
}

// a2aTask returns the task of a result in either version.
func a2aTask(t *testing.T, version string, body map[string]any) map[string]any {
	t.Helper()
	require.Nil(t, body["error"], "rpc error: %v", body)
	result, ok := body["result"].(map[string]any)
	require.True(t, ok, "rpc result missing: %v", body)
	if version == "1.0" {
		result, ok = result["task"].(map[string]any)
		require.True(t, ok, "result has no task: %v", body)
	}
	return result
}

func a2aErrorCode(t *testing.T, status int, body map[string]any) int {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	return int(rpcErrorCode(t, status, body))
}

func a2aErrorData(body map[string]any) map[string]any {
	rpcErr, _ := body["error"].(map[string]any)
	data, _ := rpcErr["data"].(map[string]any)
	return data
}

func a2aKey(key string) map[string]string {
	return map[string]string{"X-AG-API-Key": key}
}
