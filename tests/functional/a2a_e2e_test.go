//go:build functional

package functional_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An agent registered by its base URL is previewed, pinned and served through
// the agent plane: the card rewritten, send, get, cancel and stream forwarded
// with the registry's credential and nothing of the caller's.
func TestA2A_RegisterAndCallAnAgent(t *testing.T) {
	defer Track(t, "A2A")()
	for _, version := range []string{"0.3", "1.0"} {
		t.Run(version, func(t *testing.T) {
			agent := startFakeAgent(t, version)
			methods := a2aMethods[version]
			gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})

			status, preview := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/registries/preview-agent-card", AdminURL, gatewayID),
				nil, map[string]any{"card_url": agent.srv.URL})
			require.Equal(t, http.StatusOK, status, "body=%v", preview)
			assert.Equal(t, agent.srv.URL+agent.cardPath(), preview["resolved_card_url"])
			assert.Contains(t, preview["versions"], version)

			status, reg := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gatewayID), nil,
				a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, version,
					map[string]any{"mode": "static", "header": "X-Agent-Key", "value": "agent-secret"}))
			require.Equal(t, http.StatusCreated, status, "body=%v", reg)
			registryID := reg["id"].(string)
			target := reg["a2a_target"].(map[string]any)
			assert.Equal(t, version, target["protocol_version"])
			assert.Equal(t, agent.srv.URL+agent.cardPath(), target["resolved_card_url"])
			assert.True(t, strings.HasPrefix(fmt.Sprint(target["card_digest"]), "sha256:"), "target=%v", target)
			assert.Equal(t, agent.endpoint(), target["endpoint"])

			consumerID, key := createA2AConsumer(t, gatewayID, registryID)
			path := agentPath(t, consumerID, registryID)

			resp := agentRequest(t, AgentURL, gatewayID, http.MethodGet, path+"/.well-known/agent-card.json", a2aKey(key), nil)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var card map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&card))
			capabilities := card["capabilities"].(map[string]any)
			assert.Equal(t, false, capabilities["pushNotifications"])
			assert.Contains(t, fmt.Sprint(card["securitySchemes"]), "X-AG-API-Key")
			if version == "0.3" {
				assert.True(t, strings.HasSuffix(fmt.Sprint(card["url"]), path), "card url=%v", card["url"])
			} else {
				ifaces := card["supportedInterfaces"].([]any)
				require.Len(t, ifaces, 1)
				assert.True(t, strings.HasSuffix(fmt.Sprint(ifaces[0].(map[string]any)["url"]), path), "interfaces=%v", ifaces)
			}

			headers := map[string]string{"X-AG-API-Key": key, "X-AG-Caller": "caller", "Cookie": "session=caller"}
			status, sent := a2aRPC(t, AgentURL, gatewayID, path, headers, methods["send"], a2aMessage(version, "hello", ""))
			require.Equal(t, http.StatusOK, status, "body=%v", sent)
			assert.EqualValues(t, 7, sent["id"])
			task := a2aTask(t, version, sent)
			taskID := task["id"].(string)
			assert.Contains(t, fmt.Sprint(task["artifacts"]), "echo: hello")

			got := agent.last()
			assert.Equal(t, methods["send"], got.Method)
			assert.Equal(t, "agent-secret", got.Header.Get("X-Agent-Key"))
			assert.Empty(t, got.Header.Get("Cookie"))
			assert.Empty(t, got.Header.Get("X-AG-API-Key"))
			assert.Empty(t, got.Header.Get("X-AG-Caller"))
			assert.NotEmpty(t, got.Header.Get("X-AG-Trace-Id"))
			if version == "1.0" {
				assert.Equal(t, "1.0", got.Header.Get("A2A-Version"))
			} else {
				assert.Empty(t, got.Header.Get("A2A-Version"))
			}

			status, fetched := a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), methods["get"], map[string]any{"id": taskID})
			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, taskID, a2aTask(t, version, fetched)["id"])

			status, canceled := a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), methods["cancel"], map[string]any{"id": taskID})
			require.Equal(t, http.StatusOK, status)
			assert.Contains(t, strings.ToLower(fmt.Sprint(a2aTask(t, version, canceled)["status"])), "canceled")

			events := a2aStream(t, AgentURL, gatewayID, path, a2aKey(key), methods["stream"], a2aMessage(version, "streamed", ""))
			require.Len(t, events, 4, "events=%v", events)
			for _, event := range events {
				assert.Nil(t, event["error"], "event=%v", event)
				assert.EqualValues(t, 7, event["id"])
			}
			assert.Contains(t, fmt.Sprint(events[2]["result"]), "echo: streamed")
			streamedTask := events[0]["result"].(map[string]any)
			if version == "1.0" {
				streamedTask = streamedTask["task"].(map[string]any)
			}
			status, fetched = a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), methods["get"], map[string]any{"id": streamedTask["id"]})
			require.Equal(t, http.StatusOK, status)
			assert.Nil(t, fetched["error"], "a streamed task belongs to its caller; body=%v", fetched)
		})
	}
}

// Methods the gateway never forwards are refused with the version's error and
// never reach the agent.
func TestA2A_RefusesMethodsItDoesNotForward(t *testing.T) {
	defer Track(t, "A2A")()
	for _, version := range []string{"0.3", "1.0"} {
		t.Run(version, func(t *testing.T) {
			agent := startFakeAgent(t, version)
			methods := a2aMethods[version]
			gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
			registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, version, nil))
			consumerID, key := createA2AConsumer(t, gatewayID, registryID)
			path := agentPath(t, consumerID, registryID)

			cases := map[string]int{
				methods["push"]:  -32003,
				methods["card"]:  -32007,
				methods["other"]: -32601,
				"unknown/method": -32601,
			}
			if version == "1.0" {
				cases[methods["list"]] = -32004
			}
			for method, code := range cases {
				status, body := a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), method,
					map[string]any{"taskId": "t-1", "pushNotificationConfig": map[string]any{"url": "https://hook.example.com"}})
				assert.Equal(t, code, a2aErrorCode(t, status, body), "%s: body=%v", method, body)
			}

			resp := agentRequest(t, AgentURL, gatewayID, http.MethodPost, path, a2aKey(key), []byte(`[{"jsonrpc":"2.0","id":1,"method":"`+methods["send"]+`"}]`))
			raw, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(raw), "-32600")
			resp = agentRequest(t, AgentURL, gatewayID, http.MethodPost, path, a2aKey(key), []byte(`{not json`))
			raw, _ = io.ReadAll(resp.Body)
			assert.Contains(t, string(raw), "-32700")

			assert.Zero(t, agent.count(), "a refused call must not reach the agent")
		})
	}
}

// A task belongs to the consumer and subject that created it: two keys of the
// same application share it, another application and another named user of
// the same application get TaskNotFound, without the agent being called.
func TestA2A_TasksBelongToTheirCaller(t *testing.T) {
	defer Track(t, "A2A")()
	const version = "0.3"
	agent := startFakeAgent(t, version)
	methods := a2aMethods[version]
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, version, nil))
	consumerA, keyA1 := createA2AConsumer(t, gatewayID, registryID)
	keyA2 := createAndAttachAPIKey(t, gatewayID, consumerA)
	consumerB, keyB := createA2AConsumer(t, gatewayID, registryID)
	pathA, pathB := agentPath(t, consumerA, registryID), agentPath(t, consumerB, registryID)

	status, sent := a2aRPC(t, AgentURL, gatewayID, pathA, a2aKey(keyA1), methods["send"], a2aMessage(version, "hi", ""))
	require.Equal(t, http.StatusOK, status)
	task := a2aTask(t, version, sent)
	taskID, contextID := task["id"].(string), task["contextId"].(string)

	status, body := a2aRPC(t, AgentURL, gatewayID, pathA, a2aKey(keyA2), methods["get"], map[string]any{"id": taskID})
	require.Equal(t, http.StatusOK, status)
	assert.Nil(t, body["error"], "another key of the same application shares its tasks; body=%v", body)

	before := agent.count()
	status, body = a2aRPC(t, AgentURL, gatewayID, pathB, a2aKey(keyB), methods["get"], map[string]any{"id": taskID})
	assert.Equal(t, -32001, a2aErrorCode(t, status, body))
	status, body = a2aRPC(t, AgentURL, gatewayID, pathB, a2aKey(keyB), methods["cancel"], map[string]any{"id": taskID})
	assert.Equal(t, -32001, a2aErrorCode(t, status, body))
	status, body = a2aRPC(t, AgentURL, gatewayID, pathB, a2aKey(keyB), methods["send"], a2aMessage(version, "join", contextID))
	assert.Equal(t, -32001, a2aErrorCode(t, status, body))
	status, body = a2aRPC(t, AgentURL, gatewayID, pathA, a2aKey(keyA1), methods["get"], map[string]any{"id": "no-such-task"})
	assert.Equal(t, -32001, a2aErrorCode(t, status, body))
	assert.Equal(t, before, agent.count(), "a call on a task the caller does not own must not reach the agent")

	u1 := map[string]string{"X-AG-API-Key": keyA1, "X-NeuralTrust-End-User": "user-1"}
	u2 := map[string]string{"X-AG-API-Key": keyA1, "X-NeuralTrust-End-User": "user-2"}
	status, sent = a2aRPC(t, AgentURL, gatewayID, pathA, u1, methods["send"], a2aMessage(version, "mine", ""))
	require.Equal(t, http.StatusOK, status)
	userTask := a2aTask(t, version, sent)

	status, body = a2aRPC(t, AgentURL, gatewayID, pathA, u1, methods["get"], map[string]any{"id": userTask["id"]})
	require.Equal(t, http.StatusOK, status)
	assert.Nil(t, body["error"], "body=%v", body)
	status, body = a2aRPC(t, AgentURL, gatewayID, pathA, u2, methods["get"], map[string]any{"id": userTask["id"]})
	assert.Equal(t, -32001, a2aErrorCode(t, status, body))
	status, body = a2aRPC(t, AgentURL, gatewayID, pathA, a2aKey(keyA1), methods["get"], map[string]any{"id": userTask["id"]})
	assert.Equal(t, -32001, a2aErrorCode(t, status, body), "the application is not the user it named")
	status, body = a2aRPC(t, AgentURL, gatewayID, pathA, u2, methods["send"], a2aMessage(version, "join", userTask["contextId"].(string)))
	assert.Equal(t, -32001, a2aErrorCode(t, status, body))

	status, body = a2aRPC(t, AgentURL, gatewayID, pathA, u1, methods["send"], a2aMessage(version, "again", userTask["contextId"].(string)))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, userTask["contextId"], a2aTask(t, version, body)["contextId"])
}

// A policy that blocks a message answers -32090 and the agent receives
// nothing; a message within the limit passes.
func TestA2A_PolicyBlocksTheMessage(t *testing.T) {
	defer Track(t, "A2A")()
	const version = "1.0"
	agent := startFakeAgent(t, version)
	methods := a2aMethods[version]
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, version, nil))
	consumerID, key := createA2AConsumer(t, gatewayID, registryID)
	payload := policyPlugin("request_size_limiter", map[string]any{"allowed_payload_size": 1, "size_unit": "megabytes", "max_chars_per_request": 300})
	payload["name"] = uniqueName("pol")
	AttachPolicy(t, gatewayID, consumerID, CreatePolicy(t, gatewayID, payload))
	path := agentPath(t, consumerID, registryID)

	status, body := a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), methods["send"], a2aMessage(version, strings.Repeat("x", 400), ""))
	assert.Equal(t, -32090, a2aErrorCode(t, status, body))
	data := a2aErrorData(body)
	assert.Equal(t, "policy_blocked", data["reason"], "body=%v", body)
	assert.Equal(t, "request_size_limiter", data["plugin"], "body=%v", body)
	assert.Zero(t, agent.count(), "a blocked call must not reach the agent")

	withMetadata := a2aMessage(version, "short", "")
	withMetadata["message"].(map[string]any)["metadata"] = map[string]any{"blob": strings.Repeat("x", 400)}
	status, body = a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), methods["send"], withMetadata)
	assert.Equal(t, -32090, a2aErrorCode(t, status, body), "the limit counts the request as it is sent, metadata included")
	assert.Zero(t, agent.count())

	status, body = a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), methods["send"], a2aMessage(version, "short", ""))
	require.Equal(t, http.StatusOK, status)
	assert.Nil(t, body["error"], "body=%v", body)
	assert.Equal(t, 1, agent.count())
}

// The agent plane answers 401 without a credential, 403 for a key of another
// consumer, and 404 for an agent or a consumer it does not serve.
func TestA2A_AuthenticatesAndRoutes(t *testing.T) {
	defer Track(t, "A2A")()
	const version = "1.0"
	agent := startFakeAgent(t, version)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
	name := uniqueName("echo")
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(name, agent.srv.URL, version, nil))
	consumerA, keyA := createA2AConsumer(t, gatewayID, registryID)
	_, keyB := createA2AConsumer(t, gatewayID, registryID)
	upstream := startMCPUpstream(t, nil)
	mcpRegistry := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	mcpConsumer, mcpKey := createMCPConsumer(t, gatewayID, []string{mcpRegistry}, nil, "")
	path := agentPath(t, consumerA, registryID)
	send := a2aMessage(version, "hi", "")

	status, _ := a2aRPC(t, AgentURL, gatewayID, path, nil, "SendMessage", send)
	assert.Equal(t, http.StatusUnauthorized, status)
	status, _ = a2aRPC(t, AgentURL, gatewayID, path, a2aKey(keyB), "SendMessage", send)
	assert.Equal(t, http.StatusForbidden, status)
	status, _ = a2aRPC(t, AgentURL, gatewayID, agentPath(t, mcpConsumer, registryID), a2aKey(mcpKey), "SendMessage", send)
	assert.Equal(t, http.StatusNotFound, status)
	status, _ = a2aRPC(t, AgentURL, gatewayID, agentPath(t, consumerA, "no-such-agent"), a2aKey(keyA), "SendMessage", send)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Zero(t, agent.count())

	status, body := a2aRPC(t, AgentURL, gatewayID, agentPath(t, consumerA, name), a2aKey(keyA), "SendMessage", send)
	require.Equal(t, http.StatusOK, status)
	assert.Nil(t, body["error"], "an agent is also addressed by its unique name; body=%v", body)
}

// whoami lists an A2A consumer's agents with their card URLs on the agent
// host.
func TestA2A_WhoAmIListsAgents(t *testing.T) {
	defer Track(t, "A2A")()
	agent := startFakeAgent(t, "1.0")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
	host, ok := agentHosts.Load(gatewayID)
	require.True(t, ok, "the gateway has no agent host; set AGENT_BASE_DOMAIN in .env.functional")
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, "1.0", nil))
	consumerID, key := createA2AConsumer(t, gatewayID, registryID)

	status, body := whoAmIOnGateway(t, gatewayID, key)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	consumers := body["consumers"].([]any)
	require.Len(t, consumers, 1)
	entry := consumers[0].(map[string]any)
	assert.Equal(t, "A2A", entry["type"])
	agents := entry["agents"].([]any)
	require.Len(t, agents, 1)
	listed := agents[0].(map[string]any)
	assert.Equal(t, registryID, listed["id"])
	assert.Equal(t, "1.0", listed["protocol_version"])
	assert.Contains(t, listed["card_url"], host.(string)+agentPath(t, consumerID, registryID)+"/.well-known/agent-card.json")
}

// Refresh reports a changed card without pinning it; approve pins only the
// digest it was given, and refuses one the agent has moved past.
func TestA2A_RefreshAndApproveTheCard(t *testing.T) {
	defer Track(t, "A2A")()
	agent := startFakeAgent(t, "1.0")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, "1.0", nil))
	consumerID, key := createA2AConsumer(t, gatewayID, registryID)
	cardPath := agentPath(t, consumerID, registryID) + "/.well-known/agent-card.json"
	cardURL := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/agent-card", AdminURL, gatewayID, registryID)

	agent.setSkills("echo", "refund_invoice")
	status, refresh := sendRequest(t, http.MethodPost, cardURL+"/refresh", nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", refresh)
	assert.Equal(t, true, refresh["changed"])
	assert.Equal(t, []any{"skills"}, refresh["changed_fields"])
	assert.Equal(t, []any{"refund_invoice"}, refresh["skills_added"])
	digest := refresh["fetched_digest"].(string)

	resp := agentRequest(t, AgentURL, gatewayID, http.MethodGet, cardPath, a2aKey(key), nil)
	raw, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(raw), "refund_invoice", "refresh must not pin the card")

	agent.setSkills("echo", "refund_invoice", "close_account")
	status, body := sendRequest(t, http.MethodPost, cardURL+"/approve", nil, map[string]any{"digest": digest})
	assert.Equal(t, http.StatusConflict, status, "body=%v", body)

	status, refresh = sendRequest(t, http.MethodPost, cardURL+"/refresh", nil, nil)
	require.Equal(t, http.StatusOK, status)
	status, body = sendRequest(t, http.MethodPost, cardURL+"/approve", nil, map[string]any{"digest": refresh["fetched_digest"]})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, refresh["fetched_digest"], body["a2a_target"].(map[string]any)["card_digest"])

	require.Eventually(t, func() bool {
		resp := agentRequest(t, AgentURL, gatewayID, http.MethodGet, cardPath, a2aKey(key), nil)
		raw, _ := io.ReadAll(resp.Body)
		return strings.Contains(string(raw), "close_account")
	}, 15*time.Second, 300*time.Millisecond, "the agent plane never served the approved card")
}

// With telemetry on, the gateway relays each event as the agent writes it,
// so a stream reaches the caller before the agent ends it.
func TestA2A_RelaysStreamEventsAsTheAgentWritesThem(t *testing.T) {
	defer Track(t, "A2A")()
	agent := startFakeAgent(t, "1.0")
	release := make(chan struct{})
	var released sync.Once
	agent.hold = release
	t.Cleanup(func() { released.Do(func() { close(release) }) })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-stream")})
	status, reg := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gatewayID), nil,
		a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, "1.0",
			map[string]any{"mode": "static", "header": "X-Agent-Key", "value": "agent-secret"}))
	require.Equal(t, http.StatusCreated, status, "body=%v", reg)
	consumerID, key := createA2AConsumer(t, gatewayID, reg["id"].(string))
	path := agentPath(t, consumerID, reg["id"].(string))
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": a2aMethods["1.0"]["stream"], "params": a2aMessage("1.0", "held", "")})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, AgentURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AG-API-Key", key)
	if host, ok := agentHosts.Load(gatewayID); ok {
		req.Host = host.(string)
	}

	first := make(chan string, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			first <- "request failed: " + err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "data: ") {
				first <- scanner.Text()
				return
			}
		}
		first <- "the stream ended without an event"
	}()

	select {
	case line := <-first:
		require.True(t, strings.HasPrefix(line, "data: "), line)
		assert.NotContains(t, line, `"error"`)
	case <-time.After(10 * time.Second):
		t.Fatal("the first event did not reach the caller while the agent kept the stream open")
	}
	released.Do(func() { close(release) })
}
