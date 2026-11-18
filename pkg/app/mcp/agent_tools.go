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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	// ListAgentsToolName lists the A2A agents the calling person may call.
	ListAgentsToolName = "trustgate_list_agents"
	// CallAgentToolName sends a message to one of those agents, or reads one
	// of its tasks.
	CallAgentToolName = "trustgate_call_agent"
)

// ErrAgentToolsUnavailable is returned when the agent tools cannot serve a
// request: nothing to call agents through, or no gateway data on the request.
var ErrAgentToolsUnavailable = errors.New("mcp: agent tools unavailable")

const agentNotAvailable = "That agent was not found or is not available to you. Call " + ListAgentsToolName + " to see the agents you can call."

// AgentTools are the Employee portal's agent meta-tools, offered on the Store
// only: list the agents a person may call, and call one.
type AgentTools interface {
	Definitions() []Tool
	Handles(name string) bool
	Call(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error)
}

type agentTools struct {
	forwarder *appa2a.Forwarder
	access    storeaccessdomain.AgentAccessReader
	timeout   time.Duration
}

// NewAgentTools wires the agent meta-tools. A call runs through forwarder like
// one on the agent plane, and gives up after timeout so the answer reaches the
// client before the server's write deadline; zero waits as long as the
// forwarder does.
func NewAgentTools(forwarder *appa2a.Forwarder, access storeaccessdomain.AgentAccessReader, timeout time.Duration) (AgentTools, error) {
	if forwarder == nil || access == nil {
		return nil, ErrAgentToolsUnavailable
	}
	return &agentTools{forwarder: forwarder, access: access, timeout: timeout}, nil
}

func (t *agentTools) Handles(name string) bool {
	return name == ListAgentsToolName || name == CallAgentToolName
}

func (t *agentTools) Definitions() []Tool {
	out := make([]Tool, 0, 2)
	for _, def := range []map[string]any{listAgentsDefinition(), callAgentDefinition()} {
		raw, err := json.Marshal(def)
		if err != nil {
			continue
		}
		var tool Tool
		if json.Unmarshal(raw, &tool) == nil {
			out = append(out, tool)
		}
	}
	return out
}

func (t *agentTools) Call(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	data, ok := appconsumer.DataFromContext(ctx)
	if !ok || data == nil {
		return nil, ErrAgentToolsUnavailable
	}
	switch name {
	case ListAgentsToolName:
		return t.list(ctx, data, arguments)
	case CallAgentToolName:
		return t.call(ctx, data, arguments)
	default:
		return nil, fmt.Errorf("%w: unknown tool %q", ErrAgentToolsUnavailable, name)
	}
}

// allowed is the gateway's enabled agents the request's principal may call,
// by name.
func (t *agentTools) allowed(ctx context.Context, data *appconsumer.Data) ([]*registrydomain.Registry, error) {
	agents := data.Agents()
	if len(agents) == 0 {
		return nil, nil
	}
	rows, err := t.access.ListAgentAccessByGateway(ctx, data.GatewayID)
	if err != nil {
		return nil, err
	}
	agentIDs := make([]ids.RegistryID, 0, len(agents))
	for _, a := range agents {
		agentIDs = append(agentIDs, a.ID)
	}
	p := identity.PrincipalFromContext(ctx)
	permitted := storeaccessdomain.AgentsFor(rows, p.StoreSubject(), p.StoreGroups(), agentIDs)
	out := make([]*registrydomain.Registry, 0, len(permitted))
	for _, a := range agents {
		if slices.Contains(permitted, a.ID) {
			out = append(out, a)
		}
	}
	return out, nil
}

type agentSkill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type agentEntry struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Skills      []agentSkill `json:"skills"`
	Version     string       `json:"version"`
	Streams     bool         `json:"streams"`
}

// describeAgent reads what the pinned card says about the agent. A skill
// TrustGuard flagged is left out: its text is what a model calling the agent
// would read.
func describeAgent(reg *registrydomain.Registry) agentEntry {
	target := reg.A2ATarget
	var card struct {
		Description string       `json:"description"`
		Skills      []agentSkill `json:"skills"`
	}
	_ = json.Unmarshal(target.Card, &card)
	flagged := make(map[string]struct{})
	for _, v := range target.SkillScan {
		if v.Flagged {
			flagged[v.SkillID] = struct{}{}
		}
	}
	skills := make([]agentSkill, 0, len(card.Skills))
	for _, s := range card.Skills {
		if _, bad := flagged[s.ID]; bad {
			continue
		}
		skills = append(skills, agentSkill{ID: s.ID, Name: strings.TrimSpace(s.Name), Description: strings.TrimSpace(s.Description)})
	}
	return agentEntry{
		ID:          reg.ID.String(),
		Name:        reg.Name,
		Description: strings.TrimSpace(card.Description),
		Skills:      skills,
		Version:     string(target.ProtocolVersion),
		Streams:     appa2a.CanStream(target),
	}
}

func (e agentEntry) matches(query string) bool {
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(e.Name), query) || strings.Contains(strings.ToLower(e.Description), query) {
		return true
	}
	for _, s := range e.Skills {
		if strings.Contains(strings.ToLower(s.Name), query) {
			return true
		}
	}
	return false
}

func (t *agentTools) list(ctx context.Context, data *appconsumer.Data, arguments json.RawMessage) (json.RawMessage, error) {
	var args struct {
		Query string `json:"query"`
	}
	if len(bytes.TrimSpace(arguments)) > 0 && json.Unmarshal(arguments, &args) != nil {
		return toolErrorResult(ListAgentsToolName+" takes {\"query\": <text>}, or no arguments.", map[string]any{"error": "invalid_arguments"})
	}
	agents, err := t.allowed(ctx, data)
	if err != nil {
		return nil, err
	}
	query := strings.ToLower(strings.TrimSpace(args.Query))
	entries := make([]agentEntry, 0, len(agents))
	for _, reg := range agents {
		if entry := describeAgent(reg); entry.matches(query) {
			entries = append(entries, entry)
		}
	}
	structured := map[string]any{"agents": entries}
	switch {
	case len(agents) == 0:
		return marshalToolResult("You have no agents yet. An administrator publishes agents to you in Access → Agents.", structured)
	case len(entries) == 0:
		return marshalToolResult(fmt.Sprintf("None of your agents matches %q. Call %s without a query to list them all.", args.Query, ListAgentsToolName), structured)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "You can call %d agent(s):", len(entries))
	for _, e := range entries {
		fmt.Fprintf(&b, "\n\n• %s (id: %s) — A2A %s", e.Name, e.ID, e.Version)
		if e.Streams {
			b.WriteString(", streams")
		}
		if e.Description != "" {
			fmt.Fprintf(&b, "\n  %s", oneLine(e.Description))
		}
		for _, s := range e.Skills {
			fmt.Fprintf(&b, "\n  - %s", s.Name)
			if s.Description != "" {
				fmt.Fprintf(&b, ": %s", oneLine(s.Description))
			}
		}
	}
	b.WriteString("\n\nCall one with " + CallAgentToolName + " {\"agent\": <id or name>, \"message\": <text>}, and pass the context_id it returns to continue the conversation.")
	return marshalToolResult(b.String(), structured)
}

func oneLine(text string) string {
	if i := strings.IndexAny(text, "\r\n"); i >= 0 {
		text = text[:i]
	}
	return truncateDescription(text)
}

type callAgentArgs struct {
	Agent     string `json:"agent"`
	Message   string `json:"message"`
	ContextID string `json:"context_id"`
	TaskID    string `json:"task_id"`
}

// CallAgentTarget reads the agent and the message of a tools/call of
// CallAgentToolName. ok is false for any other call.
func CallAgentTarget(params json.RawMessage) (agent, message string, ok bool) {
	var call struct {
		Name      string        `json:"name"`
		Arguments callAgentArgs `json:"arguments"`
	}
	if json.Unmarshal(params, &call) != nil || call.Name != CallAgentToolName {
		return "", "", false
	}
	return strings.TrimSpace(call.Arguments.Agent), call.Arguments.Message, true
}

func (t *agentTools) call(ctx context.Context, data *appconsumer.Data, arguments json.RawMessage) (json.RawMessage, error) {
	var args callAgentArgs
	if err := json.Unmarshal(arguments, &args); err != nil {
		return toolErrorResult(CallAgentToolName+" takes {\"agent\": <id or name>, \"message\": <text>}, with an optional \"context_id\", or {\"agent\", \"task_id\"} to read a task.", map[string]any{"error": "invalid_arguments"})
	}
	args.Agent, args.ContextID, args.TaskID = strings.TrimSpace(args.Agent), strings.TrimSpace(args.ContextID), strings.TrimSpace(args.TaskID)
	if (strings.TrimSpace(args.Message) == "") == (args.TaskID == "") {
		return toolErrorResult(CallAgentToolName+" needs exactly one of `message` (what to send) and `task_id` (a task to read).", map[string]any{"error": "invalid_arguments"})
	}
	agents, err := t.allowed(ctx, data)
	if err != nil {
		return nil, err
	}
	reg, found := pickAgent(agents, args.Agent)
	if !found || data.AgentConsumer == nil {
		return toolErrorResult(agentNotAvailable, map[string]any{"error": "agent_not_available"})
	}
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPRequest("tools/call", "tool", reg.Name, "", "")
		span.SetMCPUpstream(reg.Name, reg.ID.String(), hostFromURL(reg.A2ATarget.Endpoint()), "", "", "")
	}
	version := reg.A2ATarget.ProtocolVersion
	body := appa2a.ChatCall(version, false, args.Message, args.ContextID)
	if args.TaskID != "" {
		body = getTaskCall(version, args.TaskID)
	}
	req, rpcErr := appa2a.Decode(body)
	if rpcErr != nil {
		return agentFailure(reg, rpcErr)
	}
	callCtx := ctx
	if t.timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	x, rpcErr := t.forwarder.Prepare(callCtx, &appa2a.Call{
		Consumer:  data.AgentConsumer,
		Agent:     reg,
		Principal: identity.PrincipalFromContext(ctx),
		Request:   req,
		Body:      body,
		Header:    http.Header{},
	})
	var result json.RawMessage
	if rpcErr == nil {
		result, rpcErr = x.Send(callCtx)
	}
	if rpcErr != nil {
		if callCtx.Err() != nil && ctx.Err() == nil {
			return agentTimeout(reg, args.TaskID)
		}
		return agentFailure(reg, rpcErr)
	}
	if args.TaskID != "" && version == appa2a.Version10 {
		result = wrapTask(result)
	}
	return agentAnswer(version, result)
}

// pickAgent finds an agent by id, or by its exact name when one agent alone
// has it.
func pickAgent(agents []*registrydomain.Registry, ref string) (*registrydomain.Registry, bool) {
	var named *registrydomain.Registry
	count := 0
	for _, a := range agents {
		if a.ID.String() == ref {
			return a, true
		}
		if a.Name == ref {
			named = a
			count++
		}
	}
	return named, count == 1
}

func getTaskCall(v appa2a.Version, taskID string) []byte {
	method := "tasks/get"
	if v == appa2a.Version10 {
		method = "GetTask"
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": uuid.NewString(), "method": method, "params": map[string]any{"id": taskID}})
	return raw
}

// wrapTask puts a 1.0 GetTask answer, which is the task itself, in the
// wrapper a send answer carries it in.
func wrapTask(result json.RawMessage) json.RawMessage {
	var o map[string]json.RawMessage
	if json.Unmarshal(result, &o) != nil {
		return result
	}
	if _, wrapped := o["task"]; wrapped {
		return result
	}
	raw, err := json.Marshal(map[string]json.RawMessage{"task": result})
	if err != nil {
		return result
	}
	return raw
}

func agentAnswer(v appa2a.Version, result json.RawMessage) (json.RawMessage, error) {
	text, contextID := appa2a.ChatText(v, result)
	content, _ := appa2a.ResultContent(v, result)
	if contextID == "" {
		contextID = content.ContextID
	}
	state := strings.ToLower(strings.TrimPrefix(content.State, "TASK_STATE_"))
	structured := map[string]any{"text": text, "context_id": contextID}
	var b strings.Builder
	b.WriteString(text)
	if text == "" {
		b.WriteString("The agent answered without text.")
	}
	if contextID != "" {
		fmt.Fprintf(&b, "\n\ncontext_id: %s", contextID)
	}
	if content.TaskID != "" && state != "" && state != "completed" {
		structured["task_id"], structured["state"] = content.TaskID, state
		fmt.Fprintf(&b, "\ntask_id: %s (state: %s)", content.TaskID, state)
	}
	return marshalToolResult(b.String(), structured)
}

func agentTimeout(reg *registrydomain.Registry, taskID string) (json.RawMessage, error) {
	text := reg.Name + " did not answer in time."
	structured := map[string]any{"error": "timeout"}
	if taskID != "" {
		text += fmt.Sprintf(" Read the task later with %s {\"agent\": %q, \"task_id\": %q}.", CallAgentToolName, reg.ID.String(), taskID)
		structured["task_id"] = taskID
	}
	return toolErrorResult(text, structured)
}

func agentFailure(reg *registrydomain.Registry, e *appa2a.RPCError) (json.RawMessage, error) {
	_, kind := appa2a.ChatStatus(e)
	var data struct {
		RetryAfter int    `json:"retry_after"`
		Message    string `json:"message"`
	}
	_ = json.Unmarshal(e.Data, &data)
	var text string
	switch e.Code {
	case appa2a.CodePolicyBlocked:
		text = "Blocked by the gateway's policy."
	case appa2a.CodeRateLimited:
		text = "Rate limit exceeded."
		if data.RetryAfter > 0 {
			text += fmt.Sprintf(" Retry in %d seconds.", data.RetryAfter)
		}
	case appa2a.CodeIdentityRequired:
		text = reg.Name + " acts with your own identity, and this connection does not carry one the agent accepts."
	case appa2a.CodeTaskNotFound:
		text = reg.Name + " has no such task or conversation of yours."
	default:
		text = strings.TrimSpace(data.Message)
		if text == "" {
			text = strings.TrimSpace(e.Message)
		}
		text = reg.Name + ": " + text
	}
	return toolErrorResult(text, map[string]any{"error": kind, "code": e.Code})
}

func listAgentsDefinition() map[string]any {
	return map[string]any{
		"name":  ListAgentsToolName,
		"title": "List the agents this user can call",
		"description": "List the A2A agents the user may call through this gateway: each agent's id, name, description, skills, A2A version and whether it streams. " +
			"Call it when the user asks for an agent, or for a task one of their agents would do; then call one with " + CallAgentToolName + "." + GatewayToolDisclaimer,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "Only the agents whose name, description or skill names contain this text (case-insensitive). Omit to list them all.",
				},
			},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    true,
			"destructiveHint": false,
			"idempotentHint":  true,
			"openWorldHint":   false,
		},
	}
}

func callAgentDefinition() map[string]any {
	return map[string]any{
		"name":  CallAgentToolName,
		"title": "Send a message to one of the user's agents",
		"description": "Send a message to one of the user's A2A agents and return its answer, with the context_id that continues the conversation. " +
			"Pass `context_id` from an earlier answer to continue it. An answer that names a task_id that is not completed can be read again later with `task_id` instead of `message`. " +
			"Find the agents with " + ListAgentsToolName + ". The call runs through the gateway's policies, as the user." + GatewayToolDisclaimer,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent": map[string]any{
					"type":        "string",
					"description": "The agent's id, or its exact name when no other agent has it, as " + ListAgentsToolName + " lists it.",
				},
				"message": map[string]any{
					"type":        "string",
					"description": "The text to send. Give either this or task_id.",
				},
				"context_id": map[string]any{
					"type":        "string",
					"description": "The context_id of an earlier answer, to continue that conversation.",
				},
				"task_id": map[string]any{
					"type":        "string",
					"description": "A task an earlier answer named, to read its current state instead of sending a message.",
				},
			},
			"required":             []string{"agent"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": true,
			"idempotentHint":  false,
			"openWorldHint":   true,
		},
	}
}
