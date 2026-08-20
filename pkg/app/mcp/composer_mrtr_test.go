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
	"log/slog"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	inputRequiredResult = `{"resultType":"input_required","requestState":"upstream-state-1","inputRequests":[{"kind":"elicitation"}]}`
	completeResult      = `{"resultType":"complete","content":[]}`
)

func newSignedComposer(dialer Dialer, signer *TicketSigner) Composer {
	return NewComposerWithSigner(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler), signer)
}

func testSigner() *TicketSigner {
	return NewTicketSigner("secret", "", 0, 0)
}

func mrtrConsumer(registryID ids.RegistryID, exposeAs string) *consumerdomain.Consumer {
	toolkit := consumerdomain.Toolkit{{RegistryID: registryID, Tool: "search", ExposeAs: exposeAs}}
	return &consumerdomain.Consumer{
		ID:   ids.New[ids.ConsumerKind](),
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{Toolkit: toolkit},
	}
}

func mintTicket(t *testing.T, signer *TicketSigner, claims TicketClaims) string {
	t.Helper()
	ticket, err := signer.Mint(claims)
	if err != nil {
		t.Fatalf("mint ticket: %v", err)
	}
	return ticket
}

func rpcCode(t *testing.T, err error) int64 {
	t.Helper()
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("error = %v, want *RPCError", err)
	}
	return rpcErr.Code
}

// A retry must land on the same upstream tool the first round reached, resolved
// again from the exposed alias, and carry the upstream's own continuation state
// rather than the gateway ticket.
func TestComposer_CallTool_RetryTargetsOriginalTool(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search"), result: json.RawMessage(inputRequiredResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	signer := testSigner()
	c := newSignedComposer(dialer, signer)
	rc := routable(mrtrConsumer(reg.ID, "find"), reg)

	first, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find"})
	if err != nil {
		t.Fatalf("first round: %v", err)
	}
	_, ticket := mrtrResultFields(first)
	if ticket == "" {
		t.Fatal("first round must mint a continuation ticket")
	}
	if ticket == "upstream-state-1" {
		t.Fatal("the upstream state must never be handed to the client")
	}

	up.result = json.RawMessage(completeResult)
	second, err := c.CallTool(context.Background(), rc, ToolCall{
		Name:           "find",
		InputResponses: json.RawMessage(`[{"kind":"elicitation","content":{}}]`),
		RequestState:   ticket,
	})
	if err != nil {
		t.Fatalf("second round: %v", err)
	}
	if up.lastToolCall.Name != "search" {
		t.Fatalf("upstream tool = %q, want search", up.lastToolCall.Name)
	}
	if up.lastToolCall.RequestState != "upstream-state-1" {
		t.Fatalf("upstream requestState = %q, want the upstream state", up.lastToolCall.RequestState)
	}
	if string(second) != completeResult {
		t.Fatalf("second round result = %s", second)
	}
}

// A ticket minted for another consumer must be rejected before any upstream
// call: a stolen continuation cannot be replayed across tenants.
func TestComposer_CallTool_CrossConsumerTicketRejected(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search"), result: json.RawMessage(completeResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	signer := testSigner()
	c := newSignedComposer(dialer, signer)
	rc := routable(mrtrConsumer(reg.ID, "find"), reg)

	ticket := mintTicket(t, signer, TicketClaims{
		CID:      ids.New[ids.ConsumerKind]().String(),
		RID:      reg.ID.String(),
		Exposed:  "find",
		Upstream: "search",
		Method:   MethodToolsCall,
		Round:    1,
	})

	_, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find", RequestState: ticket})
	if got := rpcCode(t, err); got != CodeMRTRReplayRejected {
		t.Fatalf("code = %d, want %d", got, CodeMRTRReplayRejected)
	}
	if up.callCount != 0 {
		t.Fatal("a rejected continuation must never reach the upstream")
	}
}

// A ticket minted for a different exposed alias must be rejected: the binding
// covers the alias the client called, not only the upstream tool behind it.
func TestComposer_CallTool_AliasMismatchRejected(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search"), result: json.RawMessage(completeResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	signer := testSigner()
	c := newSignedComposer(dialer, signer)
	consumer := mrtrConsumer(reg.ID, "find")
	rc := routable(consumer, reg)

	ticket := mintTicket(t, signer, TicketClaims{
		CID:      consumer.ID.String(),
		RID:      reg.ID.String(),
		Exposed:  "other-alias",
		Upstream: "search",
		Method:   MethodToolsCall,
		Round:    1,
	})

	_, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find", RequestState: ticket})
	if got := rpcCode(t, err); got != CodeMRTRReplayRejected {
		t.Fatalf("code = %d, want %d", got, CodeMRTRReplayRejected)
	}
	if up.callCount != 0 {
		t.Fatal("a rejected continuation must never reach the upstream")
	}
}

// The round cap stops an endless elicitation loop with its own code, so the
// client can tell exhaustion from a rejected ticket.
func TestComposer_CallTool_RoundLimitRejected(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search"), result: json.RawMessage(completeResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	signer := testSigner()
	c := newSignedComposer(dialer, signer)
	consumer := mrtrConsumer(reg.ID, "find")
	rc := routable(consumer, reg)

	ticket := mintTicket(t, signer, TicketClaims{
		CID:      consumer.ID.String(),
		RID:      reg.ID.String(),
		Exposed:  "find",
		Upstream: "search",
		Method:   MethodToolsCall,
		Round:    DefaultMRTRMaxRounds,
	})

	_, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find", RequestState: ticket})
	if got := rpcCode(t, err); got != CodeMRTRRoundLimit {
		t.Fatalf("code = %d, want %d", got, CodeMRTRRoundLimit)
	}
	if up.callCount != 0 {
		t.Fatal("an exhausted continuation must never reach the upstream")
	}
}

// A tool that completes in one round is forwarded untouched: no ticket, no
// continuation fields.
func TestComposer_CallTool_OneRoundStaysUnchanged(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search"), result: json.RawMessage(completeResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	c := newSignedComposer(dialer, testSigner())
	rc := routable(mrtrConsumer(reg.ID, "find"), reg)

	res, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res) != completeResult {
		t.Fatalf("result = %s, want it unchanged", res)
	}
	if up.lastToolCall.RequestState != "" {
		t.Fatalf("upstream requestState = %q, want empty on a first round", up.lastToolCall.RequestState)
	}
}

// The retry runs the same policy pass as the first round: a tool the toolkit no
// longer allows is denied even with a valid ticket.
func TestComposer_CallTool_PolicyDeniesRetry(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search", "other"), result: json.RawMessage(completeResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	signer := testSigner()
	c := newSignedComposer(dialer, signer)
	consumer := &consumerdomain.Consumer{
		ID:   ids.New[ids.ConsumerKind](),
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: reg.ID, Tool: "other"},
		}},
	}
	rc := routable(consumer, reg)

	ticket := mintTicket(t, signer, TicketClaims{
		CID:      consumer.ID.String(),
		RID:      reg.ID.String(),
		Exposed:  "search",
		Upstream: "search",
		Method:   MethodToolsCall,
		Round:    1,
	})

	_, err := c.CallTool(context.Background(), rc, ToolCall{Name: "search", RequestState: ticket})
	var denied *ToolNotPermittedError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %v, want a policy denial on the retry", err)
	}
	if up.callCount != 0 {
		t.Fatal("a denied retry must never reach the upstream")
	}
}

// With no ticket secret configured the gateway cannot mediate a continuation,
// so it must not leak the upstream's state: the result is reported complete.
func TestComposer_CallTool_SecretMissingStripsContinuation(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search"), result: json.RawMessage(inputRequiredResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	c := newSignedComposer(dialer, NewTicketSigner("", "", 0, 0))
	rc := routable(mrtrConsumer(reg.ID, "find"), reg)

	res, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultType, state := mrtrResultFields(res)
	if resultType != "complete" {
		t.Fatalf("resultType = %q, want complete", resultType)
	}
	if state != "" {
		t.Fatalf("requestState = %q, want it stripped", state)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(res, &obj); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if _, ok := obj["inputRequests"]; ok {
		t.Fatal("inputRequests must be stripped when mediation is disabled")
	}
}

// A continuation presented without a configured secret is rejected instead of
// being forwarded blindly to the upstream.
func TestComposer_CallTool_SecretMissingRejectsTicket(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &fakeUpstream{tools: tools("search"), result: json.RawMessage(completeResult)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}}
	c := newSignedComposer(dialer, NewTicketSigner("", "", 0, 0))
	rc := routable(mrtrConsumer(reg.ID, "find"), reg)

	_, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find", RequestState: "tg1.c.x.y"})
	if got := rpcCode(t, err); got != CodeMRTRReplayRejected {
		t.Fatalf("code = %d, want %d", got, CodeMRTRReplayRejected)
	}
	if up.callCount != 0 {
		t.Fatal("a rejected continuation must never reach the upstream")
	}
}
