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
	"log/slog"
	"net/url"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"golang.org/x/sync/singleflight"
)

//go:generate mockery --name=Composer --dir=. --output=./mocks --filename=mcp_composer_mock.go --case=underscore --with-expecter
type Composer interface {
	ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Tool, error)
	CallTool(ctx context.Context, rc *appconsumer.RoutableConsumer, call ToolCall) (json.RawMessage, error)
	ListResources(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Resource, error)
	ListResourceTemplates(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]ResourceTemplate, error)
	ReadResource(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (json.RawMessage, error)
	ListPrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Prompt, error)
	GetPrompt(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments map[string]string) (json.RawMessage, error)
	UnwrapTaskHandle(ctx context.Context, rc *appconsumer.RoutableConsumer, handle string) (TaskRef, error)
	GetTask(ctx context.Context, rc *appconsumer.RoutableConsumer, handle string) (json.RawMessage, error)
	UpdateTask(
		ctx context.Context,
		rc *appconsumer.RoutableConsumer,
		handle string,
		inputResponses json.RawMessage,
	) (json.RawMessage, error)
	CancelTask(ctx context.Context, rc *appconsumer.RoutableConsumer, handle string) (json.RawMessage, error)
}

// AppsCallComposer classifies an Apps call during normal tool routing.
type AppsCallComposer interface {
	CallToolClassified(ctx context.Context, rc *appconsumer.RoutableConsumer, call ToolCall) (json.RawMessage, bool, error)
}

var _ Composer = (*composer)(nil)

type composer struct {
	dialer      Dialer
	creds       CredentialResolver
	discovery   DiscoveryCache
	flight      singleflight.Group
	logger      *slog.Logger
	signer      *TicketSigner
	tasks       *TaskHandleSigner
	pollFloorMs int64
}

func NewComposer(dialer Dialer, creds CredentialResolver, discovery DiscoveryCache, logger *slog.Logger) Composer {
	return NewComposerWithSigner(dialer, creds, discovery, logger, nil)
}

func NewComposerWithSigner(
	dialer Dialer,
	creds CredentialResolver,
	discovery DiscoveryCache,
	logger *slog.Logger,
	signer *TicketSigner,
) Composer {
	return NewComposerWithMediation(dialer, creds, discovery, logger, signer, nil, 0)
}

// NewComposerWithMediation wires both mediated continuation primitives: MRTR
// tickets and task handles. A nil task signer leaves task mediation off.
func NewComposerWithMediation(
	dialer Dialer,
	creds CredentialResolver,
	discovery DiscoveryCache,
	logger *slog.Logger,
	signer *TicketSigner,
	tasks *TaskHandleSigner,
	pollFloorMs int64,
) Composer {
	return &composer{
		dialer:      dialer,
		creds:       creds,
		discovery:   discovery,
		logger:      logger,
		signer:      signer,
		tasks:       tasks,
		pollFloorMs: pollFloorMs,
	}
}

type binding struct {
	registry *registrydomain.Registry
	tool     Tool
	exposed  string
}

func (c *composer) ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Tool, error) {
	annotateTargets(ctx, len(mcpRegistries(rc)))
	// Partial federation: upstreams still awaiting consent are skipped and the
	// linked ones are listed. Only when every upstream needs consent does
	// compose report it, so the client is told to visit the connect page.
	comp, err := c.compose(ctx, rc)
	if err != nil {
		return nil, err
	}
	out := make([]Tool, 0, len(comp.bindings))
	for _, b := range comp.bindings {
		t := b.tool
		t.Name = b.exposed
		t.source = b.registry.ID.String()
		out = append(out, t)
	}
	return out, nil
}

func (c *composer) CallTool(ctx context.Context, rc *appconsumer.RoutableConsumer, call ToolCall) (json.RawMessage, error) {
	result, _, err := c.callTool(ctx, rc, call, false)
	return result, err
}

func (c *composer) CallToolClassified(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	call ToolCall,
) (json.RawMessage, bool, error) {
	return c.callTool(ctx, rc, call, true)
}

func (c *composer) callTool(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	call ToolCall,
	classifyApps bool,
) (json.RawMessage, bool, error) {
	comp, err := c.compose(ctx, rc)
	if err != nil {
		return nil, false, err
	}
	for _, b := range comp.bindings {
		if b.exposed != call.Name {
			continue
		}
		appsCall := false
		if classifyApps {
			metadata, marked, metadataErr := toolAppsMetadata(b.tool)
			if marked && (metadataErr != nil || metadata.ResourceURI == "") {
				return nil, false, ErrAppsResourceRejected
			}
			appsCall = marked
		}
		south, producingRound, err := c.bindContinuation(ctx, rc, b, call)
		if err != nil {
			return nil, false, err
		}
		target, err := c.target(ctx, rc, b.registry)
		if err != nil {
			return nil, false, err
		}
		stop := annotateUpstream(ctx, b.registry, b.tool.Name)
		defer stop()
		up, err := c.dialer.Connect(ctx, target)
		if err != nil {
			return nil, false, err
		}
		defer up.Close(ctx)
		result, err := up.CallTool(ctx, south)
		if err != nil {
			return nil, false, err
		}
		result, err = c.wrapContinuation(ctx, rc, b, call, producingRound, result)
		return result, appsCall, err
	}
	if _, forbidden := comp.denied[call.Name]; forbidden {
		return nil, false, &ToolNotPermittedError{Tool: call.Name}
	}
	if comp.consent != nil {
		return nil, false, comp.consent
	}
	return nil, false, fmt.Errorf("%w: %s", ErrToolNotFound, call.Name)
}

func (c *composer) bindContinuation(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	b binding,
	call ToolCall,
) (ToolCall, int, error) {
	south := ToolCall{
		Name:           b.tool.Name,
		Arguments:      call.Arguments,
		InputResponses: call.InputResponses,
	}
	round := 1
	if call.RequestState == "" {
		stampMRTR(ctx, "", round)
		return south, round, nil
	}
	claims, err := c.unwrapTicket(call.RequestState)
	if err != nil {
		stampMRTR(ctx, trace.MRTROutcomeReplayRejected, round)
		return ToolCall{}, 0, MapMRTRError(err)
	}
	round = claims.Round + 1
	if claims.Round >= c.maxRounds() {
		stampMRTR(ctx, trace.MRTROutcomeRoundLimit, round)
		return ToolCall{}, 0, MRTRRoundLimitRPCError()
	}
	if rc == nil || rc.Consumer == nil || b.registry == nil ||
		!claims.Binds(rc.Consumer.ID.String(), b.registry.ID.String(), call.Name, b.tool.Name, MethodToolsCall) {
		stampMRTR(ctx, trace.MRTROutcomeReplayRejected, round)
		return ToolCall{}, 0, MRTRReplayRPCError()
	}
	stampMRTR(ctx, "", round)
	south.RequestState = claims.State
	return south, round, nil
}

func (c *composer) unwrapTicket(ticket string) (*TicketClaims, error) {
	if c.signer == nil || !c.signer.Enabled() {
		return nil, ErrMRTRReplayRejected
	}
	return c.signer.Unwrap(ticket)
}

func (c *composer) maxRounds() int {
	if c.signer == nil {
		return DefaultMRTRMaxRounds
	}
	return c.signer.MaxRounds()
}

func (c *composer) wrapContinuation(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	b binding,
	call ToolCall,
	producingRound int,
	result json.RawMessage,
) (json.RawMessage, error) {
	resultType, upstreamState := mrtrResultFields(result)
	// A task result is checked before the MRTR branch: it is a third answer
	// shape, and letting it fall through would report it as complete and strip
	// the fields the client needs to poll.
	if resultType == ResultTypeTask {
		return c.wrapTask(ctx, rc, b, call, result)
	}
	if resultType != trace.MRTROutcomeInputRequired {
		stampMRTR(ctx, trace.MRTROutcomeComplete, 0)
		return result, nil
	}
	if c.signer == nil || !c.signer.Enabled() {
		stampMRTR(ctx, trace.MRTROutcomeComplete, 0)
		return stripMRTRResult(result), nil
	}
	consumerID, registryID := "", ""
	if rc != nil && rc.Consumer != nil {
		consumerID = rc.Consumer.ID.String()
	}
	if b.registry != nil {
		registryID = b.registry.ID.String()
	}
	ticket, err := c.signer.Mint(TicketClaims{
		CID:      consumerID,
		RID:      registryID,
		Exposed:  call.Name,
		Upstream: b.tool.Name,
		Method:   MethodToolsCall,
		Round:    producingRound,
		State:    upstreamState,
	})
	if err != nil {
		return nil, MapMRTRError(err)
	}
	stampMRTR(ctx, trace.MRTROutcomeInputRequired, 0)
	return replaceRequestState(result, ticket), nil
}

func stampMRTR(ctx context.Context, outcome string, round int) {
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPMRTR(outcome, trace.BoundMRTRRound(round))
	}
}

func mrtrResultFields(raw json.RawMessage) (resultType, requestState string) {
	var env struct {
		ResultType   string `json:"resultType"`
		RequestState string `json:"requestState"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", ""
	}
	return env.ResultType, env.RequestState
}

func stripMRTRResult(raw json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}
	complete, _ := json.Marshal(trace.MRTROutcomeComplete)
	obj["resultType"] = complete
	delete(obj, "requestState")
	delete(obj, "inputRequests")
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

func replaceRequestState(raw json.RawMessage, ticket string) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}
	encoded, err := json.Marshal(ticket)
	if err != nil {
		return raw
	}
	obj["requestState"] = encoded
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// annotateUpstream records the resolved upstream registry on the active MCP
// span and returns a stop function that captures the upstream call latency.
func annotateUpstream(ctx context.Context, reg *registrydomain.Registry, upstreamTool string) func() {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return func() {}
	}
	var host, catalog, transport string
	if reg.MCPTarget != nil {
		host = hostFromURL(reg.MCPTarget.URL)
		catalog = reg.MCPTarget.Code
		transport = string(reg.MCPTarget.Transport)
	}
	span.SetMCPUpstream(reg.Name, reg.ID.String(), host, catalog, transport, upstreamTool)
	start := time.Now()
	return func() { span.SetLatency(time.Since(start)) }
}

func annotateTargets(ctx context.Context, count int) {
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPTargets(count)
	}
}

func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// compose discovers every upstream bound to the consumer and returns the tool
// bindings of the reachable ones. An upstream awaiting user consent never
// aborts the composition — it is skipped so the linked upstreams still federate
// — and its consent requirement is reported separately so each caller can
// decide whether it is relevant: listing ignores it, calling a tool no reachable
// upstream serves reports it. Only when nothing at all could be composed does it
// become the returned error.
func (c *composer) compose(ctx context.Context, rc *appconsumer.RoutableConsumer) (*composition, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	failOpen := rc.Consumer.FailMode() != consumerdomain.FailModeClosed
	toolkit := rc.Consumer.Toolkit()

	var candidates []binding
	var pendingConsent *ConsentRequiredError
	denied := make(map[string]struct{})
	reachable := 0
	for _, found := range c.discoverTools(ctx, rc, registries) {
		reg, tools := found.registry, found.items
		if err := found.err; err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var consentErr *ConsentRequiredError
			if errors.As(err, &consentErr) {
				// Partial consent is allowed on the connect page — skip unlinked
				// upstreams during federation and serve tools from linked ones.
				if pendingConsent == nil {
					pendingConsent = consentErr
				}
				markCompositionDegraded(ctx)
				c.logger.Info("mcp composer: skipping upstream pending consent",
					"registry", reg.Name, "provider", consentErr.Provider)
				continue
			}
			if !failOpen {
				return nil, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, err)
			}
			markCompositionDegraded(ctx)
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", err)
			continue
		}
		reachable++
		kept := selectTools(toolkit, reg, tools)
		candidates = append(candidates, kept...)
		// Remember what the toolkit turned away. A call for one of these is a
		// policy denial, and answering it with "not found" — or worse, with a
		// consent prompt for an unrelated upstream — hides the real reason.
		if toolkit != nil {
			allowed := make(map[string]struct{}, len(kept))
			for _, b := range kept {
				allowed[b.tool.Name] = struct{}{}
			}
			for _, t := range tools {
				if _, ok := allowed[t.Name]; !ok {
					denied[t.Name] = struct{}{}
				}
			}
		}
	}
	if reachable == 0 {
		// Nothing could be composed. A pending consent requirement is the more
		// actionable explanation, so it wins over a bare "unreachable".
		if pendingConsent != nil {
			return nil, pendingConsent
		}
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	bindings := resolveNames(candidates)
	// A name that another registry ends up exposing was never really denied.
	for _, b := range bindings {
		delete(denied, b.exposed)
	}
	return &composition{bindings: bindings, denied: denied, consent: pendingConsent}, nil
}

// composition is the consumer's effective MCP surface for one request: the tool
// bindings it may use, the tools its toolkit turned away, and any upstream that
// is still awaiting user consent.
type composition struct {
	bindings []binding
	denied   map[string]struct{}
	consent  *ConsentRequiredError
}

func selectTools(toolkit consumerdomain.Toolkit, reg *registrydomain.Registry, tools []Tool) []binding {
	if toolkit == nil {
		out := make([]binding, 0, len(tools))
		for _, t := range tools {
			out = append(out, binding{registry: reg, tool: t, exposed: t.Name})
		}
		return out
	}
	entries := toolkit.EntriesFor(reg.ID)
	if len(entries) == 0 {
		return nil
	}
	byName := make(map[string]Tool, len(tools))
	for _, t := range tools {
		byName[t.Name] = t
	}
	var out []binding
	seen := make(map[string]struct{}, len(tools))
	for _, e := range entries {
		if e.Tool == consumerdomain.ToolWildcard {
			continue
		}
		t, ok := byName[e.Tool]
		if !ok {
			continue
		}
		if _, dup := seen[t.Name]; dup {
			continue
		}
		seen[t.Name] = struct{}{}
		exposed := t.Name
		if e.ExposeAs != "" {
			exposed = e.ExposeAs
		}
		out = append(out, binding{registry: reg, tool: t, exposed: exposed})
	}
	for _, e := range entries {
		if e.Tool != consumerdomain.ToolWildcard {
			continue
		}
		for _, t := range tools {
			if _, dup := seen[t.Name]; dup {
				continue
			}
			seen[t.Name] = struct{}{}
			out = append(out, binding{registry: reg, tool: t, exposed: t.Name})
		}
	}
	return out
}
