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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const (
	// defaultSubscriptionMaxEventBytes mirrors MCP_SUBSCRIPTIONS_MAX_EVENT_BYTES
	// so a lease opened with an unset bound is still bounded.
	defaultSubscriptionMaxEventBytes = 8192

	methodSubscriptionsAcknowledged = "notifications/subscriptions/acknowledged"

	headerAccelBuffering = "X-Accel-Buffering"

	// subscriptionJitterDivisor spreads deadlines over the last tenth of the
	// configured lifetime, so a fleet opened in lockstep does not re-open in
	// lockstep.
	subscriptionJitterDivisor = 10

	// maxInconclusivePasses ends a lease whose surface could not be re-verified
	// this many times running. Emitting against an authorization decision that is
	// no longer known to hold is worse than making the client re-open.
	maxInconclusivePasses = 3
)

// SubscriptionsSupport carries the bounded-subscription dependencies the
// northbound handler needs. The flag field is On rather than Enabled so the
// predicate can keep the TasksSupport name.
type SubscriptionsSupport struct {
	On             bool
	MaxLifetime    time.Duration
	ReauthInterval time.Duration
	Keepalive      time.Duration
	MaxEventBytes  int
	MaxURIs        int
	Registry       *appmcp.SubscriptionRegistry
	Policy         appmcp.SubscriptionPolicy
	Recorder       SubscriptionsRecorder
	Upstream       bool
	Targets        appmcp.SubscriptionTargetResolver
	Source         appmcp.SubscriptionSource
}

// Enabled reports whether the feature can serve a lease at all. While it is
// false subscriptions/listen is not a known method, so the kill switch restores
// the pre-subscriptions wire behaviour exactly. A lease with no policy could
// never re-authorize, so it is not served either.
func (s SubscriptionsSupport) Enabled() bool {
	return s.On && s.Registry != nil && s.Policy != nil
}

// UpstreamEnabled reports whether definitive upstream negotiation is available.
func (s SubscriptionsSupport) UpstreamEnabled() bool {
	return s.Enabled() && s.Upstream && s.Targets != nil && s.Source != nil
}

// subscriptionOutcome is the bounded reason a lease ended. It never reaches the
// wire: the terminal frame is the same bytes whichever value this holds.
type subscriptionOutcome string

const (
	subscriptionOutcomeOpened       subscriptionOutcome = trace.SubscriptionOutcomeOpened
	subscriptionOutcomeRefused      subscriptionOutcome = trace.SubscriptionOutcomeRefused
	subscriptionOutcomeEmitted      subscriptionOutcome = trace.SubscriptionOutcomeEmitted
	subscriptionOutcomeAcked        subscriptionOutcome = trace.SubscriptionOutcomeAcked
	subscriptionOutcomeDeadline     subscriptionOutcome = trace.SubscriptionOutcomeDeadline
	subscriptionOutcomeShutdown     subscriptionOutcome = trace.SubscriptionOutcomeShutdown
	subscriptionOutcomeDisconnected subscriptionOutcome = trace.SubscriptionOutcomeDisconnected
	subscriptionOutcomeOversize     subscriptionOutcome = trace.SubscriptionOutcomeOversize
	subscriptionOutcomeRevoked      subscriptionOutcome = trace.SubscriptionOutcomeRevoked
	subscriptionOutcomeDegraded     subscriptionOutcome = trace.SubscriptionOutcomeDegraded

	// subscriptionOutcomeFailed is a recovered panic. It is deliberately outside
	// the bounded telemetry enumeration, so it is reported as an operational
	// server error on the route rather than as a lease outcome label.
	subscriptionOutcomeFailed subscriptionOutcome = "failed"
)

// opsOutcome maps a lease outcome onto the bounded operational outcome set. Every
// termination the protocol defines is an ordinary completed request; only a
// recovered panic is a server error.
func (o subscriptionOutcome) opsOutcome() o11y.Outcome {
	if o == subscriptionOutcomeFailed {
		return o11y.OutcomeServerError
	}
	return o11y.OutcomeAllowed
}

// subscriptionListenParamsLocal carries the validated listen negotiation from the
// protocol boundary to the dispatch branch, so the params are parsed once.
const subscriptionListenParamsLocal = "mcp.subscriptions.listen.params"

// SubscriptionsListenResult is the one terminal result a lease produces. It
// reports the honoured subset and nothing about why the lease ended: every
// termination cause shares this shape.
type SubscriptionsListenResult struct {
	Notifications []appmcp.NotificationKind `json:"notifications"`
	Meta          map[string]any            `json:"_meta,omitempty"`
}

// streamSpec is everything the loop needs, captured before the handler returns.
// Fiber pools *fiber.Ctx and recycles it once the handler returns, so no field
// here may reference it. The ack and terminal frames are rendered at open, which
// is also what makes the terminal frame byte-identical across every termination
// cause.
type streamSpec struct {
	honoured      appmcp.HonouredSet
	identity      appmcp.LeaseIdentity
	policy        appmcp.SubscriptionPolicy
	recorder      SubscriptionsRecorder
	ack           []byte
	terminal      []byte
	notifications map[appmcp.NotificationKind][]byte
	timers        subscriptionTimers
	budget        time.Duration
	source        appmcp.SubscriptionHandle
	watchdogOnly  bool
}

// subscriptionTimers is the loop's three time sources, injectable so every
// ordering assertion is a unit test with no sleeps.
type subscriptionTimers struct {
	Reauth    <-chan time.Time
	Keepalive <-chan time.Time
	Deadline  <-chan time.Time
	Remaining func() time.Duration
	Stop      func()
}

// newSubscriptionTimers arms the lease deadline and the two tickers. The
// effective deadline is drawn once, here, and lands in [0.9*lifetime, lifetime).
func newSubscriptionTimers(
	lifetime, reauth, keepalive time.Duration,
	jitter func(time.Duration) time.Duration,
) subscriptionTimers {
	effective := lifetime
	if jitter != nil {
		if drawn := lifetime - jitter(lifetime); drawn > 0 {
			effective = drawn
		}
	}
	deadline := time.NewTimer(effective)
	expiresAt := time.Now().Add(effective)
	stops := []func(){func() { deadline.Stop() }}

	timers := subscriptionTimers{
		Deadline:  deadline.C,
		Remaining: func() time.Duration { return time.Until(expiresAt) },
	}
	if reauth > 0 {
		ticker := time.NewTicker(reauth)
		timers.Reauth = ticker.C
		stops = append(stops, ticker.Stop)
	}
	if keepalive > 0 {
		ticker := time.NewTicker(keepalive)
		timers.Keepalive = ticker.C
		stops = append(stops, ticker.Stop)
	}
	timers.Stop = func() {
		for _, stop := range stops {
			stop()
		}
	}
	return timers
}

// subscriptionJitter draws the reduction applied to a configured lifetime. The
// draw is in [1, lifetime/10], so the deadline never equals the configured
// lifetime and never falls below nine tenths of it.
func subscriptionJitter(lifetime time.Duration) time.Duration {
	span := int64(lifetime / subscriptionJitterDivisor)
	if span <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(span) + 1) // #nosec G404 -- scheduling jitter is not security-sensitive
}

func (h *Handler) handleSubscriptionsListen(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	listen, _ := c.Locals(subscriptionListenParamsLocal).(subscriptionListenParams)
	identity := h.leaseIdentity(c, rc, honouredSubset(listen.requested, rc))
	if err := h.gateway.OpenSubscriptionLease(c.UserContext(), rc, identity.Honoured); err != nil {
		return writeAppError(c, req.ID, err, protocolEraModern, appmcp.MethodSubscriptionsListen)
	}

	// The lease is claimed before a single byte is written, so a capacity
	// refusal is an ordinary buffered JSON-RPC error with no stream ever
	// having existed.
	lease, err := h.subs.Registry.Claim(c.UserContext(), identity.Key)
	if err != nil {
		h.recordSubscription(c.UserContext(), "", subscriptionOutcomeRefused)
		stampSubscriptionSpan(c.UserContext(), subscriptionOutcomeRefused)
		return writeSubscriptionRefused(c, req.ID)
	}

	var source appmcp.SubscriptionHandle
	if h.subs.UpstreamEnabled() {
		var attachErr error
		source, identity.Honoured, attachErr = h.attachUpstream(c, listen.requested, identity)
		if attachErr != nil {
			lease.Release()
			if errors.Is(attachErr, appmcp.ErrSubscriptionListenerCapacity) {
				h.recordSubscription(c.UserContext(), "", subscriptionOutcomeRefused)
				stampSubscriptionSpan(c.UserContext(), subscriptionOutcomeRefused)
				return writeSubscriptionRefused(c, req.ID)
			}
			middleware.SetOpsOutcome(c, o11y.OutcomeServerError)
			h.recordSubscription(c.UserContext(), "", subscriptionOutcomeFailed)
			stampSubscriptionSpan(c.UserContext(), subscriptionOutcomeFailed)
			return writeJSONStatus(c, fiber.StatusServiceUnavailable, rpcResponse{
				JSONRPC: "2.0",
				ID:      normalizeID(req.ID),
				Error: &rpcError{
					Code:    int(appmcp.CodeUnavailable),
					Message: appmcp.ErrUpstreamUnavailable.Error(),
				},
			})
		}
	}

	spec, err := h.newStreamSpec(c, req, rc, identity, source)
	if err != nil {
		if source != nil {
			source.Close()
		}
		lease.Release()
		return writeRPCErrorStatus(c, req.ID, fiber.StatusInternalServerError, codeInternalError, "internal error", nil)
	}

	setSubscriptionStreamHeaders(c)
	ops := middleware.ClaimOpsStream(c, o11y.RouteMCPSubscription)
	metrics := claimStreamMetrics(c)
	maxEventBytes := h.subs.MaxEventBytes
	leaseCtx := lease.Context()
	recorder := h.subs.Recorder

	h.recordSubscription(c.UserContext(), "", subscriptionOutcomeOpened)
	recordSubscriptionLive(c.UserContext(), recorder, 1)
	stampSubscriptionSpan(c.UserContext(), subscriptionOutcomeOpened)

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		outcome := subscriptionOutcomeShutdown
		// PanicRecoverMiddleware wraps the handler, not fasthttp's stream
		// goroutine, and the stream reader does not recover either, so an
		// unrecovered panic here would take the process down.
		defer func() { _ = recover() }()
		defer func() {
			ops(outcome.opsOutcome(), fiber.StatusOK)
			if metrics != nil {
				metrics(nil, nil, fiber.StatusOK, nil)
			}
			recordSubscriptionOutcome(leaseCtx, recorder, "", outcome)
			recordSubscriptionLive(leaseCtx, recorder, -1)
			lease.Release()
		}()
		outcome = runSubscriptionStream(leaseCtx, newBufioSink(w, maxEventBytes), spec)
	})
	return nil
}

func (h *Handler) attachUpstream(
	c *fiber.Ctx,
	requested appmcp.HonouredSet,
	identity appmcp.LeaseIdentity,
) (appmcp.SubscriptionHandle, appmcp.HonouredSet, error) {
	requests, err := h.subs.Targets.Resolve(
		c.UserContext(),
		identity.GatewayID,
		identity.Path,
		requested,
	)
	if err != nil {
		return nil, appmcp.HonouredSet{}, err
	}
	handle, prepared, err := h.subs.Source.Attach(c.UserContext(), requests)
	if err != nil {
		return nil, appmcp.HonouredSet{}, err
	}
	return handle, identity.Honoured.Intersect(prepared), nil
}

func (h *Handler) recordSubscription(
	ctx context.Context,
	kind appmcp.NotificationKind,
	outcome subscriptionOutcome,
) {
	recordSubscriptionOutcome(ctx, h.subs.Recorder, kind, outcome)
}

// recordSubscriptionOutcome counts one bounded lease lifecycle event. Nothing
// derived from the request reaches the label set: the kind and the outcome are
// both closed enumerations and the era of a listen is always modern.
func recordSubscriptionOutcome(
	ctx context.Context,
	recorder SubscriptionsRecorder,
	kind appmcp.NotificationKind,
	outcome subscriptionOutcome,
) {
	if recorder == nil {
		return
	}
	recorder.Record(ctx, string(kind), string(outcome), eraLabel(protocolEraModern))
}

func recordSubscriptionLive(ctx context.Context, recorder SubscriptionsRecorder, delta int64) {
	if recorder == nil {
		return
	}
	recorder.Live(ctx, delta, eraLabel(protocolEraModern))
}

// stampSubscriptionSpan records the bounded open-time outcome on the listen span.
// Only the open path stamps: a lease outlives its request trace, so a close-time
// stamp would be written after the trace was serialized. Close outcomes are
// reported through the outcome counter instead.
func stampSubscriptionSpan(ctx context.Context, outcome subscriptionOutcome) {
	requestTrace := trace.FromContext(ctx)
	if requestTrace == nil {
		return
	}
	for _, span := range requestTrace.Spans() {
		attrs, ok := span.MCPAttrsCopy()
		if !ok || attrs.Method != appmcp.MethodSubscriptionsListen {
			continue
		}
		span.SetMCPSubscription("", string(outcome))
		return
	}
}

func runSubscriptionStream(ctx context.Context, sink frameSink, spec streamSpec) (outcome subscriptionOutcome) {
	outcome = subscriptionOutcomeShutdown
	defer func() {
		if recovered := recover(); recovered != nil {
			outcome = subscriptionOutcomeFailed
		}
		if err := writeSubscriptionFrame(sink, spec.terminal); err != nil &&
			outcome != subscriptionOutcomeFailed {
			outcome = frameFailureOutcome(err)
		}
	}()
	defer spec.timers.Stop()
	if spec.source != nil {
		defer spec.source.Close()
	}

	if err := writeSubscriptionFrame(sink, spec.ack); err != nil {
		return frameFailureOutcome(err)
	}
	if spec.honoured.Empty() {
		return subscriptionOutcomeAcked
	}

	state := reauthState{}
	var (
		pass       <-chan reauthResult
		cancelPass context.CancelFunc
		emit       <-chan emitAuthorizationResult
		cancelEmit context.CancelFunc
		emitDone   <-chan struct{}
	)
	defer func() {
		if cancelPass != nil {
			cancelPass()
		}
		if cancelEmit != nil {
			cancelEmit()
			<-emitDone
		}
	}()
	var sourceEvents <-chan appmcp.SubscriptionEvent
	var sourceDone <-chan struct{}
	if spec.source != nil {
		sourceEvents = spec.source.Events()
		sourceDone = spec.source.Done()
	}
	for {
		reauth := spec.timers.Reauth
		if pass != nil {
			reauth = nil
		}
		nextSourceEvent := sourceEvents
		if emit != nil {
			nextSourceEvent = nil
		}
		select {
		case <-ctx.Done():
			return subscriptionOutcomeShutdown
		case <-spec.timers.Deadline:
			return subscriptionOutcomeDeadline
		case <-reauth:
			if spec.timers.Remaining() < spec.budget {
				continue
			}
			pass, cancelPass = startReauthPass(ctx, spec, state.snapshot)
		case result := <-pass:
			cancelPass()
			pass = nil
			cancelPass = nil
			if outcome, ended := applyReauthResult(ctx, sink, spec, &state, result); ended {
				return outcome
			}
		case event, ok := <-nextSourceEvent:
			if !ok {
				return subscriptionSourceOutcome(spec.source.Err())
			}
			emit, cancelEmit, emitDone = startEmitAuthorization(ctx, spec.source, event)
		case result := <-emit:
			cancelEmit()
			<-emitDone
			emit = nil
			cancelEmit = nil
			emitDone = nil
			if result.err != nil {
				if errors.Is(result.err, appmcp.ErrSubscriptionRevoked) ||
					errors.Is(result.err, appmcp.ErrSubscriptionSourceChanged) ||
					errors.Is(result.err, appmcp.ErrSubscriptionAuthentication) ||
					errors.Is(result.err, appmcp.ErrSubscriptionTerminal) {
					return subscriptionSourceOutcome(result.err)
				}
				continue
			}
			frame, ok := spec.notifications[result.event.Kind]
			if !ok {
				continue
			}
			if err := writeSubscriptionFrame(sink, frame); err != nil {
				return frameFailureOutcome(err)
			}
			recordSubscriptionOutcome(ctx, spec.recorder, result.event.Kind, subscriptionOutcomeEmitted)
		case <-sourceDone:
			return subscriptionSourceOutcome(spec.source.Err())
		case <-spec.timers.Keepalive:
			if err := sink.Comment(sseKeepalive); err != nil {
				return frameFailureOutcome(err)
			}
			if err := sink.Flush(); err != nil {
				return frameFailureOutcome(err)
			}
		}
	}
}

type emitAuthorizationResult struct {
	event appmcp.SubscriptionEvent
	err   error
}

func startEmitAuthorization(
	parent context.Context,
	source appmcp.SubscriptionHandle,
	event appmcp.SubscriptionEvent,
) (<-chan emitAuthorizationResult, context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(parent)
	result := make(chan emitAuthorizationResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := source.Authorize(ctx, event)
		select {
		case result <- emitAuthorizationResult{event: event, err: err}:
		case <-ctx.Done():
		}
	}()
	return result, cancel, done
}

// reauthState is the loop's memory between passes: the digest set the next pass
// compares against, and how many passes in a row were inconclusive.
type reauthState struct {
	snapshot appmcp.SurfaceSnapshot
	failures int
}

type reauthResult struct {
	evaluation appmcp.Evaluation
	err        error
}

func startReauthPass(
	ctx context.Context,
	spec streamSpec,
	previous appmcp.SurfaceSnapshot,
) (<-chan reauthResult, context.CancelFunc) {
	passCtx, cancel := context.WithTimeout(ctx, spec.budget)
	done := make(chan reauthResult, 1)
	go func() {
		evaluation, err := spec.policy.Evaluate(passCtx, spec.identity, previous)
		done <- reauthResult{evaluation: evaluation, err: err}
	}()
	return done, cancel
}

func applyReauthResult(
	ctx context.Context,
	sink frameSink,
	spec streamSpec,
	state *reauthState,
	result reauthResult,
) (subscriptionOutcome, bool) {
	if errors.Is(result.err, appmcp.ErrSubscriptionRevoked) {
		return subscriptionOutcomeRevoked, true
	}
	if result.err != nil || result.evaluation.Snapshot.Degraded {
		state.failures++
		if state.failures >= maxInconclusivePasses {
			return subscriptionOutcomeDegraded, true
		}
		return "", false
	}

	state.failures = 0
	state.snapshot = result.evaluation.Snapshot
	if spec.watchdogOnly {
		return "", false
	}
	for _, kind := range result.evaluation.Changed {
		frame, ok := spec.notifications[kind]
		if !ok {
			continue
		}
		if err := writeSubscriptionFrame(sink, frame); err != nil {
			return frameFailureOutcome(err), true
		}
		recordSubscriptionOutcome(ctx, spec.recorder, kind, subscriptionOutcomeEmitted)
	}
	return "", false
}

func subscriptionSourceOutcome(err error) subscriptionOutcome {
	if errors.Is(err, appmcp.ErrSubscriptionRevoked) ||
		errors.Is(err, appmcp.ErrSubscriptionSourceChanged) ||
		errors.Is(err, appmcp.ErrSubscriptionAuthentication) {
		return subscriptionOutcomeRevoked
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, appmcp.ErrSubscriptionTerminal) {
		return subscriptionOutcomeShutdown
	}
	return subscriptionOutcomeDegraded
}

func writeSubscriptionFrame(sink frameSink, payload []byte) error {
	if err := sink.Frame(payload); err != nil {
		return err
	}
	return sink.Flush()
}

func frameFailureOutcome(err error) subscriptionOutcome {
	if errors.Is(err, ErrFrameTooLarge) {
		return subscriptionOutcomeOversize
	}
	return subscriptionOutcomeDisconnected
}

func (h *Handler) isolationKey(c *fiber.Ctx, rc *appconsumer.RoutableConsumer) appmcp.IsolationKey {
	gatewayID := ""
	if id, ok := appconsumer.GatewayIDFromContext(c.UserContext()); ok {
		gatewayID = id.String()
	}
	return appmcp.NewIsolationKey(c.UserContext(), gatewayID, rc)
}

// leaseIdentity captures what a re-authorization pass will need, before Fiber
// recycles the request context it was read from.
func (h *Handler) leaseIdentity(
	c *fiber.Ctx,
	rc *appconsumer.RoutableConsumer,
	honoured appmcp.HonouredSet,
) appmcp.LeaseIdentity {
	identity := appmcp.LeaseIdentity{
		Key:      h.isolationKey(c, rc),
		Path:     c.Path(),
		Honoured: honoured,
	}
	if gatewayID, ok := appconsumer.GatewayIDFromContext(c.UserContext()); ok {
		identity.GatewayID = gatewayID
	}
	if authID, ok := appconsumer.AuthIDFromContext(c.UserContext()); ok {
		identity.AuthID = authID
	}
	return identity
}

func (h *Handler) newStreamSpec(
	c *fiber.Ctx,
	req rpcRequest,
	rc *appconsumer.RoutableConsumer,
	identity appmcp.LeaseIdentity,
	source appmcp.SubscriptionHandle,
) (streamSpec, error) {
	honoured := identity.Honoured
	ack, err := json.Marshal(subscriptionAckNotification(req.ID, honoured))
	if err != nil {
		return streamSpec{}, err
	}
	notifications, err := subscriptionNotificationFrames(req.ID, honoured)
	if err != nil {
		return streamSpec{}, err
	}
	normalized, err := normalizeModernResult(
		appmcp.MethodSubscriptionsListen,
		subscriptionsListenResult(req.ID, honoured),
		rc,
		appmcp.ClientCapabilitiesFromContext(c.UserContext()),
	)
	if err != nil {
		return streamSpec{}, err
	}
	terminal, err := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: normalizeID(req.ID), Result: normalized})
	if err != nil {
		return streamSpec{}, err
	}
	return streamSpec{
		honoured:      honoured,
		identity:      identity,
		policy:        h.subs.Policy,
		recorder:      h.subs.Recorder,
		ack:           ack,
		terminal:      terminal,
		notifications: notifications,
		timers: newSubscriptionTimers(
			h.subs.MaxLifetime,
			h.subs.ReauthInterval,
			h.subs.Keepalive,
			subscriptionJitter,
		),
		budget:       appmcp.ReauthBudget(h.subs.ReauthInterval, h.subs.Keepalive),
		source:       source,
		watchdogOnly: h.subs.UpstreamEnabled(),
	}, nil
}

// subscriptionNotification is a JSON-RPC notification frame. It is never
// normalized as a result, so it carries no resultType, ttlMs or cacheScope.
type subscriptionNotification struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

func subscriptionAckNotification(id json.RawMessage, honoured appmcp.HonouredSet) subscriptionNotification {
	params := map[string]any{"notifications": honoured.Kinds()}
	if meta := subscriptionFrameMeta(id); meta != nil {
		params["_meta"] = meta
	}
	return subscriptionNotification{
		JSONRPC: "2.0",
		Method:  methodSubscriptionsAcknowledged,
		Params:  params,
	}
}

// subscriptionNotificationFrames renders the one frame each honoured kind can
// ever emit. Rendering at open keeps the writer allocation-free per tick and is
// what makes a kind absent from the honoured subset unemittable by construction.
func subscriptionNotificationFrames(
	id json.RawMessage,
	honoured appmcp.HonouredSet,
) (map[appmcp.NotificationKind][]byte, error) {
	kinds := honoured.Kinds()
	frames := make(map[appmcp.NotificationKind][]byte, len(kinds))
	for _, kind := range kinds {
		params := map[string]any(nil)
		if meta := subscriptionFrameMeta(id); meta != nil {
			params = map[string]any{"_meta": meta}
		}
		frame, err := json.Marshal(subscriptionNotification{
			JSONRPC: "2.0",
			Method:  kind.Method(),
			Params:  params,
		})
		if err != nil {
			return nil, err
		}
		frames[kind] = frame
	}
	return frames, nil
}

func subscriptionFrameMeta(id json.RawMessage) map[string]any {
	if len(id) == 0 {
		return nil
	}
	return map[string]any{appmcp.MetaKeySubscriptionID: id}
}

func subscriptionsListenResult(id json.RawMessage, honoured appmcp.HonouredSet) SubscriptionsListenResult {
	result := SubscriptionsListenResult{Notifications: honoured.Kinds()}
	if len(id) > 0 {
		result.Meta = map[string]any{appmcp.MetaKeySubscriptionID: id}
	}
	return result
}

func setSubscriptionStreamHeaders(c *fiber.Ctx) {
	c.Status(fiber.StatusOK)
	c.Set(fiber.HeaderContentType, mediaTypeEventStream)
	c.Set(fiber.HeaderCacheControl, "no-cache, no-transform")
	c.Set(headerAccelBuffering, "no")
}

// claimStreamMetrics takes ownership of the metrics emission for this response
// synchronously, before the handler returns, so the middleware skips its own
// deferred emission and the stream is reported exactly once.
func claimStreamMetrics(c *fiber.Ctx) infracontext.StreamMetricsFinalizer {
	finalizer, ok := c.Locals(infracontext.StreamMetricsFinalizerKey).(infracontext.StreamMetricsFinalizer)
	if !ok || finalizer == nil {
		return nil
	}
	c.Locals(infracontext.StreamMetricsOwnedKey, true)
	return finalizer
}

// writeSubscriptionRefused answers a capacity refusal. One constant message, no
// data, and no indication of which cap was reached, so the caps cannot be probed
// for another tenant's stream count.
func writeSubscriptionRefused(c *fiber.Ctx, id json.RawMessage) error {
	refusal := appmcp.SubscriptionRefusedRPCError()
	middleware.SetOpsOutcome(c, o11y.OutcomeDeniedThrottled)
	return writeJSONStatus(c, httpStatusForRPCError(refusal), rpcResponse{
		JSONRPC: "2.0",
		ID:      normalizeID(id),
		Error:   &rpcError{Code: int(refusal.Code), Message: refusal.Message},
	})
}
