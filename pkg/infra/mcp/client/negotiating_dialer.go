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

package client

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"golang.org/x/sync/singleflight"
)

type legacyConnector interface {
	ConnectLegacy(ctx context.Context, target appmcp.Target) (appmcp.Upstream, error)
}

type modernUpstreamFactory func(appmcp.Target, string) (appmcp.Upstream, error)

type negotiatingDialer struct {
	legacy              legacyConnector
	coordinator         *eraCoordinator
	modern              modernUpstreamFactory
	logger              *slog.Logger
	now                 func() time.Time
	confirmationFlight  singleflight.Group
	confirmationRetry   singleflight.Group
	confirmationJoined  func()
	confirmationRetried func()
	reconcileConfirmed  func()
}

func NewNegotiatingDialer(client *Client, logger *slog.Logger) appmcp.Dialer {
	legacy := newCachedDialer(client, logger)
	return newNegotiatingDialer(
		legacy,
		newEraCoordinator(newProtocolProbe(sharedHTTPTransport), responseHeaderTimeout),
		func(target appmcp.Target, protocolVersion string) (appmcp.Upstream, error) {
			return newModernUpstream(target, protocolVersion)
		},
		logger,
	)
}

func newNegotiatingDialer(
	legacy legacyConnector,
	coordinator *eraCoordinator,
	modern modernUpstreamFactory,
	logger *slog.Logger,
) *negotiatingDialer {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &negotiatingDialer{
		legacy:      legacy,
		coordinator: coordinator,
		modern:      modern,
		logger:      logger,
		now:         time.Now,
	}
}

func (d *negotiatingDialer) Connect(ctx context.Context, target appmcp.Target) (appmcp.Upstream, error) {
	started := d.now()
	origin, err := canonicalOrigin(target.URL)
	if err != nil {
		wrapped := wrapUnreachable("", "invalid upstream origin", err)
		d.logDecision(ctx, "", target.ProtocolMode, eraUnknown, decisionOverride, "failed", "", started, wrapped)
		return nil, wrapped
	}
	mode := target.ProtocolMode
	if mode == "" {
		mode = registrydomain.MCPProtocolModeAuto
	}
	target.ProtocolMode = mode
	switch mode {
	case registrydomain.MCPProtocolModeLegacy:
		upstream, connectErr := d.legacy.ConnectLegacy(ctx, target)
		d.logSelection(ctx, origin, mode, eraLegacy, decisionOverride, "", started, connectErr)
		return upstream, connectErr
	case registrydomain.MCPProtocolModeModern:
		upstream, connectErr := d.modern(target, modernProtocolVersion)
		d.logSelection(ctx, origin, mode, eraModern, decisionOverride, modernProtocolVersion, started, connectErr)
		return upstream, connectErr
	case registrydomain.MCPProtocolModeAuto:
		return d.connectAuto(ctx, target, origin, started)
	default:
		err := errors.New("mcp upstream protocol mode is invalid")
		d.logDecision(ctx, origin, mode, eraUnknown, decisionOverride, "failed", "", started, err)
		return nil, err
	}
}

func (d *negotiatingDialer) connectAuto(
	ctx context.Context,
	target appmcp.Target,
	origin string,
	started time.Time,
) (appmcp.Upstream, error) {
	resolution, err := d.coordinator.resolve(ctx, target, origin)
	if err != nil {
		era := resolution.entry.era
		outcome := "failed"
		if errors.Is(err, appmcp.ErrProtocolIncompatible) {
			outcome = "incompatible"
		}
		d.logDecision(ctx, origin, registrydomain.MCPProtocolModeAuto, era, resolution.source, outcome, resolution.entry.version, started, err)
		return nil, err
	}
	if resolution.legacyCandidate {
		legacy, connectErr := d.legacy.ConnectLegacy(ctx, target)
		if connectErr != nil {
			d.logDecision(
				ctx,
				origin,
				registrydomain.MCPProtocolModeAuto,
				eraUnknown,
				resolution.source,
				"unclassified",
				"",
				started,
				connectErr,
			)
			return nil, connectErr
		}
		resolution.entry = d.coordinator.commitLegacy(origin)
		if resolution.entry.era == eraLegacy {
			upstream := newGuardedUpstream(d, target, origin, resolution.entry, legacy)
			d.logSelection(
				ctx,
				origin,
				registrydomain.MCPProtocolModeAuto,
				eraLegacy,
				resolution.source,
				"",
				started,
				nil,
			)
			return upstream, nil
		}
		legacy.Close(ctx)
	}
	upstream, connectErr := d.connectEntry(ctx, target, origin, resolution.entry)
	d.logSelection(
		ctx,
		origin,
		registrydomain.MCPProtocolModeAuto,
		resolution.entry.era,
		resolution.source,
		resolution.entry.version,
		started,
		connectErr,
	)
	return upstream, connectErr
}

func (d *negotiatingDialer) connectEntry(
	ctx context.Context,
	target appmcp.Target,
	origin string,
	entry eraEntry,
) (appmcp.Upstream, error) {
	upstream, err := d.connectRawEntry(ctx, target, entry)
	if err != nil {
		return nil, err
	}
	return newGuardedUpstream(d, target, origin, entry, upstream), nil
}

func (d *negotiatingDialer) connectRawEntry(
	ctx context.Context,
	target appmcp.Target,
	entry eraEntry,
) (appmcp.Upstream, error) {
	var upstream appmcp.Upstream
	var err error
	switch entry.era {
	case eraModern:
		upstream, err = d.modern(target, entry.version)
	case eraLegacy:
		upstream, err = d.legacy.ConnectLegacy(ctx, target)
	case eraModernIncompatible:
		return nil, appmcp.ErrProtocolIncompatible
	default:
		return nil, errors.New("mcp upstream protocol era is unresolved")
	}
	if err != nil {
		return nil, err
	}
	return upstream, nil
}

type upstreamOwner struct {
	upstream appmcp.Upstream
	close    func(context.Context)
}

func ownUpstream(upstream appmcp.Upstream) upstreamOwner {
	var once sync.Once
	return upstreamOwner{
		upstream: upstream,
		close: func(ctx context.Context) {
			once.Do(func() {
				upstream.Close(ctx)
			})
		},
	}
}

func (o upstreamOwner) Close(ctx context.Context) {
	if o.close != nil {
		o.close(ctx)
	}
}

type confirmationResult struct {
	entry      eraEntry
	corrected  bool
	conclusive bool
	credential string
	err        error
}

func (d *negotiatingDialer) confirmContradiction(
	ctx context.Context,
	target appmcp.Target,
	origin string,
	observed eraEntry,
) (upstreamOwner, eraEntry, bool, error) {
	key := origin + "\x00" + strconv.FormatUint(observed.generation, 10)
	target = cloneTarget(target)
	credential := credentialFingerprint(target.Headers)
	resultChannel := d.confirmationFlight.DoChan(key, func() (any, error) {
		return d.confirmContradictionWork(ctx, target, origin, observed), nil
	})
	if d.confirmationJoined != nil {
		d.confirmationJoined()
	}
	result, err := awaitConfirmation(ctx, resultChannel)
	if err != nil {
		return upstreamOwner{}, observed, false, err
	}
	if current, changed := d.correctedEntry(origin, observed); changed {
		return d.connectConfirmedEntry(ctx, target, current)
	}
	if !result.conclusive && result.credential != credential {
		retryKey := key + "\x00" + credential
		retryChannel := d.confirmationRetry.DoChan(retryKey, func() (any, error) {
			if current, changed := d.correctedEntry(origin, observed); changed {
				return confirmationResult{
					entry:      current,
					corrected:  true,
					conclusive: true,
					credential: credential,
					err:        incompatibleEntryError(current),
				}, nil
			}
			retry := d.confirmContradictionWork(ctx, target, origin, observed)
			if current, changed := d.correctedEntry(origin, observed); changed {
				return confirmationResult{
					entry:      current,
					corrected:  true,
					conclusive: true,
					credential: credential,
					err:        incompatibleEntryError(current),
				}, nil
			}
			return retry, nil
		})
		if d.confirmationRetried != nil {
			d.confirmationRetried()
		}
		result, err = awaitConfirmation(ctx, retryChannel)
		if err != nil {
			return upstreamOwner{}, observed, false, err
		}
	}
	if current, changed := d.correctedEntry(origin, observed); changed {
		return d.connectConfirmedEntry(ctx, target, current)
	}
	if result.err != nil {
		return upstreamOwner{}, result.entry, result.corrected, result.err
	}
	if !result.corrected {
		return upstreamOwner{}, result.entry, false, nil
	}
	return d.connectConfirmedEntry(ctx, target, result.entry)
}

func awaitConfirmation(
	ctx context.Context,
	resultChannel <-chan singleflight.Result,
) (confirmationResult, error) {
	select {
	case <-ctx.Done():
		return confirmationResult{}, ctx.Err()
	case shared := <-resultChannel:
		if shared.Err != nil {
			return confirmationResult{}, shared.Err
		}
		result, ok := shared.Val.(confirmationResult)
		if !ok {
			return confirmationResult{}, errors.New("mcp contradiction coordinator received an invalid result")
		}
		if ctx.Err() != nil {
			return confirmationResult{}, ctx.Err()
		}
		return result, nil
	}
}

func (d *negotiatingDialer) correctedEntry(origin string, observed eraEntry) (eraEntry, bool) {
	current, ok := d.coordinator.lookup(origin)
	return current, ok && current.generation != observed.generation
}

func (d *negotiatingDialer) connectConfirmedEntry(
	ctx context.Context,
	target appmcp.Target,
	entry eraEntry,
) (upstreamOwner, eraEntry, bool, error) {
	if err := incompatibleEntryError(entry); err != nil {
		return upstreamOwner{}, entry, true, err
	}
	upstream, err := d.connectRawEntry(ctx, target, entry)
	if err != nil {
		return upstreamOwner{}, entry, true, err
	}
	return ownUpstream(upstream), entry, true, nil
}

func incompatibleEntryError(entry eraEntry) error {
	if entry.era == eraModernIncompatible {
		return appmcp.ErrProtocolIncompatible
	}
	return nil
}

func (d *negotiatingDialer) confirmContradictionWork(
	ctx context.Context,
	target appmcp.Target,
	origin string,
	observed eraEntry,
) confirmationResult {
	workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.coordinator.timeout)
	defer cancel()
	current, ok := d.coordinator.lookup(origin)
	if !ok {
		return confirmationResult{
			entry: observed,
			err:   errors.New("mcp protocol era cache entry is missing"),
		}
	}
	if current.generation != observed.generation {
		return confirmationResult{
			entry:      current,
			corrected:  true,
			conclusive: true,
			credential: credentialFingerprint(target.Headers),
			err:        incompatibleEntryError(current),
		}
	}
	credential := credentialFingerprint(target.Headers)
	outcome, probeErr := d.coordinator.probe.Probe(workCtx, cloneTarget(target))
	result := probeWorkResult{outcome: outcome, err: probeErr, credential: credential}
	if result.err != nil {
		return confirmationResult{entry: observed, credential: credential, err: result.err}
	}
	var candidate eraEntry
	var prepared appmcp.Upstream
	switch observed.era {
	case eraModern:
		if result.err != nil || result.outcome.kind != probeLegacyCandidate {
			return confirmationResult{entry: observed, credential: credential, err: result.err}
		}
		var err error
		prepared, err = d.legacy.ConnectLegacy(workCtx, target)
		if err != nil {
			return confirmationResult{entry: observed, credential: credential, err: err}
		}
		defer prepared.Close(workCtx)
		candidate = eraEntry{era: eraLegacy}
	case eraLegacy:
		switch result.outcome.kind {
		case probeModern:
			candidate = eraEntry{era: eraModern, version: result.outcome.version}
		case probeModernIncompatible:
			candidate = eraEntry{era: eraModernIncompatible}
		default:
			return confirmationResult{entry: observed, credential: credential, err: result.err}
		}
	default:
		return confirmationResult{entry: observed, credential: credential}
	}
	current, won := d.coordinator.correct(origin, observed, candidate)
	if !won {
		if current.generation == observed.generation || current.generation == 0 {
			return confirmationResult{entry: observed, credential: credential}
		}
		return confirmationResult{
			entry:      current,
			corrected:  true,
			conclusive: true,
			credential: credential,
			err:        incompatibleEntryError(current),
		}
	}
	return confirmationResult{
		entry:      current,
		corrected:  true,
		conclusive: true,
		credential: credential,
		err:        incompatibleEntryError(current),
	}
}

func (d *negotiatingDialer) logSelection(
	ctx context.Context,
	origin string,
	mode registrydomain.MCPProtocolMode,
	era protocolEra,
	source decisionSource,
	version string,
	started time.Time,
	err error,
) {
	outcome := "selected"
	if err != nil {
		outcome = "failed"
	}
	d.logDecision(ctx, origin, mode, era, source, outcome, version, started, err)
}

func (d *negotiatingDialer) logDecision(
	ctx context.Context,
	origin string,
	mode registrydomain.MCPProtocolMode,
	era protocolEra,
	source decisionSource,
	outcome string,
	version string,
	started time.Time,
	err error,
) {
	attrs := []slog.Attr{
		slog.String("component", "mcp_upstream_protocol"),
		slog.String("origin", origin),
		slog.String("mode", string(mode)),
		slog.String("era", era.String()),
		slog.String("source", string(source)),
		slog.String("result", outcome),
		slog.String("version", version),
		slog.Int64("latency_ms", d.now().Sub(started).Milliseconds()),
	}
	if err != nil {
		attrs = append(attrs, slog.String("category", negotiationErrorCategory(err)))
	}
	d.logger.LogAttrs(ctx, slog.LevelInfo, "mcp upstream protocol selection", attrs...)
}

func negotiationErrorCategory(err error) string {
	switch {
	case errors.Is(err, errContradictionAlreadyReconciled):
		return "contradiction"
	case errors.Is(err, errContradictionInconclusive):
		return "unclassified"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, appmcp.ErrProtocolIncompatible):
		return "incompatible"
	case errors.Is(err, appmcp.ErrUnreachable):
		return "unreachable"
	case appmcp.IsRPCError(err):
		return "rpc"
	default:
		return "invalid"
	}
}

var (
	errContradictionAlreadyReconciled = errors.New("mcp protocol contradiction already reconciled")
	errContradictionInconclusive      = errors.New("mcp protocol contradiction confirmation was inconclusive")
)

type guardedUpstream struct {
	dialer      *negotiatingDialer
	target      appmcp.Target
	origin      string
	lifecycleMu sync.RWMutex
	reconcileMu sync.Mutex
	stateMu     sync.RWMutex
	entry       eraEntry
	owner       upstreamOwner
	state       uint64
	reconciled  bool
	closed      bool
}

func newGuardedUpstream(
	dialer *negotiatingDialer,
	target appmcp.Target,
	origin string,
	entry eraEntry,
	upstream appmcp.Upstream,
) *guardedUpstream {
	return &guardedUpstream{
		dialer: dialer,
		target: cloneTarget(target),
		origin: origin,
		entry:  entry,
		owner:  ownUpstream(upstream),
	}
}

func guardedRead[T any](
	ctx context.Context,
	upstream *guardedUpstream,
	call func(appmcp.Upstream) (T, error),
) (T, error) {
	upstream.lifecycleMu.RLock()
	defer upstream.lifecycleMu.RUnlock()
	result, entry, err := guardedCallCurrent(upstream, call)
	if err == nil || !oppositeEraCandidate(entry.era, err) {
		return result, err
	}
	corrected, reconcileErr := upstream.reconcile(ctx)
	if reconcileErr != nil {
		var zero T
		return zero, reconcileErr
	}
	if !corrected {
		return result, err
	}
	retried, _, retryErr := guardedCallCurrent(upstream, call)
	return retried, retryErr
}

func guardedCallCurrent[T any](
	g *guardedUpstream,
	call func(appmcp.Upstream) (T, error),
) (T, eraEntry, error) {
	g.stateMu.RLock()
	defer g.stateMu.RUnlock()
	if g.closed || g.owner.upstream == nil {
		var zero T
		return zero, g.entry, appmcp.ErrUnreachable
	}
	result, err := call(g.owner.upstream)
	return result, g.entry, err
}

type guardedSnapshot struct {
	entry eraEntry
	state uint64
}

func (g *guardedUpstream) snapshot() (guardedSnapshot, bool, bool) {
	g.stateMu.RLock()
	defer g.stateMu.RUnlock()
	if g.closed || g.owner.upstream == nil {
		return guardedSnapshot{}, false, false
	}
	snapshot := guardedSnapshot{entry: g.entry, state: g.state}
	if g.reconciled {
		return snapshot, false, true
	}
	return snapshot, true, false
}

func (g *guardedUpstream) reconcile(ctx context.Context) (bool, error) {
	g.reconcileMu.Lock()
	defer g.reconcileMu.Unlock()
	started := g.dialer.now()
	snapshot, ok, repeated := g.snapshot()
	if !ok {
		if repeated {
			g.dialer.logDecision(
				ctx,
				g.origin,
				registrydomain.MCPProtocolModeAuto,
				snapshot.entry.era,
				decisionContradiction,
				"failed",
				snapshot.entry.version,
				started,
				errContradictionAlreadyReconciled,
			)
		}
		return false, nil
	}
	replacement, entry, corrected, err := g.dialer.confirmContradiction(
		ctx,
		g.target,
		g.origin,
		snapshot.entry,
	)
	if g.dialer.reconcileConfirmed != nil {
		g.dialer.reconcileConfirmed()
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		if current, changed := g.dialer.correctedEntry(g.origin, snapshot.entry); changed {
			replacement.Close(ctx)
			replacement, entry, corrected, err = g.dialer.connectConfirmedEntry(ctx, g.target, current)
		}
	}
	result := "selected"
	logErr := err
	switch {
	case errors.Is(err, appmcp.ErrProtocolIncompatible):
		result = "incompatible"
	case err != nil:
		result = "failed"
	case !corrected:
		result = "unclassified"
		logErr = errContradictionInconclusive
	}
	logEntry := entry
	if logEntry.era == eraUnknown {
		logEntry = snapshot.entry
	}
	g.dialer.logDecision(
		ctx,
		g.origin,
		registrydomain.MCPProtocolModeAuto,
		logEntry.era,
		decisionContradiction,
		result,
		logEntry.version,
		started,
		logErr,
	)
	g.stateMu.Lock()
	if g.closed {
		g.stateMu.Unlock()
		replacement.Close(ctx)
		return false, appmcp.ErrUnreachable
	}
	if g.state != snapshot.state || g.entry.generation != snapshot.entry.generation {
		adopted := g.owner.upstream != nil && g.entry.generation != snapshot.entry.generation
		g.stateMu.Unlock()
		replacement.Close(ctx)
		if adopted {
			return true, nil
		}
		return false, err
	}
	if g.reconciled {
		g.stateMu.Unlock()
		replacement.Close(ctx)
		return false, err
	}
	if !corrected {
		g.stateMu.Unlock()
		replacement.Close(ctx)
		return false, err
	}
	if errors.Is(err, appmcp.ErrProtocolIncompatible) {
		g.reconciled = true
		g.stateMu.Unlock()
		replacement.Close(ctx)
		return false, err
	}
	if err != nil {
		g.stateMu.Unlock()
		replacement.Close(ctx)
		return false, err
	}
	old := g.owner
	g.owner = replacement
	g.entry = entry
	g.state++
	g.reconciled = true
	g.stateMu.Unlock()
	old.Close(ctx)
	return true, nil
}

func (g *guardedUpstream) ListTools(ctx context.Context) ([]appmcp.Tool, error) {
	return guardedRead(ctx, g, func(upstream appmcp.Upstream) ([]appmcp.Tool, error) {
		return upstream.ListTools(ctx)
	})
}

func (g *guardedUpstream) CallTool(
	ctx context.Context,
	name string,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	g.lifecycleMu.RLock()
	defer g.lifecycleMu.RUnlock()
	result, entry, err := guardedCallCurrent(g, func(upstream appmcp.Upstream) (json.RawMessage, error) {
		return upstream.CallTool(ctx, name, arguments)
	})
	if err != nil && oppositeEraCandidate(entry.era, err) {
		_, reconcileErr := g.reconcile(ctx)
		if reconcileErr != nil && (errors.Is(reconcileErr, context.Canceled) || errors.Is(reconcileErr, context.DeadlineExceeded)) {
			return nil, reconcileErr
		}
	}
	return result, err
}

func (g *guardedUpstream) ListResources(ctx context.Context) ([]appmcp.Resource, error) {
	return guardedRead(ctx, g, func(upstream appmcp.Upstream) ([]appmcp.Resource, error) {
		return upstream.ListResources(ctx)
	})
}

func (g *guardedUpstream) ListResourceTemplates(ctx context.Context) ([]appmcp.ResourceTemplate, error) {
	return guardedRead(ctx, g, func(upstream appmcp.Upstream) ([]appmcp.ResourceTemplate, error) {
		return upstream.ListResourceTemplates(ctx)
	})
}

func (g *guardedUpstream) ReadResource(ctx context.Context, uri string) (json.RawMessage, error) {
	return guardedRead(ctx, g, func(upstream appmcp.Upstream) (json.RawMessage, error) {
		return upstream.ReadResource(ctx, uri)
	})
}

func (g *guardedUpstream) ListPrompts(ctx context.Context) ([]appmcp.Prompt, error) {
	return guardedRead(ctx, g, func(upstream appmcp.Upstream) ([]appmcp.Prompt, error) {
		return upstream.ListPrompts(ctx)
	})
}

func (g *guardedUpstream) GetPrompt(
	ctx context.Context,
	name string,
	arguments map[string]string,
) (json.RawMessage, error) {
	return guardedRead(ctx, g, func(upstream appmcp.Upstream) (json.RawMessage, error) {
		return upstream.GetPrompt(ctx, name, arguments)
	})
}

func (g *guardedUpstream) SupportsResources() bool {
	g.lifecycleMu.RLock()
	defer g.lifecycleMu.RUnlock()
	g.stateMu.RLock()
	defer g.stateMu.RUnlock()
	return !g.closed && g.owner.upstream != nil && g.owner.upstream.SupportsResources()
}

func (g *guardedUpstream) SupportsPrompts() bool {
	g.lifecycleMu.RLock()
	defer g.lifecycleMu.RUnlock()
	g.stateMu.RLock()
	defer g.stateMu.RUnlock()
	return !g.closed && g.owner.upstream != nil && g.owner.upstream.SupportsPrompts()
}

func (g *guardedUpstream) Close(ctx context.Context) {
	g.lifecycleMu.Lock()
	defer g.lifecycleMu.Unlock()
	g.reconcileMu.Lock()
	defer g.reconcileMu.Unlock()
	g.stateMu.Lock()
	if g.closed {
		g.stateMu.Unlock()
		return
	}
	g.closed = true
	current := g.owner
	g.owner = upstreamOwner{}
	g.state++
	g.stateMu.Unlock()
	current.Close(ctx)
}
