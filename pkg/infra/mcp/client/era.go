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
	"errors"
	"sync"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"golang.org/x/sync/singleflight"
)

type protocolEra uint8

const (
	eraUnknown protocolEra = iota
	eraModern
	eraLegacy
	eraModernIncompatible
)

type decisionSource string

const (
	decisionOverride      decisionSource = "override"
	decisionCache         decisionSource = "cache"
	decisionProbe         decisionSource = "probe"
	decisionContradiction decisionSource = "contradiction"
)

type eraEntry struct {
	era         protocolEra
	version     string
	listChanged appmcp.ListChangedCapabilities
	generation  uint64
	corrected   bool
}

type eraResolution struct {
	entry           eraEntry
	source          decisionSource
	legacyCandidate bool
}

type protocolProbe interface {
	Probe(ctx context.Context, target appmcp.Target) (probeOutcome, error)
}

type legacyConfirmer func(ctx context.Context, target appmcp.Target) error

type eraCoordinator struct {
	mu            sync.RWMutex
	entries       map[string]eraEntry
	generation    uint64
	flight        singleflight.Group
	retryFlight   singleflight.Group
	probe         protocolProbe
	confirmLegacy legacyConfirmer
	timeout       time.Duration
	originJoined  func()
	retryJoined   func()
}

type probeWorkResult struct {
	outcome    probeOutcome
	err        error
	credential string
	entry      eraEntry
	cached     bool
	published  bool
}

func newEraCoordinator(probe protocolProbe, timeout time.Duration) *eraCoordinator {
	return &eraCoordinator{
		entries: make(map[string]eraEntry),
		probe:   probe,
		timeout: timeout,
	}
}

func (c *eraCoordinator) resolve(
	ctx context.Context,
	target appmcp.Target,
	origin string,
) (eraResolution, error) {
	if entry, ok := c.lookup(origin); ok {
		return resolutionForEntry(entry, decisionCache)
	}
	target = cloneTarget(target)
	credential := credentialFingerprint(target.Headers)
	resultChannel := c.flight.DoChan(origin, func() (any, error) {
		if entry, ok := c.lookup(origin); ok {
			return probeWorkResult{entry: entry, cached: true}, nil
		}
		result := c.runProbe(ctx, target, credential)
		return c.publishClassifiable(ctx, target, origin, result), nil
	})
	if c.originJoined != nil {
		c.originJoined()
	}
	var result probeWorkResult
	select {
	case <-ctx.Done():
		return eraResolution{source: decisionProbe}, ctx.Err()
	case shared := <-resultChannel:
		if shared.Err != nil {
			return eraResolution{source: decisionProbe}, shared.Err
		}
		var ok bool
		result, ok = shared.Val.(probeWorkResult)
		if !ok {
			return eraResolution{source: decisionProbe}, errors.New("mcp era coordinator received an invalid probe result")
		}
	}
	if ctx.Err() != nil {
		return eraResolution{source: decisionProbe}, ctx.Err()
	}
	if result.cached {
		return resolutionForEntry(result.entry, decisionCache)
	}
	if result.published {
		return resolutionForEntry(result.entry, decisionProbe)
	}
	if probeResultRequiresCredentialRetry(result) && result.credential != credential {
		var err error
		result, err = c.retryProbe(ctx, target, origin, credential)
		if err != nil {
			return eraResolution{source: decisionProbe}, err
		}
		if result.cached {
			return resolutionForEntry(result.entry, decisionCache)
		}
		if result.published {
			return resolutionForEntry(result.entry, decisionProbe)
		}
	}
	if entry, ok := c.lookup(origin); ok {
		return resolutionForEntry(entry, decisionCache)
	}
	return c.publishProbeResult(origin, result, decisionProbe)
}

func (c *eraCoordinator) retryProbe(
	ctx context.Context,
	target appmcp.Target,
	origin string,
	credential string,
) (probeWorkResult, error) {
	key := origin + "\x00" + credential
	resultChannel := c.retryFlight.DoChan(key, func() (any, error) {
		if entry, ok := c.lookup(origin); ok {
			return probeWorkResult{entry: entry, cached: true}, nil
		}
		result := c.runProbe(ctx, target, credential)
		if entry, ok := c.lookup(origin); ok {
			return probeWorkResult{entry: entry, cached: true}, nil
		}
		return c.publishClassifiable(ctx, target, origin, result), nil
	})
	if c.retryJoined != nil {
		c.retryJoined()
	}
	select {
	case <-ctx.Done():
		return probeWorkResult{}, ctx.Err()
	case shared := <-resultChannel:
		if shared.Err != nil {
			return probeWorkResult{}, shared.Err
		}
		result, ok := shared.Val.(probeWorkResult)
		if !ok {
			return probeWorkResult{}, errors.New("mcp era coordinator received an invalid credential probe result")
		}
		if ctx.Err() != nil {
			return probeWorkResult{}, ctx.Err()
		}
		return result, nil
	}
}

func (c *eraCoordinator) runProbe(
	ctx context.Context,
	target appmcp.Target,
	credential string,
) probeWorkResult {
	workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	outcome, err := c.probe.Probe(workCtx, target)
	return probeWorkResult{
		outcome:    outcome,
		err:        err,
		credential: credential,
	}
}

func (c *eraCoordinator) publishClassifiable(
	ctx context.Context,
	target appmcp.Target,
	origin string,
	result probeWorkResult,
) probeWorkResult {
	switch result.outcome.kind {
	case probeModern:
		result.entry = c.storeInitial(origin, eraEntry{
			era:         eraModern,
			version:     result.outcome.version,
			listChanged: result.outcome.capabilities,
		})
		result.published = true
	case probeModernIncompatible:
		result.entry = c.storeInitial(origin, eraEntry{era: eraModernIncompatible})
		result.published = true
	case probeLegacyCandidate:
		if result.err == nil {
			result = c.confirmLegacyCandidate(ctx, target, origin, result)
		}
	}
	return result
}

// confirmLegacyCandidate settles a legacy candidate inside the probe flight so a
// cold-start stampede on one origin costs a single strict probe. The era is still
// only cached once a legacy handshake succeeds, so a rejected strict probe alone
// never pins an origin to legacy.
func (c *eraCoordinator) confirmLegacyCandidate(
	ctx context.Context,
	target appmcp.Target,
	origin string,
	result probeWorkResult,
) probeWorkResult {
	if c.confirmLegacy == nil {
		return result
	}
	workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	if err := c.confirmLegacy(workCtx, target); err != nil {
		result.err = err
		return result
	}
	result.entry = c.storeInitial(origin, eraEntry{era: eraLegacy})
	result.published = true
	return result
}

func (c *eraCoordinator) publishProbeResult(
	origin string,
	result probeWorkResult,
	source decisionSource,
) (eraResolution, error) {
	switch result.outcome.kind {
	case probeModern:
		entry := c.storeInitial(origin, eraEntry{
			era:         eraModern,
			version:     result.outcome.version,
			listChanged: result.outcome.capabilities,
		})
		return eraResolution{entry: entry, source: source}, nil
	case probeModernIncompatible:
		entry := c.storeInitial(origin, eraEntry{era: eraModernIncompatible})
		return eraResolution{entry: entry, source: source}, appmcp.ErrProtocolIncompatible
	case probeLegacyCandidate:
		if result.err != nil {
			return eraResolution{source: source}, result.err
		}
		return eraResolution{source: source, legacyCandidate: true}, nil
	default:
		if result.err != nil {
			return eraResolution{source: source}, result.err
		}
		return eraResolution{source: source}, errors.New("mcp era probe returned no classification")
	}
}

func (c *eraCoordinator) commitLegacy(origin string) eraEntry {
	return c.storeInitial(origin, eraEntry{era: eraLegacy})
}

func (c *eraCoordinator) storeInitial(origin string, candidate eraEntry) eraEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if current, ok := c.entries[origin]; ok {
		return current
	}
	c.generation++
	candidate.generation = c.generation
	c.entries[origin] = candidate
	return candidate
}

func (c *eraCoordinator) correct(origin string, observed, candidate eraEntry) (eraEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, ok := c.entries[origin]
	if !ok || current.generation != observed.generation || current.corrected {
		return current, false
	}
	c.generation++
	candidate.generation = c.generation
	candidate.corrected = true
	c.entries[origin] = candidate
	return candidate, true
}

func (c *eraCoordinator) lookup(origin string) (eraEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[origin]
	return entry, ok
}

func (c *eraCoordinator) lookupSubscription(
	origin string,
	listChanged appmcp.ListChangedCapabilities,
) (eraEntry, bool) {
	entry, ok := c.lookup(origin)
	if !ok || entry.era != eraModern || entry.version != modernProtocolVersion {
		return eraEntry{}, false
	}
	if !entry.listChanged.Equal(listChanged) {
		return eraEntry{}, false
	}
	return entry, true
}

func resolutionForEntry(entry eraEntry, source decisionSource) (eraResolution, error) {
	resolution := eraResolution{entry: entry, source: source}
	if entry.era == eraModernIncompatible {
		return resolution, appmcp.ErrProtocolIncompatible
	}
	return resolution, nil
}

func probeResultRequiresCredentialRetry(result probeWorkResult) bool {
	switch result.outcome.kind {
	case probeModern, probeModernIncompatible:
		return false
	case probeLegacyCandidate:
		return true
	default:
		return true
	}
}

func cloneTarget(target appmcp.Target) appmcp.Target {
	cloned := target
	cloned.Headers = make(map[string]string, len(target.Headers))
	for key, value := range target.Headers {
		cloned.Headers[key] = value
	}
	return cloned
}

type eraCandidateError struct {
	era protocolEra
}

func newEraCandidateError(era protocolEra) error {
	return &eraCandidateError{era: era}
}

func (e *eraCandidateError) Error() string {
	return "mcp upstream response indicates a possible opposite protocol era"
}

func (e *eraCandidateError) Unwrap() error {
	return appmcp.ErrUnreachable
}

func oppositeEraCandidate(current protocolEra, err error) bool {
	var candidate *eraCandidateError
	if errors.As(err, &candidate) {
		return candidate.era != eraUnknown && candidate.era != current
	}
	if current != eraLegacy {
		return false
	}
	var rpcErr *appmcp.RPCError
	return errors.As(err, &rpcErr) && isModernProofRPCCode(rpcErr.Code)
}

func (e protocolEra) String() string {
	switch e {
	case eraModern:
		return "modern"
	case eraLegacy:
		return "legacy"
	case eraModernIncompatible:
		return "modern_incompatible"
	default:
		return "unknown"
	}
}
