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
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

type probeFunc func(context.Context, appmcp.Target) (probeOutcome, error)

func (f probeFunc) Probe(ctx context.Context, target appmcp.Target) (probeOutcome, error) {
	return f(ctx, target)
}

func TestEraCoordinatorSubscriptionLookupRequiresExactTrio(t *testing.T) {
	t.Parallel()
	coordinator := newEraCoordinator(nil, 0)
	capabilities := appmcp.ListChangedCapabilities{Tools: true, Resources: true}
	coordinator.entries["https://upstream.example:443"] = eraEntry{
		era:         eraModern,
		version:     modernProtocolVersion,
		listChanged: capabilities,
	}
	if _, ok := coordinator.lookupSubscription("https://upstream.example:443", capabilities); !ok {
		t.Fatal("exact capability trio was not reusable")
	}
	if _, ok := coordinator.lookupSubscription(
		"https://upstream.example:443",
		appmcp.ListChangedCapabilities{Tools: true},
	); ok {
		t.Fatal("different capability trio reused cached discovery")
	}
	coordinator.entries["https://old.example:443"] = eraEntry{
		era:         eraModern,
		version:     "2025-11-25",
		listChanged: capabilities,
	}
	if _, ok := coordinator.lookupSubscription("https://old.example:443", capabilities); ok {
		t.Fatal("different protocol reused cached discovery")
	}
	coordinator.entries["https://legacy.example:443"] = eraEntry{era: eraLegacy}
	if _, ok := coordinator.lookupSubscription(
		"https://legacy.example:443",
		appmcp.ListChangedCapabilities{},
	); ok {
		t.Fatal("legacy discovery reused for a modern subscription")
	}
}

func TestEraCoordinatorSingleflightAndProcessCache(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
	}), time.Second)
	target := appmcp.Target{URL: "https://example.com/mcp"}
	origin := "https://example.com:443"

	const callers = 32
	results := make(chan eraResolution, callers)
	errs := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	begin := make(chan struct{})
	for range callers {
		go func() {
			ready.Done()
			<-begin
			resolution, err := coordinator.resolve(context.Background(), target, origin)
			results <- resolution
			errs <- err
		}()
	}
	ready.Wait()
	close(begin)
	<-started
	close(release)

	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got := (<-results).entry; got.era != eraModern || got.version != modernProtocolVersion {
			t.Fatalf("entry = %+v", got)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}

	resolution, err := coordinator.resolve(context.Background(), target, origin)
	if err != nil {
		t.Fatalf("cache resolve: %v", err)
	}
	if resolution.source != decisionCache {
		t.Fatalf("source = %q, want cache", resolution.source)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls after cache hit = %d, want 1", got)
	}
}

func TestEraCoordinatorWaiterCancellationDoesNotCancelLeader(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(ctx context.Context, _ appmcp.Target) (probeOutcome, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		case <-ctx.Done():
			return probeOutcome{}, ctx.Err()
		}
	}), time.Second)
	target := appmcp.Target{URL: "https://example.com/mcp"}
	leaderDone := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(context.Background(), target, "https://example.com:443")
		leaderDone <- err
	}()
	<-started

	waiterCtx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(waiterCtx, target, "https://example.com:443")
		waiterDone <- err
	}()
	cancel()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter error = %v, want canceled", err)
	}
	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader error: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
}

func TestEraCoordinatorRetriesInconclusiveSharedProbeForDifferentCredentials(t *testing.T) {
	t.Parallel()

	badStarted := make(chan struct{})
	releaseBad := make(chan struct{})
	goodStarted := make(chan struct{})
	releaseGood := make(chan struct{})
	var calls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(_ context.Context, target appmcp.Target) (probeOutcome, error) {
		calls.Add(1)
		switch target.Headers["Authorization"] {
		case "Bearer bad":
			close(badStarted)
			<-releaseBad
			return probeOutcome{}, appmcp.ErrUnreachable
		case "Bearer good":
			close(goodStarted)
			<-releaseGood
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		default:
			return probeOutcome{}, errors.New("unexpected credential")
		}
	}), time.Second)
	origin := "https://example.com:443"
	bad := appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": "Bearer bad"},
	}
	good := appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": "Bearer good"},
	}

	badDone := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(context.Background(), bad, origin)
		badDone <- err
	}()
	<-badStarted
	goodDone := make(chan struct {
		resolution eraResolution
		err        error
	}, 1)
	go func() {
		resolution, err := coordinator.resolve(context.Background(), good, origin)
		goodDone <- struct {
			resolution eraResolution
			err        error
		}{resolution: resolution, err: err}
	}()
	close(releaseBad)
	<-goodStarted

	if err := <-badDone; !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("bad credential error = %v", err)
	}
	close(releaseGood)
	goodResult := <-goodDone
	if goodResult.err != nil {
		t.Fatalf("good credential resolve: %v", goodResult.err)
	}
	if got := goodResult.resolution.entry.era; got != eraModern {
		t.Fatalf("good credential era = %v, want modern", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("probe calls = %d, want shared attempt plus credential retry", got)
	}
}

func TestEraCoordinatorSharesLegacyCandidateForSameCredential(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		calls.Add(1)
		close(started)
		<-release
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	joined := make(chan struct{}, 2)
	coordinator.originJoined = func() { joined <- struct{}{} }
	target := appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": "Bearer shared"},
	}
	origin := "https://example.com:443"
	results := make(chan struct {
		resolution eraResolution
		err        error
	}, 2)
	for range 2 {
		go func() {
			resolution, err := coordinator.resolve(context.Background(), target, origin)
			results <- struct {
				resolution eraResolution
				err        error
			}{resolution: resolution, err: err}
		}()
	}
	<-started
	for range 2 {
		<-joined
	}
	close(release)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("resolve: %v", result.err)
		}
		if !result.resolution.legacyCandidate {
			t.Fatalf("resolution = %+v, want legacy candidate", result.resolution)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
}

func TestEraCoordinatorSettlesLegacyInsideProbeFlight(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	var confirms atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	coordinator.confirmLegacy = func(context.Context, appmcp.Target) error {
		confirms.Add(1)
		return nil
	}
	target := appmcp.Target{URL: "https://example.com/mcp"}
	origin := "https://example.com:443"
	for range 3 {
		resolution, err := coordinator.resolve(context.Background(), target, origin)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if resolution.legacyCandidate {
			t.Fatalf("resolution = %+v, want a settled legacy entry", resolution)
		}
		if resolution.entry.era != eraLegacy {
			t.Fatalf("era = %v, want legacy", resolution.entry.era)
		}
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
	if got := confirms.Load(); got != 1 {
		t.Fatalf("legacy confirmations = %d, want 1", got)
	}
}

func TestEraCoordinatorSharesLegacyConfirmationFailure(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var probes atomic.Int64
	var confirms atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		close(started)
		<-release
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	coordinator.confirmLegacy = func(context.Context, appmcp.Target) error {
		confirms.Add(1)
		return appmcp.ErrUnreachable
	}
	joined := make(chan struct{}, 2)
	coordinator.originJoined = func() { joined <- struct{}{} }
	target := appmcp.Target{URL: "https://example.com/mcp"}
	origin := "https://example.com:443"
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := coordinator.resolve(context.Background(), target, origin)
			errs <- err
		}()
	}
	<-started
	for range 2 {
		<-joined
	}
	close(release)
	for range 2 {
		if err := <-errs; !errors.Is(err, appmcp.ErrUnreachable) {
			t.Fatalf("resolve error = %v, want unreachable", err)
		}
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
	if got := confirms.Load(); got != 1 {
		t.Fatalf("legacy confirmations = %d, want 1", got)
	}
	if entry, ok := coordinator.lookup(origin); ok {
		t.Fatalf("cached entry = %+v, want no era cached after a failed handshake", entry)
	}
}

func TestEraCoordinatorRetriesSharedLegacyCandidateForDifferentCredential(t *testing.T) {
	t.Parallel()

	badStarted := make(chan struct{})
	releaseBad := make(chan struct{})
	goodStarted := make(chan struct{})
	releaseGood := make(chan struct{})
	var calls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(_ context.Context, target appmcp.Target) (probeOutcome, error) {
		calls.Add(1)
		switch target.Headers["Authorization"] {
		case "Bearer bad":
			close(badStarted)
			<-releaseBad
			return probeOutcome{kind: probeLegacyCandidate}, nil
		case "Bearer good":
			close(goodStarted)
			<-releaseGood
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		default:
			return probeOutcome{}, errors.New("unexpected credential")
		}
	}), time.Second)
	originJoined := make(chan struct{}, 3)
	retryJoined := make(chan struct{}, 2)
	coordinator.originJoined = func() { originJoined <- struct{}{} }
	coordinator.retryJoined = func() { retryJoined <- struct{}{} }
	origin := "https://example.com:443"
	bad := appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": "Bearer bad"},
	}
	good := appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": "Bearer good"},
	}
	badDone := make(chan struct {
		resolution eraResolution
		err        error
	}, 1)
	go func() {
		resolution, err := coordinator.resolve(context.Background(), bad, origin)
		badDone <- struct {
			resolution eraResolution
			err        error
		}{resolution: resolution, err: err}
	}()
	<-badStarted
	<-originJoined
	goodResults := make(chan struct {
		resolution eraResolution
		err        error
	}, 2)
	for range 2 {
		go func() {
			resolution, err := coordinator.resolve(context.Background(), good, origin)
			goodResults <- struct {
				resolution eraResolution
				err        error
			}{resolution: resolution, err: err}
		}()
	}
	for range 2 {
		<-originJoined
	}
	close(releaseBad)
	<-goodStarted
	for range 2 {
		<-retryJoined
	}
	close(releaseGood)
	for range 2 {
		result := <-goodResults
		if result.err != nil {
			t.Fatalf("good resolve: %v", result.err)
		}
		if got := result.resolution.entry.era; got != eraModern {
			t.Fatalf("good era = %v, want modern", got)
		}
	}
	badResult := <-badDone
	if badResult.err != nil {
		t.Fatalf("bad resolve: %v", badResult.err)
	}
	if badResult.resolution.entry.era != eraModern && !badResult.resolution.legacyCandidate {
		t.Fatalf("bad resolution = %+v", badResult.resolution)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("probe calls = %d, want ambiguous leader plus one good retry", got)
	}
}

func TestEraCoordinatorCoalescesInconclusiveRetriesByCredential(t *testing.T) {
	t.Parallel()

	initialStarted := make(chan struct{})
	releaseInitial := make(chan struct{})
	groupStarted := make(chan string, 2)
	releaseGroups := make(chan struct{})
	const callersPerGroup = 12
	var calls atomic.Int64
	var groupACalls atomic.Int64
	var groupBCalls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(_ context.Context, target appmcp.Target) (probeOutcome, error) {
		calls.Add(1)
		switch target.Headers["Authorization"] {
		case "Bearer initial":
			close(initialStarted)
			<-releaseInitial
			return probeOutcome{}, appmcp.ErrUnreachable
		case "Bearer group-a":
			if groupACalls.Add(1) == 1 {
				groupStarted <- "a"
			}
			<-releaseGroups
			return probeOutcome{}, appmcp.ErrUnreachable
		case "Bearer group-b":
			if groupBCalls.Add(1) == 1 {
				groupStarted <- "b"
			}
			<-releaseGroups
			return probeOutcome{}, appmcp.ErrUnreachable
		default:
			return probeOutcome{}, errors.New("unexpected credential")
		}
	}), time.Second)
	originJoined := make(chan struct{}, callersPerGroup*2+1)
	retryJoined := make(chan struct{}, callersPerGroup*2)
	coordinator.originJoined = func() { originJoined <- struct{}{} }
	coordinator.retryJoined = func() { retryJoined <- struct{}{} }
	origin := "https://example.com:443"
	initial := appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": "Bearer initial"},
	}

	initialDone := make(chan error, 1)
	go func() {
		resolution, err := coordinator.resolve(context.Background(), initial, origin)
		if resolution.source != decisionProbe {
			initialDone <- errors.New("initial error source is not probe")
			return
		}
		initialDone <- err
	}()
	<-initialStarted
	<-originJoined

	errs := make(chan error, callersPerGroup*2)
	var ready sync.WaitGroup
	ready.Add(callersPerGroup * 2)
	begin := make(chan struct{})
	for _, credential := range []string{"Bearer group-a", "Bearer group-b"} {
		for range callersPerGroup {
			go func() {
				target := appmcp.Target{
					URL:     "https://example.com/mcp",
					Headers: map[string]string{"Authorization": credential},
				}
				ready.Done()
				<-begin
				resolution, err := coordinator.resolve(context.Background(), target, origin)
				if resolution.source != decisionProbe {
					errs <- errors.New("credential retry error source is not probe")
					return
				}
				errs <- err
			}()
		}
	}
	ready.Wait()
	close(begin)
	for range callersPerGroup * 2 {
		<-originJoined
	}
	close(releaseInitial)
	if err := <-initialDone; !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("initial error = %v", err)
	}
	for range callersPerGroup * 2 {
		<-retryJoined
	}
	seen := map[string]bool{}
	for range 2 {
		seen[<-groupStarted] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("credential retry groups = %v", seen)
	}
	close(releaseGroups)
	for range callersPerGroup * 2 {
		if err := <-errs; !errors.Is(err, appmcp.ErrUnreachable) {
			t.Fatalf("credential retry error = %v", err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("probe calls = %d, want initial plus one per credential group", got)
	}
}

func TestEraCoordinatorInitiatingCallerCancellationDoesNotCancelFollower(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(ctx context.Context, _ appmcp.Target) (probeOutcome, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		case <-ctx.Done():
			return probeOutcome{}, ctx.Err()
		}
	}), time.Second)
	target := appmcp.Target{URL: "https://example.com/mcp"}
	origin := "https://example.com:443"
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct {
		resolution eraResolution
		err        error
	}, 1)
	go func() {
		resolution, err := coordinator.resolve(leaderCtx, target, origin)
		leaderDone <- struct {
			resolution eraResolution
			err        error
		}{resolution: resolution, err: err}
	}()
	<-started

	followerDone := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(context.Background(), target, origin)
		followerDone <- err
	}()
	cancelLeader()
	leaderResult := <-leaderDone
	if !errors.Is(leaderResult.err, context.Canceled) {
		t.Fatalf("leader error = %v, want canceled", leaderResult.err)
	}
	if leaderResult.resolution.source != decisionProbe {
		t.Fatalf("leader source = %q, want probe", leaderResult.resolution.source)
	}
	close(release)
	if err := <-followerDone; err != nil {
		t.Fatalf("follower error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
}

func TestEraCoordinatorDetachedCredentialRetryCancellationPreservesSource(t *testing.T) {
	t.Parallel()

	initialStarted := make(chan struct{})
	releaseInitial := make(chan struct{})
	retryStarted := make(chan struct{})
	releaseRetry := make(chan struct{})
	coordinator := newEraCoordinator(probeFunc(func(_ context.Context, target appmcp.Target) (probeOutcome, error) {
		switch target.Headers["Authorization"] {
		case "Bearer initial":
			close(initialStarted)
			<-releaseInitial
			return probeOutcome{}, appmcp.ErrUnreachable
		case "Bearer retry":
			close(retryStarted)
			<-releaseRetry
			return probeOutcome{}, appmcp.ErrUnreachable
		default:
			return probeOutcome{}, errors.New("unexpected credential")
		}
	}), time.Second)
	originJoined := make(chan struct{}, 2)
	retryJoined := make(chan struct{}, 1)
	coordinator.originJoined = func() { originJoined <- struct{}{} }
	coordinator.retryJoined = func() { retryJoined <- struct{}{} }
	origin := "https://example.com:443"
	initialDone := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(context.Background(), appmcp.Target{
			URL:     "https://example.com/mcp",
			Headers: map[string]string{"Authorization": "Bearer initial"},
		}, origin)
		initialDone <- err
	}()
	<-initialStarted
	<-originJoined

	retryCtx, cancelRetry := context.WithCancel(context.Background())
	retryDone := make(chan struct {
		resolution eraResolution
		err        error
	}, 1)
	go func() {
		resolution, err := coordinator.resolve(retryCtx, appmcp.Target{
			URL:     "https://example.com/mcp",
			Headers: map[string]string{"Authorization": "Bearer retry"},
		}, origin)
		retryDone <- struct {
			resolution eraResolution
			err        error
		}{resolution: resolution, err: err}
	}()
	<-originJoined
	close(releaseInitial)
	<-retryJoined
	<-retryStarted
	cancelRetry()
	result := <-retryDone
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("retry error = %v, want canceled", result.err)
	}
	if result.resolution.source != decisionProbe {
		t.Fatalf("retry source = %q, want probe", result.resolution.source)
	}
	close(releaseRetry)
	if err := <-initialDone; !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("initial error = %v", err)
	}
}

func TestEraCoordinatorBoundedProbeTimeoutPreservesSource(t *testing.T) {
	t.Parallel()

	coordinator := newEraCoordinator(probeFunc(func(ctx context.Context, _ appmcp.Target) (probeOutcome, error) {
		<-ctx.Done()
		return probeOutcome{}, ctx.Err()
	}), 10*time.Millisecond)
	done := make(chan struct {
		resolution eraResolution
		err        error
	}, 1)
	go func() {
		resolution, err := coordinator.resolve(
			context.Background(),
			appmcp.Target{URL: "https://example.com/mcp"},
			"https://example.com:443",
		)
		done <- struct {
			resolution eraResolution
			err        error
		}{resolution: resolution, err: err}
	}()
	select {
	case result := <-done:
		if !errors.Is(result.err, context.DeadlineExceeded) {
			t.Fatalf("resolve error = %v, want deadline exceeded", result.err)
		}
		if result.resolution.source != decisionProbe {
			t.Fatalf("source = %q, want probe", result.resolution.source)
		}
	case <-time.After(time.Second):
		t.Fatal("bounded probe did not complete")
	}
}

func TestEraCoordinatorProbeErrorsPreserveSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "auth", err: appmcp.ErrUnreachable},
		{name: "network", err: &unreachableError{origin: "https://example.com:443", category: "network", cause: errors.New("dial")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
				return probeOutcome{}, tt.err
			}), time.Second)
			resolution, err := coordinator.resolve(
				context.Background(),
				appmcp.Target{URL: "https://example.com/mcp"},
				"https://example.com:443",
			)
			if !errors.Is(err, tt.err) {
				t.Fatalf("resolve error = %v, want %v", err, tt.err)
			}
			if resolution.source != decisionProbe {
				t.Fatalf("source = %q, want probe", resolution.source)
			}
		})
	}
}

func TestCredentialFingerprintUsesFullDigest(t *testing.T) {
	t.Parallel()

	const secret = "credential-secret-sentinel"
	fingerprint := credentialFingerprint(map[string]string{"Authorization": "Bearer " + secret})
	if len(fingerprint) != sha256.Size*2 {
		t.Fatalf("fingerprint length = %d, want %d", len(fingerprint), sha256.Size*2)
	}
	if strings.Contains(fingerprint, secret) {
		t.Fatal("fingerprint contains credential")
	}
}

func TestEraCoordinatorDoesNotCacheInconclusiveResultsOrLegacyCandidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		outcome probeOutcome
		err     error
	}{
		{name: "auth", err: appmcp.ErrUnreachable},
		{name: "network", err: &unreachableError{origin: "https://example.com:443", category: "probe", cause: errors.New("network")}},
		{name: "legacy candidate", outcome: probeOutcome{kind: probeLegacyCandidate}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int64
			coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
				calls.Add(1)
				return tt.outcome, tt.err
			}), time.Second)
			target := appmcp.Target{URL: "https://example.com/mcp"}
			for range 2 {
				_, _ = coordinator.resolve(context.Background(), target, "https://example.com:443")
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("probe calls = %d, want 2", got)
			}
		})
	}
}

func TestEraCoordinatorCachesModernIncompatible(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		calls.Add(1)
		return probeOutcome{kind: probeModernIncompatible}, appmcp.ErrProtocolIncompatible
	}), time.Second)
	target := appmcp.Target{URL: "https://example.com/mcp"}
	origin := "https://example.com:443"
	for range 2 {
		resolution, err := coordinator.resolve(context.Background(), target, origin)
		if !errors.Is(err, appmcp.ErrProtocolIncompatible) {
			t.Fatalf("resolve error = %v", err)
		}
		if resolution.entry.era != eraModernIncompatible {
			t.Fatalf("entry = %+v", resolution.entry)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
}

func TestEraCoordinatorAllowsOneCASCorrectionPerOrigin(t *testing.T) {
	t.Parallel()

	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
	}), time.Second)
	origin := "https://example.com:443"
	resolution, err := coordinator.resolve(
		context.Background(),
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	corrected, won := coordinator.correct(origin, resolution.entry, eraEntry{era: eraLegacy})
	if !won || corrected.era != eraLegacy || !corrected.corrected {
		t.Fatalf("first correction = %+v, won=%v", corrected, won)
	}
	if got, won := coordinator.correct(origin, resolution.entry, eraEntry{era: eraLegacy}); won || got != corrected {
		t.Fatalf("stale correction = %+v, won=%v", got, won)
	}
	if got, won := coordinator.correct(origin, corrected, eraEntry{era: eraModern, version: modernProtocolVersion}); won || got != corrected {
		t.Fatalf("second correction = %+v, won=%v", got, won)
	}
}
