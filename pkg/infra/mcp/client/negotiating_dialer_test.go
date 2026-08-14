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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type legacyConnectorFunc func(context.Context, appmcp.Target) (appmcp.Upstream, error)

func (f legacyConnectorFunc) ConnectLegacy(ctx context.Context, target appmcp.Target) (appmcp.Upstream, error) {
	return f(ctx, target)
}

type upstreamStub struct {
	listTools func(context.Context) ([]appmcp.Tool, error)
	callTool  func(context.Context, string, json.RawMessage) (json.RawMessage, error)
	close     func(context.Context)
}

func (u *upstreamStub) ListTools(ctx context.Context) ([]appmcp.Tool, error) {
	if u.listTools == nil {
		return nil, nil
	}
	return u.listTools(ctx)
}

func (u *upstreamStub) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	if u.callTool == nil {
		return nil, nil
	}
	return u.callTool(ctx, name, arguments)
}

func (u *upstreamStub) ListResources(context.Context) ([]appmcp.Resource, error) {
	return nil, nil
}

func (u *upstreamStub) ListResourceTemplates(context.Context) ([]appmcp.ResourceTemplate, error) {
	return nil, nil
}

func (u *upstreamStub) ReadResource(context.Context, string) (json.RawMessage, error) {
	return nil, nil
}

func (u *upstreamStub) ListPrompts(context.Context) ([]appmcp.Prompt, error) {
	return nil, nil
}

func (u *upstreamStub) GetPrompt(context.Context, string, map[string]string) (json.RawMessage, error) {
	return nil, nil
}

func (u *upstreamStub) SupportsResources() bool {
	return true
}

func (u *upstreamStub) SupportsPrompts() bool {
	return true
}

func (u *upstreamStub) Close(ctx context.Context) {
	if u.close != nil {
		u.close(ctx)
	}
}

type legacyOnlyNegotiationServer struct {
	server          *httptest.Server
	discovers       atomic.Int64
	initializes     atomic.Int64
	discoverOnce    sync.Once
	discoverStarted chan struct{}
	releaseDiscover chan struct{}
}

func startLegacyOnlyNegotiationServer(t *testing.T) *legacyOnlyNegotiationServer {
	t.Helper()
	fixture := &legacyOnlyNegotiationServer{}
	server := sdk.NewServer(&sdk.Implementation{Name: "legacy-only", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				fixture.initializes.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := r.Body.Close(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var envelope struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if envelope.Method == "server/discover" {
			fixture.discovers.Add(1)
			if fixture.discoverStarted != nil {
				fixture.discoverOnce.Do(func() {
					close(fixture.discoverStarted)
				})
				<-fixture.releaseDiscover
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(`{`)); err != nil {
				return
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func TestNegotiatingDialerStrictOverridesSkipProbeAndFallback(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	var legacyCalls atomic.Int64
	var modernCalls atomic.Int64
	legacyUpstream := &upstreamStub{}
	modernUpstream := &upstreamStub{}
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{}, errors.New("probe must not run")
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			legacyCalls.Add(1)
			return legacyUpstream, nil
		}),
		coordinator,
		func(_ appmcp.Target, version string) (appmcp.Upstream, error) {
			modernCalls.Add(1)
			if version != modernProtocolVersion {
				t.Fatalf("modern version = %q", version)
			}
			return modernUpstream, nil
		},
		slog.New(slog.DiscardHandler),
	)

	legacy, err := dialer.Connect(context.Background(), appmcp.Target{
		URL:          "https://example.com/legacy",
		ProtocolMode: registrydomain.MCPProtocolModeLegacy,
	})
	if err != nil || legacy != legacyUpstream {
		t.Fatalf("legacy override = %T, %v", legacy, err)
	}
	modern, err := dialer.Connect(context.Background(), appmcp.Target{
		URL:          "https://example.com/modern",
		ProtocolMode: registrydomain.MCPProtocolModeModern,
	})
	if err != nil || modern != modernUpstream {
		t.Fatalf("modern override = %T, %v", modern, err)
	}
	if probes.Load() != 0 || legacyCalls.Load() != 1 || modernCalls.Load() != 1 {
		t.Fatalf("calls probe=%d legacy=%d modern=%d", probes.Load(), legacyCalls.Load(), modernCalls.Load())
	}
}

func TestNegotiatingDialerAutoModernCacheMissAndHit(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	var modernCalls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return nil, errors.New("legacy fallback must not run")
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			modernCalls.Add(1)
			return &upstreamStub{}, nil
		},
		slog.New(slog.DiscardHandler),
	)
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	for range 2 {
		if _, err := dialer.Connect(context.Background(), target); err != nil {
			t.Fatalf("connect: %v", err)
		}
	}
	if probes.Load() != 1 || modernCalls.Load() != 2 {
		t.Fatalf("calls probe=%d modern=%d", probes.Load(), modernCalls.Load())
	}
}

func TestNegotiatingDialerConcurrentFirstRequestsUseOneProbe(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		if probes.Add(1) == 1 {
			close(started)
		}
		<-release
		return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return nil, errors.New("unexpected legacy")
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) { return &upstreamStub{}, nil },
		slog.New(slog.DiscardHandler),
	)
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	const callers = 24
	var ready sync.WaitGroup
	ready.Add(callers)
	begin := make(chan struct{})
	errs := make(chan error, callers)
	for range callers {
		go func() {
			ready.Done()
			<-begin
			_, err := dialer.Connect(context.Background(), target)
			errs <- err
		}()
	}
	ready.Wait()
	close(begin)
	<-started
	close(release)
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("connect: %v", err)
		}
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
}

func TestNegotiatingDialerConcurrentPinnedLegacyFallbackSharesColdSession(t *testing.T) {
	t.Parallel()

	fixture := startLegacyOnlyNegotiationServer(t)
	fixture.discoverStarted = make(chan struct{})
	fixture.releaseDiscover = make(chan struct{})
	dialer := NewNegotiatingDialer(New(), slog.New(slog.DiscardHandler))
	target := appmcp.Target{
		URL:          fixture.server.URL,
		PinKey:       "gateway:consumer:registry",
		ProtocolMode: registrydomain.MCPProtocolModeAuto,
	}
	const callers = 32
	var ready sync.WaitGroup
	ready.Add(callers)
	begin := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			ready.Done()
			<-begin
			upstream, err := dialer.Connect(context.Background(), target)
			if err == nil {
				upstream.Close(context.Background())
			}
			results <- err
		}()
	}
	ready.Wait()
	close(begin)
	<-fixture.discoverStarted
	close(fixture.releaseDiscover)
	for range callers {
		if err := <-results; err != nil {
			t.Fatalf("connect: %v", err)
		}
	}
	if got := fixture.discovers.Load(); got != 1 {
		t.Fatalf("strict probes = %d, want 1", got)
	}
	if got := fixture.initializes.Load(); got != 1 {
		t.Fatalf("legacy initializes = %d, want 1", got)
	}
}

func TestNegotiatingDialerEmptyAndExplicitAutoSharePinnedSession(t *testing.T) {
	t.Parallel()

	fixture := startLegacyOnlyNegotiationServer(t)
	dialer := NewNegotiatingDialer(New(), slog.New(slog.DiscardHandler))
	target := appmcp.Target{
		URL:    fixture.server.URL,
		PinKey: "gateway:consumer:registry",
	}
	first, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("empty-mode connect: %v", err)
	}
	first.Close(context.Background())
	target.ProtocolMode = registrydomain.MCPProtocolModeAuto
	second, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("explicit-auto connect: %v", err)
	}
	second.Close(context.Background())
	if got := fixture.discovers.Load(); got != 1 {
		t.Fatalf("strict probes = %d, want 1", got)
	}
	if got := fixture.initializes.Load(); got != 1 {
		t.Fatalf("legacy initializes = %d, want 1", got)
	}
}

func TestNegotiatingDialerCachesLegacyOnlyAfterSuccessfulInitialize(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	var connects atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			if connects.Add(1) == 1 {
				return nil, appmcp.ErrUnreachable
			}
			return &upstreamStub{}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("unexpected modern")
		},
		slog.New(slog.DiscardHandler),
	)
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	if _, err := dialer.Connect(context.Background(), target); !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("failed initialize error = %v", err)
	}
	for range 2 {
		if _, err := dialer.Connect(context.Background(), target); err != nil {
			t.Fatalf("successful legacy connect: %v", err)
		}
	}
	if probes.Load() != 2 {
		t.Fatalf("probe calls = %d, want retry after failed initialize then cache hit", probes.Load())
	}
	if connects.Load() != 3 {
		t.Fatalf("legacy connects = %d, want one per dial", connects.Load())
	}
}

func TestNegotiatingDialerModernIncompatibleNeverFallsBack(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	var legacyCalls atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{kind: probeModernIncompatible}, appmcp.ErrProtocolIncompatible
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			legacyCalls.Add(1)
			return &upstreamStub{}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) { return &upstreamStub{}, nil },
		slog.New(slog.DiscardHandler),
	)
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	for range 2 {
		if _, err := dialer.Connect(context.Background(), target); !errors.Is(err, appmcp.ErrProtocolIncompatible) {
			t.Fatalf("connect error = %v", err)
		}
	}
	if probes.Load() != 1 || legacyCalls.Load() != 0 {
		t.Fatalf("calls probe=%d legacy=%d", probes.Load(), legacyCalls.Load())
	}
}

func TestNegotiatingDialerGuardedReadCorrectsOnceAndRetries(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	modern := &upstreamStub{
		listTools: func(context.Context) ([]appmcp.Tool, error) {
			return nil, newEraCandidateError(eraLegacy)
		},
	}
	legacy := &upstreamStub{
		listTools: func(context.Context) ([]appmcp.Tool, error) {
			return []appmcp.Tool{{Name: "legacy"}}, nil
		},
	}
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		switch probes.Add(1) {
		case 1:
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		default:
			return probeOutcome{kind: probeLegacyCandidate}, nil
		}
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return legacy, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) { return modern, nil },
		slog.New(slog.DiscardHandler),
	)
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	upstream, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tools, err := upstream.ListTools(context.Background())
	if err != nil {
		t.Fatalf("guarded list: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "legacy" {
		t.Fatalf("tools = %+v", tools)
	}
	if probes.Load() != 2 {
		t.Fatalf("probe calls = %d, want initial plus contradiction confirmation", probes.Load())
	}

	next, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect after correction: %v", err)
	}
	if tools, err = next.ListTools(context.Background()); err != nil || len(tools) != 1 {
		t.Fatalf("cached corrected list = %+v, %v", tools, err)
	}
}

func TestGuardedUpstreamCoordinatesReadReconcileAndClose(t *testing.T) {
	t.Parallel()

	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	confirmationStarted := make(chan struct{})
	releaseConfirmation := make(chan struct{})
	closeStarted := make(chan struct{})
	closeDone := make(chan struct{})
	var oldCalls atomic.Int64
	var oldCloses atomic.Int64
	var proofCloses atomic.Int64
	var replacementCloses atomic.Int64
	old := &upstreamStub{
		listTools: func(context.Context) ([]appmcp.Tool, error) {
			if oldCalls.Add(1) == 1 {
				close(readStarted)
				<-releaseRead
				return []appmcp.Tool{{Name: "old"}}, nil
			}
			return nil, newEraCandidateError(eraLegacy)
		},
		close: func(context.Context) {
			oldCloses.Add(1)
		},
	}
	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		if probes.Add(1) == 1 {
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		}
		close(confirmationStarted)
		<-releaseConfirmation
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	var legacyCalls atomic.Int64
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			call := legacyCalls.Add(1)
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return []appmcp.Tool{{Name: "replacement"}}, nil
				},
				close: func(context.Context) {
					if call == 1 {
						proofCloses.Add(1)
						return
					}
					replacementCloses.Add(1)
				},
			}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) { return old, nil },
		slog.New(slog.DiscardHandler),
	)
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	upstream, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		_, listErr := upstream.ListTools(context.Background())
		readDone <- listErr
	}()
	<-readStarted

	reconcileDone := make(chan error, 1)
	go func() {
		tools, listErr := upstream.ListTools(context.Background())
		if listErr == nil && (len(tools) != 1 || tools[0].Name != "replacement") {
			listErr = errors.New("reconciled read did not use replacement")
		}
		reconcileDone <- listErr
	}()
	<-confirmationStarted

	go func() {
		close(closeStarted)
		upstream.Close(context.Background())
		close(closeDone)
	}()
	<-closeStarted
	close(releaseConfirmation)
	select {
	case <-closeDone:
		t.Fatal("close completed while the old upstream was in use")
	default:
	}
	if got := oldCloses.Load(); got != 0 {
		t.Fatalf("old closes while read active = %d", got)
	}
	close(releaseRead)
	if err := <-readDone; err != nil {
		t.Fatalf("concurrent read: %v", err)
	}
	if err := <-reconcileDone; err != nil {
		t.Fatalf("reconciled read: %v", err)
	}
	<-closeDone
	upstream.Close(context.Background())
	if got := oldCloses.Load(); got != 1 {
		t.Fatalf("old closes = %d, want 1", got)
	}
	if got := proofCloses.Load(); got != 1 {
		t.Fatalf("proof closes = %d, want 1", got)
	}
	if got := replacementCloses.Load(); got != 1 {
		t.Fatalf("replacement closes = %d, want 1", got)
	}
}

func TestNegotiatingDialerCoalescesContradictionAcrossWrappers(t *testing.T) {
	t.Parallel()

	confirmationStarted := make(chan struct{})
	releaseConfirmation := make(chan struct{})
	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		if probes.Add(1) == 1 {
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		}
		close(confirmationStarted)
		<-releaseConfirmation
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	var legacyCalls atomic.Int64
	var proofCloses atomic.Int64
	var replacementCloses atomic.Int64
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			call := legacyCalls.Add(1)
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return []appmcp.Tool{{Name: "legacy"}}, nil
				},
				close: func(context.Context) {
					if call == 1 {
						proofCloses.Add(1)
						return
					}
					replacementCloses.Add(1)
				},
			}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return nil, newEraCandidateError(eraLegacy)
				},
			}, nil
		},
		slog.New(slog.DiscardHandler),
	)
	confirmationJoined := make(chan struct{}, 2)
	dialer.confirmationJoined = func() { confirmationJoined <- struct{}{} }
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	first, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	second, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}

	errs := make(chan error, 2)
	go func() {
		_, listErr := first.ListTools(context.Background())
		errs <- listErr
	}()
	<-confirmationStarted
	<-confirmationJoined
	go func() {
		_, listErr := second.ListTools(context.Background())
		errs <- listErr
	}()
	<-confirmationJoined
	close(releaseConfirmation)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("reconciled list: %v", err)
		}
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("probe calls = %d, want initial plus one confirmation", got)
	}
	if got := legacyCalls.Load(); got != 3 {
		t.Fatalf("legacy dials = %d, want one proof and two owners", got)
	}
	if got := proofCloses.Load(); got != 1 {
		t.Fatalf("legacy proof closes = %d, want 1", got)
	}
	first.Close(context.Background())
	if got := replacementCloses.Load(); got != 1 {
		t.Fatalf("first replacement closes = %d, want 1", got)
	}
	second.Close(context.Background())
	if got := replacementCloses.Load(); got != 2 {
		t.Fatalf("replacement closes = %d, want 2", got)
	}
}

func TestNegotiatingDialerRetriesInconclusiveContradictionByCredential(t *testing.T) {
	t.Parallel()

	const (
		badCredential  = "Bearer bad"
		goodCredential = "Bearer good"
	)
	badProbeStarted := make(chan struct{})
	releaseBadProbe := make(chan struct{})
	goodProbeStarted := make(chan struct{})
	releaseGoodProbe := make(chan struct{})
	var goodProbeOnce sync.Once
	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(_ context.Context, target appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		switch target.Headers["Authorization"] {
		case badCredential:
			close(badProbeStarted)
			<-releaseBadProbe
			return probeOutcome{}, appmcp.ErrUnreachable
		case goodCredential:
			goodProbeOnce.Do(func() { close(goodProbeStarted) })
			<-releaseGoodProbe
			return probeOutcome{kind: probeLegacyCandidate}, nil
		default:
			return probeOutcome{}, errors.New("unexpected credential")
		}
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	var legacyCalls atomic.Int64
	var legacyCloses atomic.Int64
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(_ context.Context, target appmcp.Target) (appmcp.Upstream, error) {
			if target.Headers["Authorization"] != goodCredential {
				return nil, appmcp.ErrUnreachable
			}
			legacyCalls.Add(1)
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return []appmcp.Tool{{Name: "legacy"}}, nil
				},
				close: func(context.Context) {
					legacyCloses.Add(1)
				},
			}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	joined := make(chan struct{}, 3)
	dialer.confirmationJoined = func() { joined <- struct{}{} }
	retries := make(chan struct{}, 2)
	dialer.confirmationRetried = func() { retries <- struct{}{} }
	candidate := func() appmcp.Upstream {
		return &upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
			return nil, newEraCandidateError(eraLegacy)
		}}
	}
	bad := newGuardedUpstream(dialer, appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": badCredential},
	}, origin, entry, candidate())
	goodOne := newGuardedUpstream(dialer, appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": goodCredential},
	}, origin, entry, candidate())
	goodTwo := newGuardedUpstream(dialer, appmcp.Target{
		URL:     "https://example.com/mcp",
		Headers: map[string]string{"Authorization": goodCredential},
	}, origin, entry, candidate())

	badResult := make(chan error, 1)
	go func() {
		_, err := bad.ListTools(context.Background())
		badResult <- err
	}()
	<-badProbeStarted
	goodResults := make(chan error, 2)
	for _, guarded := range []appmcp.Upstream{goodOne, goodTwo} {
		go func(upstream appmcp.Upstream) {
			tools, err := upstream.ListTools(context.Background())
			if err == nil && (len(tools) != 1 || tools[0].Name != "legacy") {
				err = errors.New("credential retry did not select legacy")
			}
			goodResults <- err
		}(guarded)
	}
	for range 3 {
		<-joined
	}
	close(releaseBadProbe)
	<-goodProbeStarted
	for range 2 {
		<-retries
	}
	close(releaseGoodProbe)
	for range 2 {
		if err := <-goodResults; err != nil {
			t.Fatalf("good follower: %v", err)
		}
	}
	if err := <-badResult; err == nil {
		t.Fatal("bad leader unexpectedly succeeded")
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("probe calls = %d, want bad primary plus one good credential retry", got)
	}
	if got := legacyCalls.Load(); got != 3 {
		t.Fatalf("legacy calls = %d, want one proof plus two owners", got)
	}
	bad.Close(context.Background())
	goodOne.Close(context.Background())
	goodTwo.Close(context.Background())
	if got := legacyCloses.Load(); got != 3 {
		t.Fatalf("legacy closes = %d, want 3", got)
	}
}

func TestNegotiatingDialerSeparatesInconclusiveCredentialGroups(t *testing.T) {
	t.Parallel()

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(_ context.Context, target appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		if target.Headers["Authorization"] == "Bearer first" {
			close(firstStarted)
			<-releaseFirst
		}
		return probeOutcome{}, appmcp.ErrUnreachable
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return nil, errors.New("legacy must not be attempted")
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	candidate := func(credential string) appmcp.Upstream {
		return newGuardedUpstream(dialer, appmcp.Target{
			URL:     "https://example.com/mcp",
			Headers: map[string]string{"Authorization": credential},
		}, origin, entry, &upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
			return nil, newEraCandidateError(eraLegacy)
		}})
	}
	first := candidate("Bearer first")
	second := candidate("Bearer second")
	errs := make(chan error, 2)
	go func() {
		_, err := first.ListTools(context.Background())
		errs <- err
	}()
	<-firstStarted
	go func() {
		_, err := second.ListTools(context.Background())
		errs <- err
	}()
	close(releaseFirst)
	for range 2 {
		if err := <-errs; err == nil {
			t.Fatal("inconclusive credential unexpectedly succeeded")
		}
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("probe calls = %d, want one per credential group", got)
	}
	first.Close(context.Background())
	second.Close(context.Background())
}

func TestNegotiatingDialerContradictionWaiterCancellationIsIndependent(t *testing.T) {
	t.Parallel()

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		close(probeStarted)
		<-releaseProbe
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return &upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
				return []appmcp.Tool{{Name: "legacy"}}, nil
			}}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	candidate := func() appmcp.Upstream {
		return newGuardedUpstream(dialer, appmcp.Target{URL: "https://example.com/mcp"}, origin, entry,
			&upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
				return nil, newEraCandidateError(eraLegacy)
			}})
	}
	leader := candidate()
	waiter := candidate()
	leaderResult := make(chan error, 1)
	go func() {
		_, err := leader.ListTools(context.Background())
		leaderResult <- err
	}()
	<-probeStarted
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)
	go func() {
		_, err := waiter.ListTools(waiterCtx)
		waiterResult <- err
	}()
	cancelWaiter()
	if err := <-waiterResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter error = %v, want canceled", err)
	}
	close(releaseProbe)
	if err := <-leaderResult; err != nil {
		t.Fatalf("leader error = %v", err)
	}
	leader.Close(context.Background())
	waiter.Close(context.Background())
}

func TestGuardedUpstreamCanceledReconcileLaterAdoptsDetachedCorrection(t *testing.T) {
	t.Parallel()

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	proofClosed := make(chan struct{})
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		close(probeStarted)
		<-releaseProbe
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	var legacyCalls atomic.Int64
	var oldCloses atomic.Int64
	var ownerCloses atomic.Int64
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			call := legacyCalls.Add(1)
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return []appmcp.Tool{{Name: "legacy"}}, nil
				},
				close: func(context.Context) {
					if call == 1 {
						close(proofClosed)
						return
					}
					ownerCloses.Add(1)
				},
			}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	guarded := newGuardedUpstream(
		dialer,
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
		entry,
		&upstreamStub{
			listTools: func(context.Context) ([]appmcp.Tool, error) {
				return nil, newEraCandidateError(eraLegacy)
			},
			close: func(context.Context) {
				oldCloses.Add(1)
			},
		},
	)
	canceledCtx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := guarded.ListTools(canceledCtx)
		firstDone <- err
	}()
	<-probeStarted
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read error = %v, want canceled", err)
	}
	close(releaseProbe)
	<-proofClosed

	tools, err := guarded.ListTools(context.Background())
	if err != nil {
		t.Fatalf("read after detached correction: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "legacy" {
		t.Fatalf("tools = %+v, want legacy", tools)
	}
	if got := oldCloses.Load(); got != 1 {
		t.Fatalf("old closes = %d, want 1", got)
	}
	if got := legacyCalls.Load(); got != 2 {
		t.Fatalf("legacy calls = %d, want proof plus owner", got)
	}
	guarded.Close(context.Background())
	guarded.Close(context.Background())
	if got := ownerCloses.Load(); got != 1 {
		t.Fatalf("owner closes = %d, want 1", got)
	}
}

func TestGuardedUpstreamDiscardsStaleConfirmationErrorAfterCorrection(t *testing.T) {
	t.Parallel()

	confirmationReturned := make(chan struct{})
	releaseReconcile := make(chan struct{})
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		return probeOutcome{}, appmcp.ErrUnreachable
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return &upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
				return []appmcp.Tool{{Name: "legacy"}}, nil
			}}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	dialer.reconcileConfirmed = func() {
		close(confirmationReturned)
		<-releaseReconcile
	}
	guarded := newGuardedUpstream(
		dialer,
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
		entry,
		&upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
			return nil, newEraCandidateError(eraLegacy)
		}},
	)
	done := make(chan struct {
		tools []appmcp.Tool
		err   error
	}, 1)
	go func() {
		tools, err := guarded.ListTools(context.Background())
		done <- struct {
			tools []appmcp.Tool
			err   error
		}{tools: tools, err: err}
	}()
	<-confirmationReturned
	if _, won := coordinator.correct(origin, entry, eraEntry{era: eraLegacy}); !won {
		t.Fatal("external correction did not win")
	}
	close(releaseReconcile)
	result := <-done
	if result.err != nil {
		t.Fatalf("stale confirmation error propagated: %v", result.err)
	}
	if len(result.tools) != 1 || result.tools[0].Name != "legacy" {
		t.Fatalf("tools = %+v, want legacy", result.tools)
	}
	guarded.Close(context.Background())
}

func TestGuardedUpstreamTransientConfirmationFailureDoesNotConsumeReconcile(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		if probes.Add(1) == 1 {
			return probeOutcome{}, appmcp.ErrUnreachable
		}
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return &upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
				return []appmcp.Tool{{Name: "legacy"}}, nil
			}}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	guarded := newGuardedUpstream(
		dialer,
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
		entry,
		&upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
			return nil, newEraCandidateError(eraLegacy)
		}},
	)
	if _, err := guarded.ListTools(context.Background()); !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("first read error = %v, want unreachable", err)
	}
	tools, err := guarded.ListTools(context.Background())
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "legacy" {
		t.Fatalf("tools = %+v, want legacy", tools)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("confirmation probes = %d, want 2", got)
	}
	guarded.Close(context.Background())
}

func TestNegotiatingDialerConfirmationDropsCompletedKeys(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{}, appmcp.ErrUnreachable
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return nil, errors.New("legacy must not be attempted")
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	for range 2 {
		guarded := newGuardedUpstream(
			dialer,
			appmcp.Target{URL: "https://example.com/mcp"},
			origin,
			entry,
			&upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
				return nil, newEraCandidateError(eraLegacy)
			}},
		)
		if _, err := guarded.ListTools(context.Background()); err == nil {
			t.Fatal("inconclusive contradiction unexpectedly succeeded")
		}
		guarded.Close(context.Background())
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("sequential confirmation probes = %d, want 2", got)
	}
}

func TestNegotiatingDialerHandlesManyConfirmationGenerations(t *testing.T) {
	t.Parallel()

	const generations = 32
	var probes atomic.Int64
	var legacyCalls atomic.Int64
	var legacyCloses atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			legacyCalls.Add(1)
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return []appmcp.Tool{{Name: "legacy"}}, nil
				},
				close: func(context.Context) {
					legacyCloses.Add(1)
				},
			}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	var wg sync.WaitGroup
	errs := make(chan error, generations)
	for index := range generations {
		origin := "https://example-" + strconv.Itoa(index) + ".com:443"
		entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
		guarded := newGuardedUpstream(
			dialer,
			appmcp.Target{URL: "https://example-" + strconv.Itoa(index) + ".com/mcp"},
			origin,
			entry,
			&upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
				return nil, newEraCandidateError(eraLegacy)
			}},
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			tools, err := guarded.ListTools(context.Background())
			if err == nil && (len(tools) != 1 || tools[0].Name != "legacy") {
				err = errors.New("generation did not select legacy")
			}
			guarded.Close(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("generation confirmation: %v", err)
		}
	}
	if got := probes.Load(); got != generations {
		t.Fatalf("confirmation probes = %d, want %d", got, generations)
	}
	if got := legacyCalls.Load(); got != generations*2 {
		t.Fatalf("legacy calls = %d, want %d", got, generations*2)
	}
	if got := legacyCloses.Load(); got != generations*2 {
		t.Fatalf("legacy closes = %d, want %d", got, generations*2)
	}
}

func TestGuardedUpstreamConcurrentCloseAndContradictionContenders(t *testing.T) {
	t.Parallel()

	const contenders = 24
	var probes atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		probes.Add(1)
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	var oldCloses atomic.Int64
	var legacyCalls atomic.Int64
	var legacyCloses atomic.Int64
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			legacyCalls.Add(1)
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return []appmcp.Tool{{Name: "legacy"}}, nil
				},
				close: func(context.Context) {
					legacyCloses.Add(1)
				},
			}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	guarded := newGuardedUpstream(
		dialer,
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
		entry,
		&upstreamStub{
			listTools: func(context.Context) ([]appmcp.Tool, error) {
				return nil, newEraCandidateError(eraLegacy)
			},
			close: func(context.Context) {
				oldCloses.Add(1)
			},
		},
	)
	var wg sync.WaitGroup
	errs := make(chan error, contenders)
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := guarded.ListTools(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("no contradiction contender installed the replacement")
	}
	var closeWG sync.WaitGroup
	for range contenders {
		closeWG.Add(1)
		go func() {
			defer closeWG.Done()
			guarded.Close(context.Background())
		}()
	}
	closeWG.Wait()
	if got := probes.Load(); got != 1 {
		t.Fatalf("confirmation probes = %d, want 1", got)
	}
	if got := legacyCalls.Load(); got != 2 {
		t.Fatalf("legacy calls = %d, want proof plus owner", got)
	}
	if got := oldCloses.Load(); got != 1 {
		t.Fatalf("old closes = %d, want 1", got)
	}
	if got := legacyCloses.Load(); got != 2 {
		t.Fatalf("legacy closes = %d, want proof plus owner", got)
	}
}

func TestGuardedUpstreamConcurrentCloseWhileConfirmationBlocked(t *testing.T) {
	t.Parallel()

	const (
		contenders = 12
		closers    = 8
	)
	allOldCallsStarted := make(chan struct{})
	releaseOldCalls := make(chan struct{})
	confirmationStarted := make(chan struct{})
	releaseConfirmation := make(chan struct{})
	var oldCalls atomic.Int64
	var oldCloses atomic.Int64
	var legacyCalls atomic.Int64
	var proofCloses atomic.Int64
	var ownerCloses atomic.Int64
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		close(confirmationStarted)
		<-releaseConfirmation
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			call := legacyCalls.Add(1)
			return &upstreamStub{
				listTools: func(context.Context) ([]appmcp.Tool, error) {
					return []appmcp.Tool{{Name: "legacy"}}, nil
				},
				close: func(context.Context) {
					if call == 1 {
						proofCloses.Add(1)
						return
					}
					ownerCloses.Add(1)
				},
			}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	guarded := newGuardedUpstream(
		dialer,
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
		entry,
		&upstreamStub{
			listTools: func(context.Context) ([]appmcp.Tool, error) {
				if oldCalls.Add(1) == contenders {
					close(allOldCallsStarted)
				}
				<-releaseOldCalls
				return nil, newEraCandidateError(eraLegacy)
			},
			close: func(context.Context) {
				oldCloses.Add(1)
			},
		},
	)
	results := make(chan error, contenders)
	for range contenders {
		go func() {
			_, err := guarded.ListTools(context.Background())
			results <- err
		}()
	}
	<-allOldCallsStarted
	close(releaseOldCalls)
	<-confirmationStarted
	closeAttempted := make(chan struct{}, closers)
	closeDone := make(chan struct{}, closers)
	for range closers {
		go func() {
			closeAttempted <- struct{}{}
			guarded.Close(context.Background())
			closeDone <- struct{}{}
		}()
	}
	for range closers {
		<-closeAttempted
	}
	close(releaseConfirmation)
	for range contenders {
		<-results
	}
	for range closers {
		<-closeDone
	}
	if got := oldCloses.Load(); got != 1 {
		t.Fatalf("old closes = %d, want 1", got)
	}
	if got := proofCloses.Load(); got != 1 {
		t.Fatalf("proof closes = %d, want 1", got)
	}
	if got := ownerCloses.Load(); got != 1 {
		t.Fatalf("owner closes = %d, want 1", got)
	}
	if got := legacyCalls.Load(); got != 2 {
		t.Fatalf("legacy calls = %d, want proof plus owner", got)
	}
}

func TestGuardedUpstreamConcurrentMutationNeverRetries(t *testing.T) {
	t.Parallel()

	const contenders = 24
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	var replacementCalls atomic.Int64
	var oldCalls atomic.Int64
	allOldCallsStarted := make(chan struct{})
	releaseOldCalls := make(chan struct{})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return &upstreamStub{callTool: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
				replacementCalls.Add(1)
				return json.RawMessage(`{"ok":true}`), nil
			}}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.DiscardHandler),
	)
	guarded := newGuardedUpstream(
		dialer,
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
		entry,
		&upstreamStub{callTool: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			if oldCalls.Add(1) == contenders {
				close(allOldCallsStarted)
			}
			<-releaseOldCalls
			return nil, newEraCandidateError(eraLegacy)
		}},
	)
	var wg sync.WaitGroup
	errs := make(chan error, contenders)
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := guarded.CallTool(context.Background(), "mutate", nil)
			errs <- err
		}()
	}
	<-allOldCallsStarted
	close(releaseOldCalls)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("mutation contender unexpectedly succeeded")
		}
	}
	if got := replacementCalls.Load(); got != 0 {
		t.Fatalf("mutation retries = %d, want 0", got)
	}
	guarded.Close(context.Background())
}

func TestNegotiatingDialerNeverRetriesToolsCallAfterCorrection(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	var legacyCalls atomic.Int64
	modern := &upstreamStub{
		callTool: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			return nil, newEraCandidateError(eraLegacy)
		},
	}
	legacy := &upstreamStub{
		callTool: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			legacyCalls.Add(1)
			return json.RawMessage(`{"ok":true}`), nil
		},
	}
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		if probes.Add(1) == 1 {
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		}
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) { return legacy, nil }),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) { return modern, nil },
		slog.New(slog.DiscardHandler),
	)
	target := appmcp.Target{URL: "https://example.com/mcp", ProtocolMode: registrydomain.MCPProtocolModeAuto}
	upstream, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := upstream.CallTool(context.Background(), "mutate", nil); err == nil {
		t.Fatal("tools/call unexpectedly succeeded")
	}
	if legacyCalls.Load() != 0 {
		t.Fatalf("legacy tools/call retries = %d, want 0", legacyCalls.Load())
	}
	next, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect after correction: %v", err)
	}
	if _, err := next.CallTool(context.Background(), "mutate", nil); err != nil {
		t.Fatalf("next tools/call: %v", err)
	}
	if legacyCalls.Load() != 1 {
		t.Fatalf("later legacy calls = %d, want 1", legacyCalls.Load())
	}
}

func TestNegotiatingDialerObservabilityExcludesSensitiveValues(t *testing.T) {
	t.Parallel()

	const secret = "negotiation-secret-sentinel"
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
	}), time.Second)
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return nil, errors.New("unexpected legacy")
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) { return &upstreamStub{}, nil },
		logger,
	)
	_, err := dialer.Connect(context.Background(), appmcp.Target{
		URL:          "https://example.com/mcp?token=" + secret,
		Headers:      map[string]string{"Authorization": "Bearer " + secret},
		ProtocolMode: registrydomain.MCPProtocolModeAuto,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	output := logs.String()
	for _, required := range []string{
		`"component":"mcp_upstream_protocol"`,
		`"origin":"https://example.com:443"`,
		`"mode":"auto"`,
		`"era":"modern"`,
		`"source":"probe"`,
		`"result":"selected"`,
		`"latency_ms":`,
	} {
		if !strings.Contains(output, required) {
			t.Fatalf("log missing %s: %s", required, output)
		}
	}
	if strings.Contains(output, secret) ||
		strings.Contains(output, "Authorization") ||
		strings.Contains(output, "token=") ||
		strings.Contains(output, `"outcome":`) ||
		strings.Contains(output, "capabilities") ||
		strings.Contains(output, "metadata") {
		t.Fatalf("log exposed sensitive data: %s", output)
	}
}

func TestNegotiatingDialerContradictionTelemetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		observed     eraEntry
		candidateErr error
		outcome      probeOutcome
		probeErr     error
		wantResult   string
		wantEra      string
		wantCategory string
	}{
		{
			name:         "selected",
			observed:     eraEntry{era: eraModern, version: modernProtocolVersion},
			candidateErr: newEraCandidateError(eraLegacy),
			outcome:      probeOutcome{kind: probeLegacyCandidate},
			wantResult:   "selected",
			wantEra:      "legacy",
		},
		{
			name:         "modern incompatible",
			observed:     eraEntry{era: eraLegacy},
			candidateErr: &appmcp.RPCError{Code: codeUnsupportedProtocolVersion},
			outcome:      probeOutcome{kind: probeModernIncompatible},
			wantResult:   "incompatible",
			wantEra:      "modern_incompatible",
			wantCategory: "incompatible",
		},
		{
			name:         "failed",
			observed:     eraEntry{era: eraModern, version: modernProtocolVersion},
			candidateErr: newEraCandidateError(eraLegacy),
			probeErr:     appmcp.ErrUnreachable,
			wantResult:   "failed",
			wantEra:      "modern",
			wantCategory: "unreachable",
		},
		{
			name:         "inconclusive",
			observed:     eraEntry{era: eraModern, version: modernProtocolVersion},
			candidateErr: newEraCandidateError(eraLegacy),
			wantResult:   "unclassified",
			wantEra:      "modern",
			wantCategory: "unclassified",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
				return tt.outcome, tt.probeErr
			}), time.Second)
			origin := "https://example.com:443"
			entry := coordinator.storeInitial(origin, tt.observed)
			dialer := newNegotiatingDialer(
				legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
					return &upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
						return []appmcp.Tool{{Name: "legacy"}}, nil
					}}, nil
				}),
				coordinator,
				func(appmcp.Target, string) (appmcp.Upstream, error) {
					return &upstreamStub{}, nil
				},
				slog.New(slog.NewJSONHandler(&logs, nil)),
			)
			guarded := newGuardedUpstream(
				dialer,
				appmcp.Target{URL: "https://example.com/mcp"},
				origin,
				entry,
				&upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
					return nil, tt.candidateErr
				}},
			)
			_, callErr := guarded.ListTools(context.Background())
			if tt.wantResult == "selected" && callErr != nil {
				t.Fatalf("selected contradiction: %v", callErr)
			}
			if tt.wantResult != "selected" && callErr == nil {
				t.Fatal("non-selected contradiction unexpectedly succeeded")
			}
			guarded.Close(context.Background())
			events := contradictionLogEvents(t, logs.String())
			if len(events) != 1 {
				t.Fatalf("contradiction events = %d, want 1: %s", len(events), logs.String())
			}
			assertContradictionEvent(t, events[0], tt.wantResult, tt.wantEra, tt.wantCategory)
		})
	}
}

func TestNegotiatingDialerLogsSubsequentContradictionAfterReconcile(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	coordinator := newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
		return probeOutcome{kind: probeLegacyCandidate}, nil
	}), time.Second)
	origin := "https://example.com:443"
	entry := coordinator.storeInitial(origin, eraEntry{era: eraModern, version: modernProtocolVersion})
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return &upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
				return nil, newEraCandidateError(eraModern)
			}}, nil
		}),
		coordinator,
		func(appmcp.Target, string) (appmcp.Upstream, error) {
			return nil, errors.New("modern replacement must not be built")
		},
		slog.New(slog.NewJSONHandler(&logs, nil)),
	)
	guarded := newGuardedUpstream(
		dialer,
		appmcp.Target{URL: "https://example.com/mcp"},
		origin,
		entry,
		&upstreamStub{listTools: func(context.Context) ([]appmcp.Tool, error) {
			return nil, newEraCandidateError(eraLegacy)
		}},
	)
	if _, err := guarded.ListTools(context.Background()); err == nil {
		t.Fatal("replacement contradiction unexpectedly succeeded")
	}
	if _, err := guarded.ListTools(context.Background()); err == nil {
		t.Fatal("subsequent contradiction unexpectedly succeeded")
	}
	guarded.Close(context.Background())
	events := contradictionLogEvents(t, logs.String())
	if len(events) != 2 {
		t.Fatalf("contradiction events = %d, want 2: %s", len(events), logs.String())
	}
	assertContradictionEvent(t, events[0], "selected", "legacy", "")
	assertContradictionEvent(t, events[1], "failed", "legacy", "contradiction")
}

func contradictionLogEvents(t *testing.T, output string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode log event: %v", err)
		}
		if event["source"] == string(decisionContradiction) {
			events = append(events, event)
		}
	}
	return events
}

func assertContradictionEvent(
	t *testing.T,
	event map[string]any,
	result string,
	era string,
	category string,
) {
	t.Helper()
	expected := map[string]any{
		"component": "mcp_upstream_protocol",
		"origin":    "https://example.com:443",
		"mode":      "auto",
		"era":       era,
		"source":    "contradiction",
		"result":    result,
	}
	for key, value := range expected {
		if event[key] != value {
			t.Fatalf("event[%q] = %v, want %v: %+v", key, event[key], value, event)
		}
	}
	if category == "" {
		if _, ok := event["category"]; ok {
			t.Fatalf("unexpected category: %+v", event)
		}
	} else if event["category"] != category {
		t.Fatalf("category = %v, want %s: %+v", event["category"], category, event)
	}
	for _, forbidden := range []string{"outcome", "error", "headers", "body", "fingerprint"} {
		if _, ok := event[forbidden]; ok {
			t.Fatalf("event exposes %q: %+v", forbidden, event)
		}
	}
	if _, ok := event["latency_ms"]; !ok {
		t.Fatalf("event missing latency_ms: %+v", event)
	}
}

func TestOppositeEraCandidateUsesOnlyTypedSignals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		current protocolEra
		err     error
		want    bool
	}{
		{name: "modern typed legacy", current: eraModern, err: newEraCandidateError(eraLegacy), want: true},
		{name: "modern generic unreachable", current: eraModern, err: appmcp.ErrUnreachable},
		{name: "legacy modern header mismatch", current: eraLegacy, err: &appmcp.RPCError{Code: codeHeaderMismatch}, want: true},
		{name: "legacy modern capability", current: eraLegacy, err: &appmcp.RPCError{Code: codeRequiredCapability}, want: true},
		{name: "legacy modern version", current: eraLegacy, err: &appmcp.RPCError{Code: codeUnsupportedProtocolVersion}, want: true},
		{name: "legacy arbitrary RPC", current: eraLegacy, err: &appmcp.RPCError{Code: -32603}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := oppositeEraCandidate(tt.current, tt.err); got != tt.want {
				t.Fatalf("oppositeEraCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModernRoundTripperTracksOnlyAmbiguousBadRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        bool
	}{
		{
			name:        "ambiguous malformed 400",
			status:      http.StatusBadRequest,
			contentType: "application/json",
			body:        `{`,
			want:        true,
		},
		{
			name:        "ambiguous non-json 400",
			status:      http.StatusBadRequest,
			contentType: "text/plain",
			body:        "bad request",
			want:        true,
		},
		{
			name:        "400 result never contradicts",
			status:      http.StatusBadRequest,
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":"call-1","result":null}`,
		},
		{
			name:        "404 never contradicts",
			status:      http.StatusNotFound,
			contentType: "application/json",
			body:        `{`,
		},
		{
			name:        "normalized rpc error stays modern",
			status:      http.StatusBadRequest,
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":"call-1","error":{"code":-32601,"message":"missing"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var candidates sync.Map
			transport := &modernRoundTripper{
				transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: tt.status,
						Status:     http.StatusText(tt.status),
						Header:     http.Header{"Content-Type": []string{tt.contentType}},
						Body:       io.NopCloser(strings.NewReader(tt.body)),
					}, nil
				}),
				protocolVersion:       modernProtocolVersion,
				implementationVersion: "test",
				eraCandidates:         &candidates,
			}
			request, err := http.NewRequest(
				http.MethodPost,
				"https://example.com/mcp",
				strings.NewReader(`{"jsonrpc":"2.0","id":"call-1","method":"tools/list"}`),
			)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			if closeErr := response.Body.Close(); closeErr != nil {
				t.Fatalf("close response: %v", closeErr)
			}
			_, got := candidates.Load(`"call-1"`)
			if got != tt.want {
				t.Fatalf("candidate = %v, want %v", got, tt.want)
			}
		})
	}
}

type recordingProtocolDecision struct {
	mu    sync.Mutex
	calls []recordedProtocolDecision
}

type recordedProtocolDecision struct {
	source         string
	mode           string
	era            string
	result         string
	category       string
	probeHistogram bool
	probeLatency   time.Duration
	labels         map[string]string
}

func (r *recordingProtocolDecision) Record(_ context.Context, d ProtocolDecision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	labels := map[string]string{
		"source": d.Source,
		"mode":   d.Mode,
		"era":    d.Era,
		"result": d.Result,
	}
	if d.Category != "" {
		labels["category"] = d.Category
	}
	r.calls = append(r.calls, recordedProtocolDecision{
		source:         d.Source,
		mode:           d.Mode,
		era:            d.Era,
		result:         d.Result,
		category:       d.Category,
		probeHistogram: d.Source == string(decisionProbe),
		probeLatency:   d.Latency,
		labels:         labels,
	})
}

func (r *recordingProtocolDecision) snapshot() []recordedProtocolDecision {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedProtocolDecision, len(r.calls))
	copy(out, r.calls)
	return out
}

func metricTarget(url string, mode registrydomain.MCPProtocolMode) appmcp.Target {
	return appmcp.Target{
		URL:          url,
		ProtocolMode: mode,
		Headers:      map[string]string{"Authorization": "Bearer secret-token"},
	}
}

func assertNoForbiddenProtocolMetricLabels(t *testing.T, calls []recordedProtocolDecision) {
	t.Helper()
	forbidden := []string{"origin", "credential", "token", "authorization", "header", "body", "tool", "argument", "url"}
	for _, call := range calls {
		for key, value := range call.labels {
			blob := strings.ToLower(key + " " + value)
			for _, needle := range forbidden {
				if strings.Contains(blob, needle) {
					t.Fatalf("forbidden metric field %q=%q", key, value)
				}
			}
			if strings.Contains(value, "secret-token") || strings.Contains(strings.ToLower(value), "example.com") {
				t.Fatalf("sensitive value leaked in %q=%q", key, value)
			}
		}
	}
}

func TestNewProtocolDecisionRecorderDisabledIsNil(t *testing.T) {
	t.Parallel()
	if rec := NewProtocolDecisionRecorder(false); rec != nil {
		t.Fatal("disabled recorder must be nil")
	}
}

func TestNegotiatingDialerMetricsProbeThenCache(t *testing.T) {
	t.Parallel()

	rec := &recordingProtocolDecision{}
	var probes atomic.Int64
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return nil, errors.New("legacy fallback must not run")
		}),
		newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
			probes.Add(1)
			return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
		}), time.Second),
		func(appmcp.Target, string) (appmcp.Upstream, error) { return &upstreamStub{}, nil },
		slog.New(slog.DiscardHandler),
		rec,
	)
	target := metricTarget("https://example.com/mcp", registrydomain.MCPProtocolModeAuto)
	for range 2 {
		if _, err := dialer.Connect(context.Background(), target); err != nil {
			t.Fatalf("connect: %v", err)
		}
	}
	calls := rec.snapshot()
	if len(calls) != 2 {
		t.Fatalf("records = %d, want 2", len(calls))
	}
	if calls[0].source != string(decisionProbe) || !calls[0].probeHistogram || calls[0].probeLatency < 0 {
		t.Fatalf("probe record = %+v", calls[0])
	}
	if calls[1].source != string(decisionCache) || calls[1].probeHistogram {
		t.Fatalf("cache record = %+v", calls[1])
	}
	if probes.Load() != 1 {
		t.Fatalf("probes = %d, want 1", probes.Load())
	}
	assertNoForbiddenProtocolMetricLabels(t, calls)
}

func TestNegotiatingDialerMetricsOverrideSkipsProbe(t *testing.T) {
	t.Parallel()

	rec := &recordingProtocolDecision{}
	var probes atomic.Int64
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return &upstreamStub{}, nil
		}),
		newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
			probes.Add(1)
			return probeOutcome{}, errors.New("probe must not run")
		}), time.Second),
		func(appmcp.Target, string) (appmcp.Upstream, error) { return &upstreamStub{}, nil },
		slog.New(slog.DiscardHandler),
		rec,
	)
	if _, err := dialer.Connect(context.Background(), metricTarget("https://example.com/legacy", registrydomain.MCPProtocolModeLegacy)); err != nil {
		t.Fatalf("legacy override: %v", err)
	}
	if _, err := dialer.Connect(context.Background(), metricTarget("https://example.com/modern", registrydomain.MCPProtocolModeModern)); err != nil {
		t.Fatalf("modern override: %v", err)
	}
	calls := rec.snapshot()
	if len(calls) != 2 {
		t.Fatalf("records = %d, want 2", len(calls))
	}
	for _, call := range calls {
		if call.source != string(decisionOverride) || call.probeHistogram {
			t.Fatalf("override record = %+v", call)
		}
	}
	if probes.Load() != 0 {
		t.Fatalf("probes = %d, want 0", probes.Load())
	}
	assertNoForbiddenProtocolMetricLabels(t, calls)
}

func TestNegotiatingDialerMetricsContradictionLabeled(t *testing.T) {
	t.Parallel()

	rec := &recordingProtocolDecision{}
	var probes atomic.Int64
	modern := &upstreamStub{
		listTools: func(context.Context) ([]appmcp.Tool, error) {
			return nil, newEraCandidateError(eraLegacy)
		},
	}
	legacy := &upstreamStub{
		listTools: func(context.Context) ([]appmcp.Tool, error) {
			return []appmcp.Tool{{Name: "legacy"}}, nil
		},
	}
	dialer := newNegotiatingDialer(
		legacyConnectorFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			return legacy, nil
		}),
		newEraCoordinator(probeFunc(func(context.Context, appmcp.Target) (probeOutcome, error) {
			switch probes.Add(1) {
			case 1:
				return probeOutcome{kind: probeModern, version: modernProtocolVersion}, nil
			default:
				return probeOutcome{kind: probeLegacyCandidate}, nil
			}
		}), time.Second),
		func(appmcp.Target, string) (appmcp.Upstream, error) { return modern, nil },
		slog.New(slog.DiscardHandler),
		rec,
	)
	upstream, err := dialer.Connect(context.Background(), metricTarget("https://example.com/mcp", registrydomain.MCPProtocolModeAuto))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := upstream.ListTools(context.Background()); err != nil {
		t.Fatalf("guarded list: %v", err)
	}
	var contradiction recordedProtocolDecision
	found := false
	for _, call := range rec.snapshot() {
		if call.source == string(decisionContradiction) {
			contradiction = call
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing contradiction record: %+v", rec.snapshot())
	}
	if contradiction.probeHistogram {
		t.Fatalf("contradiction must not record probe latency: %+v", contradiction)
	}
	assertNoForbiddenProtocolMetricLabels(t, rec.snapshot())
}
