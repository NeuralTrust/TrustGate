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

package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	appsession "github.com/NeuralTrust/TrustGate/pkg/app/session"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	sessiondomain "github.com/NeuralTrust/TrustGate/pkg/domain/session"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newPermissiveCache(t *testing.T) *cachemocks.Client {
	t.Helper()
	c := cachemocks.NewClient(t)
	c.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	c.EXPECT().Get(mock.Anything, mock.Anything).Return("", errors.New("miss")).Maybe()
	c.EXPECT().RedisClient().Return(nil).Maybe()
	return c
}

func routableConsumerWith(gatewayID ids.GatewayID, registries ...*registrydomain.Registry) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gatewayID,
			Name:      "test-consumer",
			Slug:      "cons1234",
			LBConfig:  &domainconsumer.LBConfig{Algorithm: loadbalancer.AlgorithmRoundRobin},
		},
		Registries: registries,
	}
}

func backendFor(gatewayID ids.GatewayID, provider string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Name:      "registry-" + provider,
		Type:      registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{
			Provider: provider,
			Auth:     registrydomain.NewAPIKeyAuth("sk-1"),
		},
	}
}

func newTestForwarder(t *testing.T, invoker appproxy.ProviderInvoker) appproxy.Forwarder {
	return newTestForwarderWithLimiter(t, invoker, nil)
}

func newTestForwarderWithLimiter(t *testing.T, invoker appproxy.ProviderInvoker, limiter ratelimitapp.Checker) appproxy.Forwarder {
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, nil, approuting.NewResolver(), nil, limiter, nil, newTestLogger(),
	)
}

type fakeSessionStore struct {
	last     string
	recorded []appsession.RecordInput
	looked   []appsession.Scope
}

func (f *fakeSessionStore) Record(_ context.Context, in appsession.RecordInput) {
	f.recorded = append(f.recorded, in)
}

func (f *fakeSessionStore) LastTurnID(_ context.Context, scope appsession.Scope, _ string) string {
	f.looked = append(f.looked, scope)
	return f.last
}

func (f *fakeSessionStore) SessionForTurn(_ context.Context, _ appsession.Scope, _ string) string {
	return ""
}

func newTestForwarderWithStore(t *testing.T, invoker appproxy.ProviderInvoker, store appsession.Store) appproxy.Forwarder {
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, store, approuting.NewResolver(), nil, nil, nil, newTestLogger(),
	)
}

func enabledFallback(chain ...ids.RegistryID) *domainconsumer.Fallback {
	return &domainconsumer.Fallback{
		Enabled:  true,
		Triggers: []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
		Budget:   domainconsumer.FallbackBudget{MaxAttempts: 10},
		Chain:    chain,
	}
}

func TestForward_PoolFailoverOn503(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk1 := backendFor(gatewayID, "openai")
	bk2 := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, bk1, bk2)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 || string(res.Body) != "ok" {
		t.Fatalf("expected failover to 200/ok, got %d/%q", res.StatusCode, string(res.Body))
	}
}

func TestForward_RateLimitExceeded_Returns429WithHeaders(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID)

	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, gatewayID).Return(&ratelimitapp.Exceeded{
		Reason:     ratelimitapp.ReasonQuota,
		Limit:      10_000,
		Remaining:  0,
		RetryAfter: 10 * time.Second,
	}).Once()

	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newTestForwarderWithLimiter(t, invoker, limiter)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
	assert.Equal(t, []string{"10"}, res.Headers["Retry-After"])
	assert.Equal(t, []string{"10000"}, res.Headers["X-RateLimit-Limit"])
	assert.Equal(t, []string{"0"}, res.Headers["X-RateLimit-Remaining"])
	assert.Equal(t, []string{ratelimitapp.ReasonQuota}, res.Headers["X-RateLimit-Reason"])
	invoker.AssertNotCalled(t, "Invoke", mock.Anything, mock.Anything, mock.Anything)
}

func TestForward_RateLimitUnavailable_PropagatesError(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID)

	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, gatewayID).Return(ratelimitapp.ErrUnavailable).Once()

	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newTestForwarderWithLimiter(t, invoker, limiter)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.Nil(t, res)
	require.True(t, errors.Is(err, ratelimitapp.ErrUnavailable))
	invoker.AssertNotCalled(t, "Invoke", mock.Anything, mock.Anything, mock.Anything)
}

func TestForward_FallbackChainAfterPoolExhausted(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	pool := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, pool)
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{fallbackBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("recovered")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 || string(res.Body) != "recovered" {
		t.Fatalf("expected fallback chain success 200/recovered, got %d/%q", res.StatusCode, string(res.Body))
	}
}

func TestForward_QualifiedPinSkipsFallback(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	pinned := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, pinned)
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{fallbackBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == pinned.ID
		}), mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Body: []byte(`{"model":"@openai/gpt-5"}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 503 {
		t.Fatalf("pinned @provider/model must not fail over, got %d", res.StatusCode)
	}
}

func TestForward_AllCandidatesFailRelaysLast5xx(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	pool := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, pool)
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{fallbackBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 502, Body: []byte("bad gateway")}, nil)

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 502 {
		t.Fatalf("expected last 5xx relayed verbatim, got %d", res.StatusCode)
	}
}

func fallbackWithTriggers(chain ids.RegistryID, triggers ...domainconsumer.FallbackTrigger) *domainconsumer.Fallback {
	return &domainconsumer.Fallback{
		Enabled:  true,
		Triggers: triggers,
		Budget:   domainconsumer.FallbackBudget{MaxAttempts: 10},
		Chain:    []ids.RegistryID{chain},
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestForward_FallbackTriggerGating(t *testing.T) {
	cases := []struct {
		name        string
		triggers    []domainconsumer.FallbackTrigger
		primaryResp *appproxy.ProviderResponse
		primaryErr  error
		wantChain   bool
		wantStatus  int
		wantErr     bool
	}{
		{
			name:        "429 with only http_5xx does not reach the chain",
			triggers:    []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
			primaryResp: &appproxy.ProviderResponse{StatusCode: 429, Body: []byte("rate limited")},
			wantChain:   false,
			wantStatus:  429,
		},
		{
			name:        "429 with http_429 reaches the chain",
			triggers:    []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP429},
			primaryResp: &appproxy.ProviderResponse{StatusCode: 429, Body: []byte("rate limited")},
			wantChain:   true,
			wantStatus:  200,
		},
		{
			name:        "503 with only http_429 does not reach the chain",
			triggers:    []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP429},
			primaryResp: &appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")},
			wantChain:   false,
			wantStatus:  503,
		},
		{
			name:       "network timeout with timeout trigger reaches the chain",
			triggers:   []domainconsumer.FallbackTrigger{domainconsumer.TriggerTimeout},
			primaryErr: timeoutErr{},
			wantChain:  true,
			wantStatus: 200,
		},
		{
			name:       "network timeout with only http_5xx does not reach the chain",
			triggers:   []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
			primaryErr: timeoutErr{},
			wantChain:  false,
			wantErr:    true,
		},
		{
			name:       "deadline exceeded with timeout trigger reaches the chain",
			triggers:   []domainconsumer.FallbackTrigger{domainconsumer.TriggerTimeout},
			primaryErr: context.DeadlineExceeded,
			wantChain:  true,
			wantStatus: 200,
		},
		{
			name:       "connection error counts as http_5xx",
			triggers:   []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
			primaryErr: errors.New("connection refused"),
			wantChain:  true,
			wantStatus: 200,
		},
		{
			name:        "408 with timeout trigger reaches the chain",
			triggers:    []domainconsumer.FallbackTrigger{domainconsumer.TriggerTimeout},
			primaryResp: &appproxy.ProviderResponse{StatusCode: 408, Body: []byte("timeout")},
			wantChain:   true,
			wantStatus:  200,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			primary := backendFor(gatewayID, "openai")
			chainBk := backendFor(gatewayID, "anthropic")
			rc := routableConsumerWith(gatewayID, primary)
			rc.Consumer.Fallback = fallbackWithTriggers(chainBk.ID, tc.triggers...)
			rc.FallbackBackends = []*registrydomain.Registry{chainBk}

			invoker := proxymocks.NewProviderInvoker(t)
			invoker.EXPECT().
				Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
					return bk.ID == primary.ID
				}), mock.Anything).
				Return(tc.primaryResp, tc.primaryErr).
				Once()
			if tc.wantChain {
				invoker.EXPECT().
					Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
						return bk.ID == chainBk.ID
					}), mock.Anything).
					Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("rescued")}, nil).
					Once()
			}

			fwd := newTestForwarder(t, invoker)
			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request:   &infracontext.RequestContext{},
			})
			if tc.wantErr {
				require.Error(t, err, "the failure must be relayed as an error without fallback")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, res.StatusCode)
		})
	}
}

func TestForward_CredentialAcquisitionFailureIsTerminal(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	primary := backendFor(gatewayID, "azure")
	chainBk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, primary)
	rc.Consumer.Fallback = enabledFallback(chainBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{chainBk}

	credentialErr := fmt.Errorf("provider completions: %w: secret expired", registrydomain.ErrCredentialAcquisition)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, credentialErr).
		Once()

	fwd := newTestForwarder(t, invoker)
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.ErrorIs(t, err, registrydomain.ErrCredentialAcquisition,
		"a credential misconfiguration must fail fast without retries or fallback")
}

func TestForward_LBFailoverNotGatedByTriggers(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk1 := backendFor(gatewayID, "openai")
	bk2 := backendFor(gatewayID, "mistral")
	chainBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, bk1, bk2)
	rc.Consumer.Fallback = fallbackWithTriggers(chainBk.ID, domainconsumer.TriggerHTTP5xx)
	rc.FallbackBackends = []*registrydomain.Registry{chainBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == bk1.ID || bk.ID == bk2.ID
		}), mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 429, Body: []byte("rate limited")}, nil).
		Twice()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, 429, res.StatusCode, "both LB members must be tried, chain must not (429 not in triggers)")
}

func TestForward_SyncSuccess(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 || string(res.Body) != "ok" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestForward_DisabledLBConfigIsIgnored(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Consumer.LBConfig = &domainconsumer.LBConfig{Enabled: false, Algorithm: "unsupported-algorithm"}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

func TestForward_RecordsLLMSpanWithUsage(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{
			StatusCode: 200,
			Body:       []byte("ok"),
			Usage:      &adapter.CanonicalUsage{InputTokens: 8, OutputTokens: 2, TotalTokens: 10},
			ResponseID: "chatcmpl-xyz",
		}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	rt := trace.New("trace-1", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)

	_, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	require.NoError(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1, "one LLM span per attempt")
	assert.Equal(t, trace.SpanLLM, spans[0].Type)
	require.NotNil(t, spans[0].LLM)
	assert.Equal(t, "openai", spans[0].LLM.Provider)
	assert.Equal(t, "chatcmpl-xyz", spans[0].LLM.TurnID, "provider response id captured as turn id")
	assert.Equal(t, 200, spans[0].StatusCode())

	usage := rt.LLMUsage()
	require.NotNil(t, usage, "non-streaming usage must land on the LLM span")
	assert.Equal(t, 10, usage.TotalTokens)
}

func TestForward_RecordsSessionTurnOnSuccess(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok"), Model: "gpt-4o", ResponseID: "resp_turn"}, nil).
		Once()

	store := &fakeSessionStore{}
	fwd := newTestForwarderWithStore(t, invoker, store)

	rt := trace.New("trace-1", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	_, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{GatewayID: gatewayID.String(), SessionID: "sess-1"},
	})
	require.NoError(t, err)

	require.Len(t, store.recorded, 1)
	assert.Equal(t, "resp_turn", store.recorded[0].TurnID)
	assert.Equal(t, "sess-1", store.recorded[0].SessionID)
	assert.Equal(t, appsession.Scope{GatewayID: gatewayID.String()}, store.recorded[0].Scope)
	assert.Equal(t, "openai", store.recorded[0].Provider)
}

func TestForward_RecordsSessionTurnWhenStreamCompletes(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	stream := func(yield func([]byte, error) bool) {
		yield([]byte("data: {}"), nil)
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: stream, ResponseID: "resp_stream"}, nil).
		Once()

	store := &fakeSessionStore{}
	fwd := newTestForwarderWithStore(t, invoker, store)

	rt := trace.New("trace-1", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	res, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			GatewayID: gatewayID.String(),
			SessionID: "sess-stream",
			Body:      []byte(`{"model":"gpt-4","stream":true}`),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)
	assert.Empty(t, store.recorded, "the turn is recorded once the stream is drained")

	for _, err := range res.Stream {
		require.NoError(t, err)
	}
	require.Len(t, store.recorded, 1)
	assert.Equal(t, "resp_stream", store.recorded[0].TurnID)
	assert.Equal(t, "sess-stream", store.recorded[0].SessionID)
}

func TestForward_DoesNotRecordSessionTurnOnErrorStatus(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 429, Body: []byte(`{}`), ResponseID: "resp_failed"}, nil).
		Once()

	store := &fakeSessionStore{}
	fwd := newTestForwarderWithStore(t, invoker, store)

	rt := trace.New("trace-1", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	_, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{GatewayID: gatewayID.String(), SessionID: "sess-1"},
	})
	require.NoError(t, err)
	assert.Empty(t, store.recorded, "a failed turn must not be indexed")
}

func TestForward_DoesNotRecordWithoutSession(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok"), ResponseID: "resp_turn"}, nil).
		Once()

	store := &fakeSessionStore{}
	fwd := newTestForwarderWithStore(t, invoker, store)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{GatewayID: gatewayID.String()},
	})
	require.NoError(t, err)
	assert.Empty(t, store.recorded, "no session id means nothing to record")
}

func TestForward_StampsContinuationFromStore(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	store := &fakeSessionStore{last: "resp_prev"}
	fwd := newTestForwarderWithStore(t, invoker, store)

	req := &infracontext.RequestContext{GatewayID: gatewayID.String(), SessionID: "sess-1"}
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: req})
	require.NoError(t, err)

	assert.Equal(t, "resp_prev", req.PreviousResponseID, "last turn id is stamped for the invoker to thread")
	assert.Equal(t, []appsession.Scope{{GatewayID: gatewayID.String()}}, store.looked)
}

type memSessionRepo struct {
	sessions map[string]sessiondomain.Session
	turns    map[string]string
}

func (m *memSessionRepo) Save(_ context.Context, s *sessiondomain.Session) error {
	m.sessions[fmt.Sprintf("session:%s:%s", s.GatewayID, s.ID)] = *s
	m.turns[fmt.Sprintf("session_turn:%s:%s", s.GatewayID, s.LastTurnID)] = s.ID
	return nil
}

func (m *memSessionRepo) Get(_ context.Context, gatewayID, sessionID string) (*sessiondomain.Session, error) {
	s, ok := m.sessions[fmt.Sprintf("session:%s:%s", gatewayID, sessionID)]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *memSessionRepo) FindSessionIDByTurn(_ context.Context, gatewayID, turnID string) (string, error) {
	return m.turns[fmt.Sprintf("session_turn:%s:%s", gatewayID, turnID)], nil
}

func TestForward_SessionTurnsStayWithTheirOwner(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))
	repo := &memSessionRepo{sessions: map[string]sessiondomain.Session{}, turns: map[string]string{}}
	store := appsession.NewService(repo, &config.Config{SessionStore: config.SessionStoreConfig{Enabled: true}}, nil)
	turns := 0
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, *registrydomain.Registry, *infracontext.RequestContext) (*appproxy.ProviderResponse, error) {
			turns++
			return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok"), ResponseID: fmt.Sprintf("resp_%d", turns)}, nil
		})
	fwd := newTestForwarderWithStore(t, invoker, store)
	send := func(owner string) string {
		req := &infracontext.RequestContext{GatewayID: gatewayID.String(), SessionID: "sess-1", OwnerID: owner}
		_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: req})
		require.NoError(t, err)
		return req.PreviousResponseID
	}

	assert.Empty(t, send("alice"))
	assert.Empty(t, send("bob"), "another owner's same session id never continues alice's turn")
	assert.Empty(t, send(""), "nor does an application key's")
	assert.Equal(t, "resp_1", send("alice"))
	assert.Equal(t, "resp_2", send("bob"))
	assert.Equal(t, "resp_3", send(""))
	assert.Contains(t, repo.sessions, "session:"+gatewayID.String()+":sess-1", "an application key keeps its session key")
	assert.Equal(t, "sess-1", repo.turns["session_turn:"+gatewayID.String()+":resp_6"])
}

func TestForward_BackendErrorStatusPassthrough(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	backendBody := []byte(`{"error":"rate limited"}`)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{
			StatusCode: 429,
			Headers:    map[string][]string{"Retry-After": {"5"}},
			Body:       backendBody,
		}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 429 {
		t.Fatalf("status = %d, want 429", res.StatusCode)
	}
	if string(res.Body) != string(backendBody) {
		t.Fatalf("body = %q, want %q", string(res.Body), string(backendBody))
	}
	if got := res.Headers["Retry-After"]; len(got) != 1 || got[0] != "5" {
		t.Fatalf("Retry-After header = %v, want [5]", got)
	}
}

func TestForward_StreamingRequestInvokesStream(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	stream := func(yield func([]byte, error) bool) {
		yield([]byte("data: {}"), nil)
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Stream: stream}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Body: []byte(`{"model":"gpt-4","stream":true}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward returned error: %v", err)
	}
	if res.Stream == nil {
		t.Fatal("expected ForwardResult.Stream to be set on the streaming branch")
	}
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

func TestForward_ProviderErrorPropagates(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)

	errProvider := errors.New("provider boom")
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, errProvider).
		Once()

	fwd := newTestForwarder(t, invoker)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if !errors.Is(err, errProvider) {
		t.Fatalf("err = %v, want errProvider", err)
	}
}

func TestForward_NoBackendsInPool(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID)

	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newTestForwarder(t, invoker)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{},
	})
	if !errors.Is(err, appproxy.ErrNoBackendsInPool) {
		t.Fatalf("err = %v, want ErrNoBackendsInPool", err)
	}
}

func TestForward_NilConsumer(t *testing.T) {
	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newTestForwarder(t, invoker)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Consumer:  nil,
		Request:   &infracontext.RequestContext{},
	})
	if !errors.Is(err, appproxy.ErrNoBackendsInPool) {
		t.Fatalf("err = %v, want ErrNoBackendsInPool", err)
	}
}

type fixedScorer struct{ score float64 }

func (f fixedScorer) Score(_ context.Context, _, _, _ string) (float64, error) { return f.score, nil }

func (fixedScorer) Configured() bool { return true }

func pricedBackendFor(gatewayID ids.GatewayID, provider string, discount float64) *registrydomain.Registry {
	bk := backendFor(gatewayID, provider)
	bk.LLMTarget.Pricing = &registrydomain.Pricing{Discount: discount}
	return bk
}

func smartRoutedConsumer(gatewayID ids.GatewayID, low, high *registrydomain.Registry) *appconsumer.RoutableConsumer {
	rc := routableConsumerWith(gatewayID, low, high)
	rc.Consumer.LBConfig = &domainconsumer.LBConfig{
		Enabled:   true,
		Algorithm: loadbalancer.AlgorithmSmartRouting,
		Members: []domainconsumer.LBPoolMember{
			{RegistryID: low.ID, Model: "model-low"},
			{RegistryID: high.ID, Model: "model-high"},
		},
		SmartRouting: &registrydomain.SmartRoutingConfig{
			Tiers: []registrydomain.SmartRoutingTier{
				{MinScore: 0, RegistryID: low.ID, Model: "model-low"},
				{MinScore: 0.5, RegistryID: high.ID, Model: "model-high"},
			},
		},
	}
	return rc
}

func newSmartRoutedForwarder(
	t *testing.T,
	invoker appproxy.ProviderInvoker,
	score float64,
	maxRetries int,
) appproxy.Forwarder {
	t.Helper()
	mgr := cache.NewTTLMapManager(time.Minute)
	cfg := &config.Config{}
	cfg.Provider.MaxRetries = maxRetries
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, fixedScorer{score: score}, newTestLogger()),
		newPermissiveCache(t), mgr, invoker, nil, nil, approuting.NewResolver(), nil, nil, cfg, newTestLogger(),
	)
}

func servedLLMAttrs(t *testing.T, rt *trace.RequestTrace) trace.LLMAttrs {
	t.Helper()
	var served *trace.LLMAttrs
	for _, span := range rt.Spans() {
		if span.Type != trace.SpanLLM {
			continue
		}
		if attrs, ok := span.LLMAttrsCopy(); ok {
			copied := attrs
			served = &copied
		}
	}
	require.NotNil(t, served, "expected at least one LLM span")
	return *served
}

// The metrics builder reads the last LLM span, so a retry that does not
// re-consult the balancer must still report the tier decision that picked
// the route.
func TestForward_SameBackendRetryKeepsTierDecision(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	low := backendFor(gatewayID, "openai")
	high := backendFor(gatewayID, "anthropic")
	rc := smartRoutedConsumer(gatewayID, low, high)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	rt := trace.New("trace-retry", trace.Metadata{GatewayID: gatewayID.String()})
	rt.SetGating(true, true)
	ctx := trace.NewContext(context.Background(), rt)

	res, err := newSmartRoutedForwarder(t, invoker, 0.9, 1).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"prompt":"hi"}`)},
	})
	require.NoError(t, err)
	require.Equal(t, 200, res.StatusCode)

	served := servedLLMAttrs(t, rt)
	assert.True(t, served.TierApplied, "the retry span must keep the tier decision")
	require.NotNil(t, served.Baseline)
	assert.Equal(t, "model-high", served.Baseline.Model)
}

// The served registry's pricing overlay only reaches the metrics builder on the
// buffered path if the forwarder stamps it here: the metrics middleware builds
// its own request context, which carries no pricing.
func TestForward_StampsServedAndBaselinePricingOnSpan(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	low := pricedBackendFor(gatewayID, "openai", 0.2)
	high := pricedBackendFor(gatewayID, "anthropic", 0.4)
	rc := smartRoutedConsumer(gatewayID, low, high)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	rt := trace.New("trace-pricing", trace.Metadata{GatewayID: gatewayID.String()})
	rt.SetGating(true, true)
	ctx := trace.NewContext(context.Background(), rt)

	res, err := newSmartRoutedForwarder(t, invoker, 0.1, 0).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"prompt":"hi"}`)},
	})
	require.NoError(t, err)
	require.Equal(t, 200, res.StatusCode)

	served := servedLLMAttrs(t, rt)
	require.NotNil(t, served.ServedPricing, "the served registry's overlay must ride the span")
	assert.InDelta(t, 0.2, served.ServedPricing.Discount, 1e-12)
	require.NotNil(t, served.Baseline)
	require.NotNil(t, served.Baseline.Pricing,
		"the baseline is priced with its own registry's overlay, not the served one")
	assert.InDelta(t, 0.4, served.Baseline.Pricing.Discount, 1e-12)
}

// A fallback-chain hop never consults the strategy, so it must not inherit the
// tier decision made for the pool route it replaced.
func TestForward_FallbackChainHopDropsTierDecision(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	low := backendFor(gatewayID, "openai")
	high := backendFor(gatewayID, "anthropic")
	chainBk := backendFor(gatewayID, "bedrock")
	rc := smartRoutedConsumer(gatewayID, low, high)
	rc.Consumer.Fallback = enabledFallback(chainBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{chainBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Times(2)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("recovered")}, nil).
		Once()

	rt := trace.New("trace-chain", trace.Metadata{GatewayID: gatewayID.String()})
	rt.SetGating(true, true)
	ctx := trace.NewContext(context.Background(), rt)

	res, err := newSmartRoutedForwarder(t, invoker, 0.9, 0).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"prompt":"hi"}`)},
	})
	require.NoError(t, err)
	require.Equal(t, 200, res.StatusCode)

	served := servedLLMAttrs(t, rt)
	assert.True(t, served.Fallback, "expected the chain hop to be the served attempt")
	assert.False(t, served.TierApplied, "a chain hop must not inherit a tier decision")
}

func TestForward_RefusesAChatBodyWithAmbiguousKeys(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))
	fwd := newTestForwarder(t, proxymocks.NewProviderInvoker(t))

	for name, req := range map[string]*infracontext.RequestContext{
		"chat tools and TOOLS": {ProxyCapability: "chat", SourceFormat: "openai",
			Body: []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[],"TOOLS":[]}`)},
		"responses repeated input": {ProxyCapability: "chat", SourceFormat: "openai_responses",
			Body: []byte(`{"model":"gpt-5","input":"evil","input":"hi"}`)},
		"anthropic Content": {ProxyCapability: "chat", SourceFormat: "anthropic",
			Body: []byte(`{"model":"c","max_tokens":1,"messages":[{"role":"user","content":"evil","Content":"hi"}]}`)},
		"no capability, chat format": {SourceFormat: "google",
			Body: []byte(`{"contents":[{"role":"user","parts":[{"text":"evil","Text":"hi"}]}]}`)},
		"gemini both spellings": {ProxyCapability: "chat", SourceFormat: "google",
			Body: []byte(`{"contents":[],"systemInstruction":{"parts":[{"text":"a"}]},"system_instruction":{"parts":[{"text":"b"}]}}`)},
		"byte order mark": {ProxyCapability: "chat", SourceFormat: "openai",
			Body: []byte("\xef\xbb\xbf{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}")},
		"not valid json": {ProxyCapability: "chat", SourceFormat: "openai",
			Body: []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":NaN}`)},
		"too deep": {ProxyCapability: "chat", SourceFormat: "openai",
			Body: []byte(`{"model":"gpt-4o","messages":` + strings.Repeat("[", 1<<20))},
	} {
		_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: req})
		assert.ErrorIs(t, err, appproxy.ErrAmbiguousRequestBody, name)
	}
}

func TestForward_LetsOtherBodiesThrough(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))

	for name, req := range map[string]*infracontext.RequestContext{
		"schema with case variants": {ProxyCapability: "chat", SourceFormat: "openai",
			Body: []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{"Name":{},"name":{}}}}}]}`)},
		"tool message parts with case variants": {ProxyCapability: "chat", SourceFormat: "openai",
			Body: []byte(`{"model":"gpt-4o","messages":[{"role":"tool","tool_call_id":"c","content":[{"Result":1,"result":2}]}]}`)},
		"anthropic input_examples": {ProxyCapability: "chat", SourceFormat: "anthropic",
			Body: []byte(`{"model":"c","max_tokens":1,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{},"input_examples":[{"A":1,"a":2}]}]}`)},
		"embeddings": {ProxyCapability: "embeddings", SourceFormat: "openai_embeddings",
			Body: []byte(`{"model":"e","input":"a","Input":"b"}`)},
	} {
		invoker := proxymocks.NewProviderInvoker(t)
		invoker.EXPECT().
			Invoke(mock.Anything, mock.Anything, mock.Anything).
			Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
			Once()
		res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: req})
		require.NoError(t, err, name)
		assert.Equal(t, 200, res.StatusCode, name)
	}
}

func invokerByProvider(t *testing.T, status map[string]int) (*proxymocks.ProviderInvoker, *[]string) {
	t.Helper()
	return invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: status[provider], Body: []byte(provider)}, nil
	})
}

func TestForward_ResolvedRoutingNeverReachesASubstitutedProvider(t *testing.T) {
	userOpenAI := storeGrant{name: "D", level: levelUser, priority: 1, regs: []storeRegistry{{provider: "openai", allowed: []string{"gpt6"}}}}
	pooled := storeGrant{name: "P", level: levelGroup, priority: 1, pool: "fast", regs: []storeRegistry{
		{provider: "openai", def: "gpt-4.1", pooled: true}, {provider: "mistral", def: "mistral-large", pooled: true},
	}}
	balanced := storeGrant{name: "A", level: levelGroup, priority: 1, regs: []storeRegistry{
		{provider: "openai", def: "gpt-4.1"}, {provider: "mistral", def: "mistral-large"},
	}}
	withFallback := storeGrant{name: "F", level: levelGroup, priority: 1, regs: []storeRegistry{
		{provider: "mistral", def: "mistral-large"}, {provider: "openai", fallback: true},
	}}
	cases := []struct {
		name   string
		grants []storeGrant
		model  string
		want   string
	}{
		{name: "pool member on a substituted provider", grants: []storeGrant{userOpenAI, pooled}, model: "pool:fast", want: "P"},
		{name: "auto default on a substituted provider", grants: []storeGrant{userOpenAI, balanced}, model: "auto", want: "A"},
		{name: "fallback on a substituted provider", grants: []storeGrant{userOpenAI, withFallback}, model: "auto", want: "F"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newStoreFixture(tc.grants...)
			req := storeRequest(tc.model, "", "")
			sel, err := fx.choose(newStoreSelector(workedCatalog), req)
			require.NoError(t, err)
			require.Equal(t, tc.want, sel.Link.Consumer.Consumer.Name)
			sel.Link.Consumer.Consumer.Fallback = enabledFallback()
			invoker, invoked := invokerByProvider(t, map[string]int{"mistral": 503, "openai": 200})
			fwd := newTestForwarder(t, invoker)
			for range 3 {
				res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
					GatewayID: fx.data.GatewayID, Consumer: sel.Link.Consumer, Data: fx.data, Request: req,
					Resolved: &sel.ResolvedRouting, Prechecked: true,
				})
				require.NoError(t, err)
				assert.Equal(t, 503, res.StatusCode)
				assert.Equal(t, "mistral-large", req.DefaultModel)
			}
			assert.Equal(t, []string{"mistral", "mistral", "mistral"}, *invoked)
		})
	}
}

func TestForward_PrecheckedIsExplicit(t *testing.T) {
	fx := newStoreFixture(grantB)
	ambiguous := []byte(`{"model":"opus-4.8","model":"opus-5.5"}`)
	sel, err := fx.choose(newStoreSelector(workedCatalog), storeRequest("opus-4.8", "", ""))
	require.NoError(t, err)

	t.Run("prechecked skips the body check and the plan limit", func(t *testing.T) {
		invoker, invoked := invokerByProvider(t, map[string]int{"anthropic": 200})
		fwd := newTestForwarderWithLimiter(t, invoker, ratelimitmocks.NewChecker(t))
		req := &infracontext.RequestContext{ProxyCapability: "chat", SourceFormat: "openai", Body: ambiguous}
		res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: fx.data.GatewayID, Consumer: sel.Link.Consumer, Data: fx.data, Request: req,
			Resolved: &sel.ResolvedRouting, Prechecked: true,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
		assert.Equal(t, []string{"anthropic"}, *invoked)
	})

	t.Run("a resolved request that is not prechecked is charged", func(t *testing.T) {
		limiter := ratelimitmocks.NewChecker(t)
		limiter.EXPECT().Check(mock.Anything, fx.data.GatewayID).
			Return(&ratelimitapp.Exceeded{Reason: ratelimitapp.ReasonQuota, Limit: 1, RetryAfter: time.Second}).Once()
		fwd := newTestForwarderWithLimiter(t, proxymocks.NewProviderInvoker(t), limiter)
		res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: fx.data.GatewayID, Consumer: sel.Link.Consumer, Data: fx.data, Request: storeRequest("opus-4.8", "", ""),
			Resolved: &sel.ResolvedRouting,
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
	})
}

func TestPrecheck_RefusesAnAmbiguousBodyBeforeTheRateLimit(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	fwd := newTestForwarderWithLimiter(t, proxymocks.NewProviderInvoker(t), ratelimitmocks.NewChecker(t))
	res, err := fwd.Precheck(context.Background(), gatewayID, &infracontext.RequestContext{
		ProxyCapability: "chat", SourceFormat: "openai", Body: []byte(`{"model":"a","model":"b"}`),
	})
	require.ErrorIs(t, err, appproxy.ErrAmbiguousRequestBody)
	assert.Nil(t, res)

	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, gatewayID).Return(nil).Once()
	res, err = newTestForwarderWithLimiter(t, proxymocks.NewProviderInvoker(t), limiter).
		Precheck(context.Background(), gatewayID, &infracontext.RequestContext{ProxyCapability: "chat", SourceFormat: "openai", Body: chatBody("a")})
	require.NoError(t, err)
	assert.Nil(t, res)
}

func TestForward_ServesTheStoreSelection(t *testing.T) {
	mistralA := storeGrant{name: "A", level: levelGroup, priority: 1,
		regs: []storeRegistry{{provider: "mistral"}, {provider: "openai", fallback: true}}}
	cases := []struct {
		name    string
		grants  []storeGrant
		catalog storeCatalog
		model   string
		want    []string
		status  int
	}{
		{name: "substituted fallback is not used", grants: []storeGrant{mistralA, grantD}, catalog: workedCatalog,
			model: "mistral-large", want: []string{"mistral"}, status: 503},
		{name: "fallback serves the selected consumer", grants: []storeGrant{grantA, grantB, grantC},
			catalog: storeCatalog{"openai": {"gpt-4.1"}}, model: "gpt-4.1", want: []string{"openai", "deepseek"}, status: 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newStoreFixture(tc.grants...)
			req := storeRequest(tc.model, "", "")
			sel, err := fx.choose(newStoreSelector(tc.catalog), req)
			require.NoError(t, err)
			require.Equal(t, "A", sel.Link.Consumer.Consumer.Name)
			invoker, invoked := invokerByProvider(t, map[string]int{"mistral": 503, "openai": 503, "deepseek": 200})
			fwd := newTestForwarderWithLimiter(t, invoker, ratelimitmocks.NewChecker(t))
			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: fx.data.GatewayID, Consumer: sel.Link.Consumer, Data: fx.data, Request: req,
				Resolved: &sel.ResolvedRouting, Prechecked: true,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.status, res.StatusCode)
			assert.Equal(t, tc.want, *invoked)
			assert.Equal(t, tc.model, req.RequestedModel)
		})
	}
}

func TestForward_StoreConsumerSharesOneBalancerAcrossOwners(t *testing.T) {
	fx := newStoreFixture(grantB)
	mgr := cache.NewTTLMapManager(time.Minute)
	invoker, invoked := invokerByProvider(t, map[string]int{"anthropic": 200})
	fwd := appproxy.NewForwarder(loadbalancer.NewBaseFactory(nil, nil, nil, nil), newPermissiveCache(t), mgr, invoker,
		nil, nil, approuting.NewResolver(), nil, nil, nil, newTestLogger())
	for _, owner := range []string{"alice", "bob"} {
		req := storeRequest("", "", "")
		req.AuthID, req.OwnerID = ids.New[ids.AuthKind]().String(), owner
		sel, err := fx.choose(newStoreSelector(workedCatalog), req)
		require.NoError(t, err)
		_, err = fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: fx.data.GatewayID, Consumer: sel.Link.Consumer, Data: fx.data, Request: req,
			Resolved: &sel.ResolvedRouting, Prechecked: true,
		})
		require.NoError(t, err)
	}
	served := fx.data.StoreLinks(fx.authID)[0].Consumer.Consumer
	balancers := mgr.GetTTLMap(cache.LoadBalancerTTLName)
	_, ok := balancers.Get(served.GatewayID.String() + ":" + served.ID.String())
	assert.True(t, ok)
	assert.Equal(t, 1, balancers.Len())
	assert.Equal(t, []string{"anthropic", "anthropic"}, *invoked)
}

func TestForward_StoreModelMissPointsAtTheStoreListing(t *testing.T) {
	fx := newStoreFixture(grantD)
	req := storeRequest("gpt6", "", "")
	sel, err := fx.choose(newStoreSelector(workedCatalog), req)
	require.NoError(t, err)
	sel.Link.Consumer.Consumer.Slug = "pers0001"
	invoker, _ := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: http.StatusNotFound, Body: modelNotFoundBody(provider)}, nil
	})
	_, err = newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: fx.data.GatewayID, Consumer: sel.Link.Consumer, Data: fx.data, Request: req,
		Resolved: &sel.ResolvedRouting, RouteSlug: domainconsumer.StoreSlug, Prechecked: true,
	})
	require.ErrorIs(t, err, routingdomain.ErrNoRegistryServesModel)
	assert.Contains(t, err.Error(), "GET /store/v1/models")
	assert.NotContains(t, err.Error(), "pers0001")
}
