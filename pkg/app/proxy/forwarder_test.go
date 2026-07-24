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
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	appsession "github.com/NeuralTrust/TrustGate/pkg/app/session"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
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
		Name:      "test-backend",
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
		newPermissiveCache(t), mgr, invoker, nil, nil, approuting.NewResolver(), limiter, nil, newTestLogger(),
	)
}

type fakeSessionStore struct {
	last     string
	recorded []appsession.RecordInput
}

func (f *fakeSessionStore) Record(_ context.Context, in appsession.RecordInput) {
	f.recorded = append(f.recorded, in)
}

func (f *fakeSessionStore) LastTurnID(_ context.Context, _, _ string) string {
	return f.last
}

func newTestForwarderWithStore(t *testing.T, invoker appproxy.ProviderInvoker, store appsession.Store) appproxy.Forwarder {
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, store, approuting.NewResolver(), nil, nil, newTestLogger(),
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
	assert.Equal(t, gatewayID.String(), store.recorded[0].GatewayID)
	assert.Equal(t, "openai", store.recorded[0].Provider)
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
