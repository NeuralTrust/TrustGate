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
	"sync"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type managedLimitStub map[string]bool

func (m managedLimitStub) ManagedBlocked(tenantID string) bool { return m[tenantID] }

func newManagedForwarder(t *testing.T, invoker appproxy.ProviderInvoker, limit appproxy.ManagedLimit) appproxy.Forwarder {
	return newManagedForwarderWithExecutor(t, invoker, nil, limit)
}

func newManagedForwarderWithExecutor(t *testing.T, invoker appproxy.ProviderInvoker, executor appplugins.Executor, limit appproxy.ManagedLimit) appproxy.Forwarder {
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil),
		newPermissiveCache(t), cache.NewTTLMapManager(time.Minute), invoker, executor, nil, approuting.NewResolver(), nil, nil, nil, newTestLogger(),
		appproxy.WithManagedLimit(limit),
	)
}

type stageCounter struct {
	mu     sync.Mutex
	stages map[string]int
}

func (s *stageCounter) RunStage(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stages == nil {
		s.stages = map[string]int{}
	}
	s.stages[string(in.Stage)]++
	return &appplugins.StageOutcome{}, nil
}

func (s *stageCounter) count(stage string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stages[stage]
}

func tenantContext(tenantID string) context.Context {
	return appgateway.WithGateway(context.Background(), &gatewaydomain.Gateway{
		Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: tenantID},
	})
}

func managedBackendFor(gatewayID ids.GatewayID) *registrydomain.Registry {
	bk := backendFor(gatewayID, "openai")
	bk.Managed = true
	bk.LLMTarget.Auth = nil
	return bk
}

func TestForward_SkipsManagedRegistriesOfABlockedTenant(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	managed := managedBackendFor(gatewayID)
	own := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, managed, own)

	invoker := proxymocks.NewProviderInvoker(t)
	var served []ids.RegistryID
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, reg *registrydomain.Registry, _ *infracontext.RequestContext) {
			served = append(served, reg.ID)
		}).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil)

	fwd := newManagedForwarder(t, invoker, managedLimitStub{"tenant-1": true})
	for range 4 {
		res, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
		require.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	}
	require.NotEmpty(t, served)
	for _, id := range served {
		assert.Equal(t, own.ID, id, "a blocked tenant's managed registry must never be called")
	}
}

func TestForward_RefusesWhenOnlyManagedRegistriesAreLeft(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, managedBackendFor(gatewayID))

	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newManagedForwarder(t, invoker, managedLimitStub{"tenant-1": true})
	_, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
	assert.True(t, errors.Is(err, appproxy.ErrManagedLimitReached), "err = %v", err)
	invoker.AssertNotCalled(t, "Invoke", mock.Anything, mock.Anything, mock.Anything)
}

func TestForward_FallsBackFromAManagedRegistryToTheChain(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, managedBackendFor(gatewayID))
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{fallbackBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, fallbackBk, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("fallback")}, nil).
		Once()

	fwd := newManagedForwarder(t, invoker, managedLimitStub{"tenant-1": true})
	res, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
	require.NoError(t, err)
	assert.Equal(t, "fallback", string(res.Body))
}

func TestForward_ServesManagedRegistriesOfAHealthyTenant(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	managed := managedBackendFor(gatewayID)
	rc := routableConsumerWith(gatewayID, managed)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, managed, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newManagedForwarder(t, invoker, managedLimitStub{"other-tenant": true})
	res, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}

func TestForward_RefusesBeforeThePreRequestPluginsWhenOnlyManagedRegistriesAreLeft(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, managedBackendFor(gatewayID), managedBackendFor(gatewayID))

	invoker := proxymocks.NewProviderInvoker(t)
	plugins := &stageCounter{}
	fwd := newManagedForwarderWithExecutor(t, invoker, plugins, managedLimitStub{"tenant-1": true})
	_, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
	assert.True(t, errors.Is(err, appproxy.ErrManagedLimitReached), "err = %v", err)
	assert.Zero(t, plugins.count("pre_request"), "no plugin may run for a request that is refused")
	invoker.AssertNotCalled(t, "Invoke", mock.Anything, mock.Anything, mock.Anything)
}

func TestForward_RunsThePreRequestPluginsWhenAnOwnRegistryIsReachable(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	own := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, managedBackendFor(gatewayID), own)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, own, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("own")}, nil)
	plugins := &stageCounter{}
	fwd := newManagedForwarderWithExecutor(t, invoker, plugins, managedLimitStub{"tenant-1": true})
	for range 2 {
		res, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
		require.NoError(t, err)
		assert.Equal(t, "own", string(res.Body))
	}
	assert.Equal(t, 2, plugins.count("pre_request"))
}

func TestForward_KeepsThePreRequestPluginsWhenAFallbackIsNotManaged(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	fallbackBk := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, managedBackendFor(gatewayID))
	rc.Consumer.Fallback = enabledFallback(fallbackBk.ID)
	rc.FallbackBackends = []*registrydomain.Registry{fallbackBk}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, fallbackBk, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("fallback")}, nil).
		Once()
	plugins := &stageCounter{}
	fwd := newManagedForwarderWithExecutor(t, invoker, plugins, managedLimitStub{"tenant-1": true})
	res, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
	require.NoError(t, err)
	assert.Equal(t, "fallback", string(res.Body))
	assert.Equal(t, 1, plugins.count("pre_request"))
}

func TestForward_KeepsThePreRequestPluginsWhenTheFallbackSetIsUnknown(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, managedBackendFor(gatewayID))
	rc.Consumer.Fallback = enabledFallback(ids.New[ids.RegistryKind]())

	invoker := proxymocks.NewProviderInvoker(t)
	plugins := &stageCounter{}
	fwd := newManagedForwarderWithExecutor(t, invoker, plugins, managedLimitStub{"tenant-1": true})
	_, err := fwd.Forward(tenantContext("tenant-1"), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{}})
	assert.True(t, errors.Is(err, appproxy.ErrManagedLimitReached), "err = %v", err)
	assert.Equal(t, 1, plugins.count("pre_request"), "an unresolved fallback chain keeps the request on the slow path")
}
