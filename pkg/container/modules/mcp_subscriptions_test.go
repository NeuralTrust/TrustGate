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

package modules

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/stretchr/testify/require"
	"go.uber.org/dig"
)

func TestMCPAppsProductionPipelineIsNotReady(t *testing.T) {
	require.False(t, mcpAppsPipelineReady)
}

func TestProvideAppsMetadataPolicy(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.MCPApps = config.MCPAppsConfig{
		MaxCSPOriginsPerDirective: 1,
		MaxCSPOriginsTotal:        2,
		AllowedOriginPatterns:     []string{"https://cdn.example.com"},
		AllowedPermissions:        []string{"camera"},
	}
	policy, err := provideAppsMetadataPolicy(cfg)
	require.NoError(t, err)
	cfg.Server.MCPApps.AllowedOriginPatterns[0] = "https://changed.example.com"
	cfg.Server.MCPApps.AllowedPermissions[0] = "microphone"
	require.NoError(t, appmcp.ValidateResourceAppsMetadata(map[string]any{
		"csp":         map[string]any{"resourceDomains": []any{"https://cdn.example.com"}},
		"permissions": map[string]any{"camera": map[string]any{}},
	}, policy))

	cfg.Server.MCPApps.MaxCSPOriginsPerDirective = 0
	_, err = provideAppsMetadataPolicy(cfg)
	require.ErrorIs(t, err, appmcp.ErrInvalidAppsMetadata)
}

func TestProvideAppsListPolicyRemainsDormant(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.MCPApps.Enabled = true
	cfg.Server.MCPApps.MaxCSPOriginsPerDirective = 1
	cfg.Server.MCPApps.MaxCSPOriginsTotal = 1
	metadata, err := provideAppsMetadataPolicy(cfg)
	require.NoError(t, err)
	policy := provideAppsListPolicy(cfg, metadata)
	var tool appmcp.Tool
	require.NoError(t, json.Unmarshal([]byte(`{"name":"invalid","_meta":{"ui":"bad"}}`), &tool))
	input := []appmcp.Tool{tool}
	filtered, outcome := policy.FilterTools(input)
	require.Len(t, filtered, 1)
	require.Same(t, &input[0], &filtered[0])
	require.Zero(t, outcome.Dropped)
}

func subscriptionsConfig(enabled bool) *config.Config {
	cfg := &config.Config{}
	cfg.Server.MCPSubscriptions = config.MCPSubscriptionsConfig{
		Enabled:              enabled,
		MaxLifetime:          10 * time.Minute,
		ReauthInterval:       time.Minute,
		Keepalive:            15 * time.Second,
		MaxEventBytes:        8192,
		MaxURIs:              32,
		MaxStreams:           1024,
		MaxPerConsumer:       16,
		MaxPerPrincipal:      4,
		MaxUpstreamListeners: 32,
		MaxUpstreamPerOrigin: 8,
		StreamQueue:          8,
		UpstreamIdleTimeout:  time.Minute,
		ReconnectMaxAttempts: 3,
		ReconnectBackoffMin:  time.Second,
		ReconnectBackoffMax:  10 * time.Second,
	}
	return cfg
}

func TestSubscriptionUpstreamDigGraphModes(t *testing.T) {
	tests := []struct {
		name           string
		northbound     bool
		upstream       bool
		wantNorthbound bool
		wantUpstream   bool
	}{
		{name: "northbound off"},
		{name: "northbound on upstream off", northbound: true, wantNorthbound: true},
		{name: "both on", northbound: true, upstream: true, wantNorthbound: true, wantUpstream: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := subscriptionsConfig(test.northbound)
			cfg.Server.MCPSubscriptions.UpstreamEnabled = test.upstream
			c, err := container.New()
			require.NoError(t, err)
			require.NoError(t, c.Provide(func() *config.Config { return cfg }))
			require.NoError(t, c.Provide(func() appconsumer.DataFinder { return nil }))
			require.NoError(t, c.Provide(func() appmcp.RoleScoper { return nil }))
			require.NoError(t, c.Provide(func() appmcp.Composer { return nil }))
			require.NoError(t, c.Provide(func() *appmcp.PluginRunner { return nil }))
			require.NoError(t, c.Provide(func() appmcp.CredentialResolver { return nil }))
			require.NoError(t, c.Provide(provideSubscriptionRegistry))
			require.NoError(t, c.Provide(provideSubscriptionConnector))
			require.NoError(t, c.Provide(provideSubscriptionTargetResolver))
			require.NoError(t, c.Provide(provideSubscriptionPolicy))
			require.NoError(t, c.Provide(provideSubscriptionMultiplexer))

			var graph struct {
				dig.In
				Registry    *appmcp.SubscriptionRegistry
				Connector   appmcp.SubscriptionConnector
				Targets     appmcp.SubscriptionTargetResolver
				Policy      appmcp.SubscriptionPolicy
				Multiplexer *appmcp.SubscriptionMultiplexer
			}
			require.NoError(t, c.Invoke(func(in struct {
				dig.In
				Registry    *appmcp.SubscriptionRegistry
				Connector   appmcp.SubscriptionConnector
				Targets     appmcp.SubscriptionTargetResolver
				Policy      appmcp.SubscriptionPolicy
				Multiplexer *appmcp.SubscriptionMultiplexer
			}) {
				graph = in
			}))
			require.Equal(t, test.wantNorthbound, graph.Registry != nil)
			require.Equal(t, test.wantNorthbound, graph.Policy != nil)
			require.Equal(t, test.wantUpstream, graph.Connector != nil)
			require.Equal(t, test.wantUpstream, graph.Targets != nil)
			require.Equal(t, test.wantUpstream, graph.Multiplexer != nil)
			if graph.Multiplexer != nil {
				require.NoError(t, graph.Multiplexer.Close(context.Background()))
			}
		})
	}
}

func TestSubscriptionUpstreamDigGraphExposesOneMultiplexer(t *testing.T) {
	cfg := subscriptionsConfig(true)
	cfg.Server.MCPSubscriptions.UpstreamEnabled = true
	c, err := container.New()
	require.NoError(t, err)
	require.NoError(t, c.Provide(func() *config.Config { return cfg }))
	require.NoError(t, c.Provide(func() appmcp.SubscriptionPolicy {
		return appmcp.NewSubscriptionPolicyWithUpstream(nil, nil, nil, nil, nil, provideSubscriptionConnector(cfg))
	}))
	require.NoError(t, c.Provide(provideSubscriptionConnector))
	require.NoError(t, c.Provide(func() appmcp.SubscriptionTargetResolver {
		return appmcp.NewSubscriptionTargetResolver(nil, nil, nil)
	}))
	require.NoError(t, c.Provide(provideSubscriptionMultiplexer))

	var first, second *appmcp.SubscriptionMultiplexer
	require.NoError(t, c.Invoke(func(m *appmcp.SubscriptionMultiplexer) { first = m }))
	require.NoError(t, c.Invoke(func(m *appmcp.SubscriptionMultiplexer) { second = m }))
	require.Same(t, first, second)
	require.NoError(t, first.Close(context.Background()))
}

// The kill switch has to leave the process exactly as it was: no accountant, no
// drain hook, and a support value whose predicate is false.
func TestProvideSubscriptionRegistryFollowsTheKillSwitch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		enabled    bool
		wantOn     bool
		wantHook   bool
		wantExists bool
	}{
		{name: "disabled"},
		{name: "enabled", enabled: true, wantOn: true, wantHook: true, wantExists: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := subscriptionsConfig(tc.enabled)
			registry := provideSubscriptionRegistry(cfg)
			policy := provideSubscriptionPolicy(cfg, nil, nil, nil, nil, nil, nil)

			require.Equal(t, tc.wantExists, registry != nil)
			require.Equal(t, tc.wantExists, policy != nil,
				"a disabled feature must provide a nil interface, not a typed nil")
			require.Equal(t, tc.wantHook, subscriptionDrainHook(registry) != nil)

			support := subscriptionsSupport(cfg.Server.MCPSubscriptions, registry, policy, nil, nil, nil)
			require.Equal(t, tc.wantOn, support.Enabled())
		})
	}
}

// A lease that cannot re-authorize must never be served, so the predicate needs
// the policy as much as it needs the accountant.
func TestSubscriptionsSupportNeedsBothTheRegistryAndThePolicy(t *testing.T) {
	t.Parallel()
	cfg := subscriptionsConfig(true)
	registry := provideSubscriptionRegistry(cfg)
	policy := provideSubscriptionPolicy(cfg, nil, nil, nil, nil, nil, nil)

	tests := []struct {
		name         string
		withPolicy   bool
		withRegistry bool
		want         bool
	}{
		{name: "neither"},
		{name: "registry only", withRegistry: true},
		{name: "policy only", withPolicy: true},
		{name: "both", withPolicy: true, withRegistry: true, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			support := subscriptionsSupport(cfg.Server.MCPSubscriptions, nil, nil, nil, nil, nil)
			if tc.withRegistry {
				support.Registry = registry
			}
			if tc.withPolicy {
				support.Policy = policy
			}
			require.Equal(t, tc.want, support.Enabled())
		})
	}
}

func TestProvideSubscriptionRegistryCarriesTheConfiguredCaps(t *testing.T) {
	t.Parallel()
	cfg := subscriptionsConfig(true)
	cfg.Server.MCPSubscriptions.MaxStreams = 1

	registry := provideSubscriptionRegistry(cfg)
	require.NotNil(t, registry)

	first, err := registry.Claim(context.Background(), appmcp.IsolationKey{ConsumerID: "c1"})
	require.NoError(t, err)
	_, err = registry.Claim(context.Background(), appmcp.IsolationKey{ConsumerID: "c2"})
	require.ErrorIs(t, err, appmcp.ErrSubscriptionRefused)
	first.Release()
}

// The hook is the registry's own Drain, so shutdown cancels every live lease.
func TestSubscriptionDrainHookCancelsLiveLeases(t *testing.T) {
	t.Parallel()
	registry := provideSubscriptionRegistry(subscriptionsConfig(true))
	require.NotNil(t, registry)

	lease, err := registry.Claim(context.Background(), appmcp.IsolationKey{ConsumerID: "c1"})
	require.NoError(t, err)
	go func() {
		<-lease.Context().Done()
		lease.Release()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, subscriptionDrainHook(registry)(ctx))
	require.Equal(t, 0, registry.Live())
}
