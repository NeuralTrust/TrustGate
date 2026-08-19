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
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type subscriptionTargetFinder struct {
	data *appconsumer.Data
	err  error
}

func (f subscriptionTargetFinder) FindByGateway(context.Context, ids.GatewayID) (*appconsumer.Data, error) {
	return f.data, f.err
}

type subscriptionTargetScoper struct {
	scoped *appconsumer.RoutableConsumer
	err    error
}

func (s subscriptionTargetScoper) Scope(
	context.Context,
	*appconsumer.RoutableConsumer,
	*appconsumer.Data,
) (*appconsumer.RoutableConsumer, error) {
	return s.scoped, s.err
}

type subscriptionTargetCredentials struct {
	err error
}

func (c subscriptionTargetCredentials) Apply(
	_ context.Context,
	_ *appconsumer.RoutableConsumer,
	_ *registrydomain.Registry,
	target *Target,
) error {
	if c.err != nil {
		return c.err
	}
	target.Headers["Authorization"] = "Bearer resolved"
	return nil
}

func TestSubscriptionTargetResolverUsesFreshScopeAndCredentials(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	modernID := ids.New[ids.RegistryKind]()
	legacyID := ids.New[ids.RegistryKind]()
	deniedID := ids.New[ids.RegistryKind]()
	consumer := &consumerdomain.Consumer{
		ID:        consumerID,
		GatewayID: gatewayID,
		Type:      consumerdomain.TypeMCP,
		Slug:      "agent",
		Active:    true,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: modernID, Tool: "*"},
			{RegistryID: modernID, Resource: "file://*"},
			{RegistryID: legacyID, Prompt: "*"},
			{RegistryID: deniedID, Tool: "*"},
		}},
	}
	modern := subscriptionRegistry(modernID, registrydomain.MCPProtocolModeModern)
	legacy := subscriptionRegistry(legacyID, registrydomain.MCPProtocolModeLegacy)
	denied := subscriptionRegistry(deniedID, registrydomain.MCPProtocolModeModern)
	original := appconsumer.RoutableConsumer{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{modern, legacy, denied},
	}
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{original})
	scoped := &appconsumer.RoutableConsumer{Consumer: consumer, Registries: []*registrydomain.Registry{modern, legacy}}
	resolver := NewSubscriptionTargetResolver(
		subscriptionTargetFinder{data: data},
		subscriptionTargetScoper{scoped: scoped},
		subscriptionTargetCredentials{},
	)
	ctx := appconsumer.WithAuthID(context.Background(), authID)
	requests, err := resolver.Resolve(
		ctx,
		gatewayID,
		"/agent/mcp",
		NewHonouredSet(
			NotificationToolsListChanged,
			NotificationPromptsListChanged,
			NotificationResourcesListChanged,
		),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	request := requests[0]
	if request.Identity.GatewayID != gatewayID.String() ||
		request.Identity.ConsumerID != consumerID.String() ||
		request.Identity.AuthID != authID.String() ||
		request.Identity.RegistryID != modernID.String() {
		t.Fatalf("identity = %+v", request.Identity)
	}
	if request.Target.RegistryTargetID != modernID.String() {
		t.Fatalf("registry target id = %q", request.Target.RegistryTargetID)
	}
	if request.Target.Headers["Authorization"] != "Bearer resolved" {
		t.Fatalf("resolved headers = %v", request.Target.Headers)
	}
	if !request.Requested.Has(NotificationToolsListChanged) ||
		!request.Requested.Has(NotificationResourcesListChanged) ||
		request.Requested.Has(NotificationPromptsListChanged) {
		t.Fatalf("requested = %v", request.Requested.Kinds())
	}
}

func TestSubscriptionTargetResolverPreservesResolutionErrors(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	consumer := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gatewayID,
		Type:      consumerdomain.TypeMCP,
		Slug:      "agent",
		Active:    true,
		MCP:       &consumerdomain.MCPPolicy{},
	}
	registry := subscriptionRegistry(registryID, registrydomain.MCPProtocolModeModern)
	rc := appconsumer.RoutableConsumer{Consumer: consumer, Registries: []*registrydomain.Registry{registry}}
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{rc})
	wantErr := errors.New("credential backend unavailable")
	resolver := NewSubscriptionTargetResolver(
		subscriptionTargetFinder{data: data},
		subscriptionTargetScoper{scoped: &rc},
		subscriptionTargetCredentials{err: wantErr},
	)
	_, err := resolver.Resolve(
		context.Background(),
		gatewayID,
		"/agent/mcp",
		NewHonouredSet(NotificationToolsListChanged),
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped resolution error", err)
	}
	if errors.Is(err, ErrSubscriptionUnsupported) {
		t.Fatalf("resolution error collapsed to unsupported: %v", err)
	}
}

func TestSubscriptionTargetResolverExcludesLegacyOnlyConsumer(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	consumer := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gatewayID,
		Type:      consumerdomain.TypeMCP,
		Slug:      "agent",
		Active:    true,
		MCP: &consumerdomain.MCPPolicy{
			ProtocolAcceptance: consumerdomain.ProtocolAcceptanceLegacyOnly,
		},
	}
	registry := subscriptionRegistry(registryID, registrydomain.MCPProtocolModeModern)
	rc := appconsumer.RoutableConsumer{Consumer: consumer, Registries: []*registrydomain.Registry{registry}}
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{rc})
	resolver := NewSubscriptionTargetResolver(
		subscriptionTargetFinder{data: data},
		subscriptionTargetScoper{scoped: &rc},
		subscriptionTargetCredentials{},
	)
	requests, err := resolver.Resolve(
		context.Background(),
		gatewayID,
		"/agent/mcp",
		NewHonouredSet(NotificationToolsListChanged),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(requests) != 0 {
		t.Fatalf("requests = %d, want none", len(requests))
	}
}

func subscriptionRegistry(
	id ids.RegistryID,
	mode registrydomain.MCPProtocolMode,
) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:      id,
		Type:    registrydomain.TypeMCP,
		Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{
			URL:          "https://upstream.example/mcp",
			ProtocolMode: mode,
			Headers:      map[string]string{},
		},
	}
}
