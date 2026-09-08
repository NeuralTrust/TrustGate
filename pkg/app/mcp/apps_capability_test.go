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
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type appsCredentialFunc func(context.Context, *appconsumer.RoutableConsumer, *registrydomain.Registry, *Target) error

func (f appsCredentialFunc) Apply(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error {
	return f(ctx, rc, reg, target)
}

type appsResolverFunc func(context.Context, Target) (MCPAppsClientCapability, error)

func (f appsResolverFunc) Resolve(ctx context.Context, target Target) (MCPAppsClientCapability, error) {
	return f(ctx, target)
}

func TestParseMCPAppsClientCapability(t *testing.T) {
	valid, err := ParseMCPAppsClientCapability(map[string]any{"mimeTypes": []any{MCPAppsHTMLMIMEType, MCPAppsHTMLMIMEType}})
	if err != nil || len(valid.MIMETypes) != 1 || valid.MIMETypes[0] != MCPAppsHTMLMIMEType {
		t.Fatalf("capability = %+v, %v", valid, err)
	}
	invalid := map[string]any{
		"non-object":        "ui",
		"missing MIME list": map[string]any{},
		"empty MIME list":   map[string]any{"mimeTypes": []any{}},
		"malformed MIME":    map[string]any{"mimeTypes": []any{7}},
		"unknown key":       map[string]any{"mimeTypes": []any{MCPAppsHTMLMIMEType}, "features": []any{"smuggled"}},
	}
	for name, declaration := range invalid {
		if got, err := ParseMCPAppsClientCapability(declaration); err == nil {
			t.Errorf("%s: capability = %+v, want rejected", name, got)
		}
	}
}

func TestAppsMediatorCancellationJoinsBoundedWorkers(t *testing.T) {
	for _, cancelCaller := range []bool{false, true} {
		rc := appsConsumer(make([]registrydomain.MCPProtocolMode, discoveryFanOut+2))
		for _, reg := range rc.Registries {
			reg.MCPTarget.ProtocolMode = registrydomain.MCPProtocolModeModern
		}
		rc.Registries[0].Enabled = false
		var calls, active atomic.Int32
		started := make(chan struct{}, discoveryFanOut)
		creds := appsCredentialFunc(func(_ context.Context, _ *appconsumer.RoutableConsumer, _ *registrydomain.Registry, _ *Target) error {
			calls.Add(1)
			return nil
		})
		resolver := appsResolverFunc(func(ctx context.Context, _ Target) (MCPAppsClientCapability, error) {
			active.Add(1)
			started <- struct{}{}
			<-ctx.Done()
			active.Add(-1)
			return MCPAppsClientCapability{}, ctx.Err()
		})
		ctx, cancel := context.WithCancel(context.Background())
		mediator := NewAppsMediator(true, true, creds, resolver).(*appsMediator)
		mediator.budget = 20 * time.Millisecond
		if cancelCaller {
			go func() {
				for range discoveryFanOut {
					<-started
				}
				cancel()
			}()
		}
		advertised := mediator.Advertise(ctx, true, rc, appsClient())
		cancel()
		if advertised || calls.Load() != discoveryFanOut || active.Load() != 0 {
			t.Fatalf("advertised=%v calls=%d active=%d", advertised, calls.Load(), active.Load())
		}
	}
}

func appsClient() MCPAppsClientCapability {
	return MCPAppsClientCapability{MIMETypes: []string{MCPAppsHTMLMIMEType}}
}

func appsConsumer(modes []registrydomain.MCPProtocolMode) *appconsumer.RoutableConsumer {
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind]()}}
	rc.Consumer.MCP = &consumerdomain.MCPPolicy{}
	for _, mode := range modes {
		reg := &registrydomain.Registry{
			ID: ids.New[ids.RegistryKind](), Type: registrydomain.TypeMCP, Enabled: true,
			MCPTarget: &registrydomain.MCPTarget{URL: "https://upstream.example/mcp", ProtocolMode: mode},
		}
		rc.Registries = append(rc.Registries, reg)
		rc.Consumer.MCP.Toolkit = append(rc.Consumer.MCP.Toolkit,
			consumerdomain.ToolkitEntry{RegistryID: reg.ID, Tool: "*"},
			consumerdomain.ToolkitEntry{RegistryID: reg.ID, Resource: "*"})
	}
	return rc
}
