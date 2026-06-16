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
	"fmt"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type Introspector interface {
	ListRegistryTools(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) ([]Tool, error)
}

var _ Introspector = (*introspector)(nil)

type introspector struct {
	registries appregistry.Finder
	dialer     Dialer
}

func NewIntrospector(registries appregistry.Finder, dialer Dialer) Introspector {
	return &introspector{registries: registries, dialer: dialer}
}

func (i *introspector) ListRegistryTools(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) ([]Tool, error) {
	reg, err := i.registries.FindByID(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	if !reg.IsMCP() || reg.MCPTarget == nil {
		return nil, fmt.Errorf("%w: registry %s is not an MCP registry", ErrNoMCPRegistries, registryID)
	}
	up, err := i.dialer.Connect(ctx, StaticTarget(reg))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstreamUnavailable, err)
	}
	defer up.Close(ctx)
	return up.ListTools(ctx)
}
