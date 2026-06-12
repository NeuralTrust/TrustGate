package mcp

import (
	"context"
	"fmt"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

// Introspector lists the discoverable tools of one MCP registry so operators
// (and the admin UI) can build a consumer toolkit from a real pick-list.
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
