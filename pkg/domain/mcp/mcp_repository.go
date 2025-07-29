package mcp

import (
	"context"

	"github.com/google/uuid"
)

//go:generate mockery --name=Repository --dir=. --output=. --filename=mcp_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Get(ctx context.Context, id uuid.UUID) (*Upstream, error)
	GetByGatewayID(ctx context.Context, gatewayID uuid.UUID, name string) (*Upstream, error)
	Create(ctx context.Context, mcpUpstream *Upstream) error
	Update(ctx context.Context, mcpUpstream *Upstream) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]Upstream, error)
	ListByGatewayID(ctx context.Context, gatewayID uuid.UUID) ([]Upstream, error)
	SyncTools(ctx context.Context, upstreamID uuid.UUID, serverID string, tools []Tool) error
	GetToolsRegistry(ctx context.Context, upstreamID uuid.UUID) (ToolsRegistryJSON, error)
}
