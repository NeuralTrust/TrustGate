package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type MCPUpstreamRepository struct {
	db *gorm.DB
}

func NewMCPUpstreamRepository(db *gorm.DB) mcp.Repository {
	return &MCPUpstreamRepository{
		db: db,
	}
}

func (r *MCPUpstreamRepository) Get(ctx context.Context, id uuid.UUID) (*mcp.Upstream, error) {
	var entity mcp.Upstream
	if err := r.db.WithContext(ctx).First(&entity, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *MCPUpstreamRepository) GetByGatewayID(ctx context.Context, gatewayID uuid.UUID, name string) (*mcp.Upstream, error) {
	var entity mcp.Upstream
	if err := r.db.WithContext(ctx).Where("gateway_id = ? AND name = ?", gatewayID, name).First(&entity).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *MCPUpstreamRepository) Create(ctx context.Context, mcpUpstream *mcp.Upstream) error {
	return r.db.WithContext(ctx).Create(mcpUpstream).Error
}

func (r *MCPUpstreamRepository) Update(ctx context.Context, mcpUpstream *mcp.Upstream) error {
	return r.db.WithContext(ctx).Save(mcpUpstream).Error
}

func (r *MCPUpstreamRepository) Delete(ctx context.Context, id uuid.UUID) error {
	var count int64
	if err := r.db.WithContext(ctx).Model(&service.Service{}).Where("upstream_id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return upstream.ErrUpstreamIsBeingUsed
	}

	return r.db.WithContext(ctx).Delete(&mcp.Upstream{}, "id = ?", id).Error
}

func (r *MCPUpstreamRepository) List(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]mcp.Upstream, error) {
	var mcpUpstreams []mcp.Upstream
	query := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID)

	if limit > 0 {
		query = query.Offset(offset).Limit(limit)
	}

	if err := query.Find(&mcpUpstreams).Error; err != nil {
		return nil, err
	}
	return mcpUpstreams, nil
}

func (r *MCPUpstreamRepository) ListByGatewayID(ctx context.Context, gatewayID uuid.UUID) ([]mcp.Upstream, error) {
	var mcpUpstreams []mcp.Upstream
	if err := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID).Find(&mcpUpstreams).Error; err != nil {
		return nil, err
	}
	return mcpUpstreams, nil
}

func (r *MCPUpstreamRepository) SyncTools(ctx context.Context, upstreamID uuid.UUID, serverID string, tools []mcp.Tool) error {
	var mcpUpstream mcp.Upstream
	if err := r.db.WithContext(ctx).First(&mcpUpstream, "id = ?", upstreamID).Error; err != nil {
		return err
	}

	serverFound := false
	for i, server := range mcpUpstream.MCPServers {
		if server.ID.String() == serverID {
			// Update tools with proper timestamps and server ID
			for j := range tools {
				if tools[j].ID == uuid.Nil {
					tools[j].ID = uuid.New()
				}
				if tools[j].ServerID == uuid.Nil {
					tools[j].ServerID = server.ID
				}
				now := time.Now()
				if tools[j].CreatedAt.IsZero() {
					tools[j].CreatedAt = now
				}
				tools[j].UpdatedAt = now
			}
			mcpUpstream.MCPServers[i].Tools = tools
			mcpUpstream.MCPServers[i].LastSync = mcpUpstream.UpdatedAt
			serverFound = true
			break
		}
	}

	if !serverFound {
		return fmt.Errorf("MCP server with ID '%s' not found in upstream '%s'", serverID, upstreamID)
	}

	if err := mcpUpstream.BuildToolsRegistry(); err != nil {
		return fmt.Errorf("failed to rebuild tools registry: %w", err)
	}

	return r.db.WithContext(ctx).Save(&mcpUpstream).Error
}

func (r *MCPUpstreamRepository) GetToolsRegistry(ctx context.Context, upstreamID uuid.UUID) (mcp.ToolsRegistryJSON, error) {
	var mcpUpstream mcp.Upstream
	if err := r.db.WithContext(ctx).Select("tools_registry").First(&mcpUpstream, "id = ?", upstreamID).Error; err != nil {
		return nil, err
	}
	return mcpUpstream.ToolsRegistry, nil
}
