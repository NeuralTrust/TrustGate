package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/mcp"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var ErrInvalidMCPUpstreamCacheType = errors.New("invalid type assertion for MCP upstream model")

type MCPUpstreamService interface {
	Get(ctx context.Context, id uuid.UUID) (*mcp.Upstream, error)
	GetByGatewayID(ctx context.Context, gatewayID uuid.UUID, name string) (*mcp.Upstream, error)
	Create(ctx context.Context, mcpUpstream *mcp.Upstream) error
	Update(ctx context.Context, mcpUpstream *mcp.Upstream) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]mcp.Upstream, error)
	SyncServerTools(ctx context.Context, upstreamID uuid.UUID, serverID string, tools []mcp.Tool) error
	GetAllTools(ctx context.Context, upstreamID uuid.UUID) ([]mcp.Tool, error)
	GetToolByName(ctx context.Context, upstreamID uuid.UUID, toolName string) (*mcp.Tool, string, error)
	RefreshToolsRegistry(ctx context.Context, upstreamID uuid.UUID) error
}

type mcpUpstreamService struct {
	repo        mcp.Repository
	cache       *cache.Cache
	memoryCache *common.TTLMap
	logger      *logrus.Logger
}

func NewMCPUpstreamService(
	repository mcp.Repository,
	c *cache.Cache,
	logger *logrus.Logger,
) MCPUpstreamService {
	return &mcpUpstreamService{
		repo:        repository,
		cache:       c,
		logger:      logger,
		memoryCache: c.GetTTLMap(cache.ServiceTTLName),
	}
}

func (s *mcpUpstreamService) Get(ctx context.Context, id uuid.UUID) (*mcp.Upstream, error) {
	if mcpUpstream, err := s.getMCPUpstreamFromMemoryCache(id.String()); err == nil {
		return mcpUpstream, nil
	} else if !errors.Is(err, ErrInvalidMCPUpstreamCacheType) {
		s.logger.WithError(err).Warn("memory cache read MCP upstream failure")
	}
	mcpUpstream, err := s.repo.Get(ctx, id)
	if err != nil {
		s.logger.WithError(err).Error("failed to fetch MCP upstream from repository")
		return nil, err
	}
	s.saveMCPUpstreamToMemoryCache(mcpUpstream)
	return mcpUpstream, nil
}

func (s *mcpUpstreamService) GetByGatewayID(ctx context.Context, gatewayID uuid.UUID, name string) (*mcp.Upstream, error) {
	cacheKey := fmt.Sprintf("%s-%s", gatewayID.String(), name)

	if mcpUpstream, err := s.getMCPUpstreamFromMemoryCache(cacheKey); err == nil {
		return mcpUpstream, nil
	} else if !errors.Is(err, ErrInvalidMCPUpstreamCacheType) {
		s.logger.WithError(err).Warn("memory cache read MCP upstream failure")
	}

	mcpUpstream, err := s.repo.GetByGatewayID(ctx, gatewayID, name)
	if err != nil {
		s.logger.WithError(err).Error("failed to fetch MCP upstream by gateway ID from repository")
		return nil, err
	}

	s.saveMCPUpstreamToMemoryCache(mcpUpstream)
	return mcpUpstream, nil
}

func (s *mcpUpstreamService) Create(ctx context.Context, mcpUpstream *mcp.Upstream) error {
	if err := s.repo.Create(ctx, mcpUpstream); err != nil {
		s.logger.WithError(err).Error("failed to create MCP upstream")
		return err
	}

	s.saveMCPUpstreamToMemoryCache(mcpUpstream)
	return nil
}

func (s *mcpUpstreamService) Update(ctx context.Context, mcpUpstream *mcp.Upstream) error {
	if err := s.repo.Update(ctx, mcpUpstream); err != nil {
		s.logger.WithError(err).Error("failed to update MCP upstream")
		return err
	}

	// Invalidate cache
	s.invalidateMCPUpstreamCache(mcpUpstream.ID.String())
	s.saveMCPUpstreamToMemoryCache(mcpUpstream)
	return nil
}

func (s *mcpUpstreamService) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.WithError(err).Error("failed to delete MCP upstream")
		return err
	}

	// Invalidate cache
	s.invalidateMCPUpstreamCache(id.String())
	return nil
}

func (s *mcpUpstreamService) List(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]mcp.Upstream, error) {
	mcpUpstreams, err := s.repo.List(ctx, gatewayID, offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("failed to list MCP upstreams")
		return nil, err
	}

	// Cache the results
	for i := range mcpUpstreams {
		s.saveMCPUpstreamToMemoryCache(&mcpUpstreams[i])
	}

	return mcpUpstreams, nil
}

func (s *mcpUpstreamService) SyncServerTools(ctx context.Context, upstreamID uuid.UUID, serverID string, tools []mcp.Tool) error {
	if err := s.repo.SyncTools(ctx, upstreamID, serverID, tools); err != nil {
		s.logger.WithError(err).Error("failed to sync MCP server tools")
		return err
	}
	s.invalidateMCPUpstreamCache(upstreamID.String())
	s.logger.WithFields(logrus.Fields{
		"upstream_id": upstreamID,
		"server_id":   serverID,
		"tools_count": len(tools),
	}).Info("successfully synced MCP server tools")
	return nil
}

func (s *mcpUpstreamService) GetAllTools(ctx context.Context, upstreamID uuid.UUID) ([]mcp.Tool, error) {
	mcpUpstream, err := s.Get(ctx, upstreamID)
	if err != nil {
		return nil, err
	}

	return mcpUpstream.ListAllTools(), nil
}

func (s *mcpUpstreamService) GetToolByName(ctx context.Context, upstreamID uuid.UUID, toolName string) (*mcp.Tool, string, error) {
	mcpUpstream, err := s.Get(ctx, upstreamID)
	if err != nil {
		return nil, "", err
	}

	return mcpUpstream.GetToolByName(toolName)
}

func (s *mcpUpstreamService) RefreshToolsRegistry(ctx context.Context, upstreamID uuid.UUID) error {
	mcpUpstream, err := s.Get(ctx, upstreamID)
	if err != nil {
		return err
	}

	if err := mcpUpstream.BuildToolsRegistry(); err != nil {
		return fmt.Errorf("failed to rebuild tools registry: %w", err)
	}

	if err := s.repo.Update(ctx, mcpUpstream); err != nil {
		return fmt.Errorf("failed to update MCP upstream with new tools registry: %w", err)
	}

	s.invalidateMCPUpstreamCache(upstreamID.String())

	s.logger.WithField("upstream_id", upstreamID).Info("successfully refreshed tools registry")
	return nil
}

func (s *mcpUpstreamService) getMCPUpstreamFromMemoryCache(key string) (*mcp.Upstream, error) {
	cachedValue, found := s.memoryCache.Get(key)
	if !found {
		return nil, errors.New("MCP upstream not found in memory cache")
	}

	mcpUpstream, ok := cachedValue.(*mcp.Upstream)
	if !ok {
		return nil, ErrInvalidMCPUpstreamCacheType
	}

	return mcpUpstream, nil
}

func (s *mcpUpstreamService) saveMCPUpstreamToMemoryCache(mcpUpstream *mcp.Upstream) {
	s.memoryCache.Set(mcpUpstream.ID.String(), mcpUpstream)
	// Also cache by gateway+name combination
	cacheKey := fmt.Sprintf("%s-%s", mcpUpstream.GatewayID.String(), mcpUpstream.Name)
	s.memoryCache.Set(cacheKey, mcpUpstream)
}

func (s *mcpUpstreamService) invalidateMCPUpstreamCache(key string) {
	s.memoryCache.Delete(key)
}
