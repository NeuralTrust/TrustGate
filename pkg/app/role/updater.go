package role

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type UpdateInput struct {
	ID            ids.RoleID
	GatewayID     ids.GatewayID
	Name          *string
	ModelPolicies *domain.ModelPolicies
	McpPolicies   *json.RawMessage
	IDPMapping    *json.RawMessage
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=role_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Role, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RoleTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Role, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrNotFound
	}
	if in.Name != nil {
		existing.Name = *in.Name
	}
	if in.ModelPolicies != nil {
		existing.ModelPolicies = *in.ModelPolicies
	}
	if in.McpPolicies != nil {
		existing.McpPolicies = *in.McpPolicies
	}
	if in.IDPMapping != nil {
		existing.IDPMapping = *in.IDPMapping
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := existing.ModelPolicies.Validate(existing.BoundRegistrySet()); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, existing.GatewayID)
	return existing, nil
}
