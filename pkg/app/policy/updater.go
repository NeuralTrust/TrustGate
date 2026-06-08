package policy

import (
	"context"
	"log/slog"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type UpdateInput struct {
	ID          ids.PolicyID
	GatewayID   ids.GatewayID
	Name        string
	Description string
	Slug        string
	Enabled     bool
	Priority    int
	Parallel    bool
	Settings    map[string]any
	Stages      []domain.Stage
	Mode        domain.Mode
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=policy_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Policy, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	registry    appplugins.Registry
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	registry appplugins.Registry,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:        repo,
		registry:    registry,
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Policy, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	existing.Name = in.Name
	existing.Description = in.Description
	existing.Slug = in.Slug
	existing.Enabled = in.Enabled
	existing.Priority = in.Priority
	existing.Parallel = in.Parallel
	existing.Settings = in.Settings
	existing.Stages = in.Stages
	existing.Mode = in.Mode.Normalize()
	existing.UpdatedAt = time.Now().UTC()
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := validatePlugin(u.registry, in.Slug, in.Stages, in.Settings); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, existing.GatewayID)
	return existing, nil
}
