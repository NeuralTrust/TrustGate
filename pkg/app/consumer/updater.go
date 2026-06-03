package consumer

import (
	"context"
	"log/slog"
	"time"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type UpdateInput struct {
	ID              ids.ConsumerID
	GatewayID       ids.GatewayID
	Name            string
	Type            domain.Type
	Path            string
	Algorithm       string
	EmbeddingConfig *registrydomain.EmbeddingConfig
	Headers         map[string]string
	Active          *bool
	RegistryIDs     []ids.RegistryID
	PolicyIDs       []ids.PolicyID
	AuthIDs         []ids.AuthID
	Fallback        *domain.Fallback
	ModelPolicies   domain.ModelPolicies
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=consumer_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	policyRepo   policydomain.Repository
	authRepo     authdomain.Repository
	memoryCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:         repo,
		registryRepo: registryRepo,
		policyRepo:   policyRepo,
		authRepo:     authRepo,
		memoryCache:  manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:    publisher,
		logger:       logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	if err := validateAssociations(ctx, u.registryRepo, u.policyRepo, u.authRepo,
		existing.GatewayID, in.RegistryIDs, in.PolicyIDs, in.AuthIDs, fallbackChainIDs(in.Fallback)); err != nil {
		return nil, err
	}
	existing.Name = in.Name
	if in.Type != "" {
		existing.Type = in.Type
	}
	existing.Path = in.Path
	existing.Algorithm = in.Algorithm
	existing.EmbeddingConfig = in.EmbeddingConfig
	existing.Headers = in.Headers
	if in.Active != nil {
		existing.Active = *in.Active
	}
	existing.RegistryIDs = in.RegistryIDs
	existing.PolicyIDs = in.PolicyIDs
	existing.AuthIDs = in.AuthIDs
	existing.Fallback = in.Fallback
	existing.ModelPolicies = in.ModelPolicies
	existing.UpdatedAt = time.Now().UTC()
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, existing.GatewayID)
	return existing, nil
}
