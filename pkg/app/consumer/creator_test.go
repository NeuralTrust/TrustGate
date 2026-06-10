package consumer_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.GatewayID == gwID && c.Name == "chat" && c.Type == domain.TypeLLM
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appconsumer.NewCreator(repo, registrymocks.NewRepository(t), mgr, cachetest.NoopPublisher(), newTestLogger())

	c, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: gwID,
		Name:      "chat",
		Type:      domain.TypeLLM,
		Path:      "/v1/chat/completions",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	// Consumers are created bare; registries are attached afterwards.
	if len(c.RegistryIDs) != 0 {
		t.Fatalf("RegistryIDs = %v, want empty at creation", c.RegistryIDs)
	}
	cached, ok := mgr.GetTTLMap(cache.ConsumerTTLName).Get(c.ID.String())
	if !ok {
		t.Fatal("created consumer was not pre-warmed in the cache")
	}
	if cached.(*domain.Consumer).ID != c.ID {
		t.Fatal("cached consumer ID mismatch")
	}
}

func TestCreator_Create_WithFallback(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	fallbackID := ids.New[ids.RegistryKind]()
	fallback := &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{fallbackID},
	}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.Fallback != nil &&
				c.Fallback.Enabled &&
				c.Fallback.Budget.MaxAttempts == 3 &&
				len(c.Fallback.Chain) == 1 &&
				c.Fallback.Chain[0] == fallbackID
		})).
		Return(nil).
		Once()

	creator := appconsumer.NewCreator(repo, registrymocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	created, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: gwID,
		Name:      "chat",
		Type:      domain.TypeLLM,
		Path:      "/v1/chat/completions",
		Fallback:  fallback,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if created.Fallback == nil || created.Fallback.Chain[0] != fallbackID {
		t.Fatalf("Fallback = %#v, want chain with %s", created.Fallback, fallbackID)
	}
}

func TestCreator_Create_RejectsInvalidDomain(t *testing.T) {
	t.Parallel()
	creator := appconsumer.NewCreator(repomocks.NewRepository(t), registrymocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "",
		Type:      domain.TypeLLM,
		Path:      "/v1/chat/completions",
	})
	if !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()

	creator := appconsumer.NewCreator(repo, registrymocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "dupe",
		Type:      domain.TypeLLM,
		Path:      "/v1/chat/completions",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestCreator_Create_WithRegistriesAndModelPolicies(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	reg1 := ids.New[ids.RegistryKind]()
	reg2 := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return len(c.RegistryIDs) == 2 &&
				c.RegistryIDs.Contains(reg1) &&
				c.RegistryIDs.Contains(reg2) &&
				len(c.ModelPolicies) == 1
		})).
		Return(nil).
		Once()

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*registrydomain.Registry{
			{ID: reg1, GatewayID: gwID},
			{ID: reg2, GatewayID: gwID},
		}, nil).
		Once()

	creator := appconsumer.NewCreator(repo, registryRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	created, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:   gwID,
		Name:        "chat",
		Type:        domain.TypeLLM,
		Path:        "/v1/chat/completions",
		RegistryIDs: []ids.RegistryID{reg1, reg2},
		ModelPolicies: domain.ModelPolicies{
			reg1: {Allowed: []string{"gpt-4o", "gpt-4o-mini"}, Default: "gpt-4o"},
		},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if len(created.RegistryIDs) != 2 {
		t.Fatalf("RegistryIDs = %v, want 2 entries", created.RegistryIDs)
	}
	if _, ok := created.ModelPolicies.For(reg1); !ok {
		t.Fatalf("ModelPolicies missing entry for %s", reg1)
	}
}

func TestCreator_Create_RejectsRegistryFromAnotherGateway(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	reg1 := ids.New[ids.RegistryKind]()
	reg2 := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, mock.Anything).
		Return([]*registrydomain.Registry{
			{ID: reg1, GatewayID: gwID},
		}, nil).
		Once()

	creator := appconsumer.NewCreator(repo, registryRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:   gwID,
		Name:        "chat",
		Type:        domain.TypeLLM,
		Path:        "/v1/chat/completions",
		RegistryIDs: []ids.RegistryID{reg1, reg2},
	})
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want registrydomain.ErrInvalidRegistryID", err)
	}
}

func TestCreator_Create_RejectsModelPolicyForUnboundRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	reg1 := ids.New[ids.RegistryKind]()
	unbound := ids.New[ids.RegistryKind]()

	creator := appconsumer.NewCreator(
		repomocks.NewRepository(t),
		registrymocks.NewRepository(t),
		newCacheManager(),
		cachetest.NoopPublisher(),
		newTestLogger(),
	)

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:   gwID,
		Name:        "chat",
		Type:        domain.TypeLLM,
		Path:        "/v1/chat/completions",
		RegistryIDs: []ids.RegistryID{reg1},
		ModelPolicies: domain.ModelPolicies{
			unbound: {Default: "gpt-4o"},
		},
	})
	if !errors.Is(err, domain.ErrInvalidModelPolicy) {
		t.Fatalf("err = %v, want domain.ErrInvalidModelPolicy", err)
	}
}
