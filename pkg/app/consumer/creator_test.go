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
	creator := appconsumer.NewCreator(repo, mgr, cachetest.NoopPublisher(), newTestLogger())

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

func TestCreator_Create_RejectsRegistryReferencesBeforeAssociation(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	cases := []struct {
		name    string
		input   appconsumer.CreateInput
		wantErr error
	}{
		{
			name: "fallback chain",
			input: appconsumer.CreateInput{
				Fallback: &domain.Fallback{
					Enabled:  true,
					Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
					Budget:   domain.FallbackBudget{MaxAttempts: 3},
					Chain:    registrydomain.Registries{registryID},
				},
			},
			wantErr: registrydomain.ErrInvalidRegistryID,
		},
		{
			name: "model policies",
			input: appconsumer.CreateInput{
				ModelPolicies: domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}},
			},
			wantErr: domain.ErrInvalidModelPolicy,
		},
		{
			name: "lb config members",
			input: appconsumer.CreateInput{
				LBConfig: &domain.LBConfig{
					Enabled: true,
					Members: []domain.LBPoolMember{{RegistryID: registryID, Models: []string{"gpt-4o"}}},
				},
				ModelPolicies: domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}},
			},
			wantErr: domain.ErrInvalidModelPolicy,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creator := appconsumer.NewCreator(repomocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
			tc.input.GatewayID = gwID
			tc.input.Name = "chat"
			tc.input.Type = domain.TypeLLM
			tc.input.Path = "/v1/chat/completions"

			_, err := creator.Create(context.Background(), tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCreator_Create_RejectsInvalidDomain(t *testing.T) {
	t.Parallel()
	creator := appconsumer.NewCreator(repomocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

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

	creator := appconsumer.NewCreator(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

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
