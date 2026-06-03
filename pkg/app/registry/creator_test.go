package registry_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func validCreateInput(gwID ids.GatewayID, name string) appregistry.CreateInput {
	return appregistry.CreateInput{
		GatewayID: gwID,
		Name:      name,
		Provider:  "openai",
		Auth:      domain.NewAPIKeyAuth("sk-1"),
	}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
			return b.GatewayID == gwID && b.Name == "backend-1" && b.Provider == "openai"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appregistry.NewCreator(repo, mgr, newTestLogger())

	b, err := creator.Create(context.Background(), validCreateInput(gwID, "backend-1"))
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.RegistryTTLName).Get(b.ID.String())
	if !ok {
		t.Fatal("created backend was not pre-warmed in the cache")
	}
	if cached.(*domain.Registry).ID != b.ID {
		t.Fatal("cached backend ID mismatch")
	}
}

func TestCreator_Create_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger())

	in := validCreateInput(ids.New[ids.GatewayKind](), "x")
	in.Provider = ""
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrInvalidRegistry) {
		t.Fatalf("err = %v, want ErrInvalidRegistry", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind](), "dupe"))
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
