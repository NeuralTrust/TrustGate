package backend_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/backend/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func validCreateInput(gwID ids.GatewayID, name string) appbackend.CreateInput {
	return appbackend.CreateInput{
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
		Save(mock.Anything, mock.MatchedBy(func(b *domain.Backend) bool {
			return b.GatewayID == gwID && b.Name == "backend-1" && b.Provider == "openai"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appbackend.NewCreator(repo, mgr, newTestLogger())

	b, err := creator.Create(context.Background(), validCreateInput(gwID, "backend-1"))
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.BackendTTLName).Get(b.ID.String())
	if !ok {
		t.Fatal("created backend was not pre-warmed in the cache")
	}
	if cached.(*domain.Backend).ID != b.ID {
		t.Fatal("cached backend ID mismatch")
	}
}

func TestCreator_Create_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := appbackend.NewCreator(repo, newCacheManager(), newTestLogger())

	in := validCreateInput(ids.New[ids.GatewayKind](), "x")
	in.Provider = ""
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrInvalidBackend) {
		t.Fatalf("err = %v, want ErrInvalidBackend", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := appbackend.NewCreator(repo, newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind](), "dupe"))
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
