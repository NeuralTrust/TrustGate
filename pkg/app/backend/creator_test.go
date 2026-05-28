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
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func validTargets() domain.Targets {
	return domain.Targets{
		{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-1")},
	}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := uuid.New()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(b *domain.Backend) bool {
			return b.GatewayID == gwID && b.Name == "pool" && b.Algorithm == domain.AlgorithmRoundRobin
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appbackend.NewCreator(repo, mgr, newTestLogger())

	b, err := creator.Create(context.Background(), appbackend.CreateInput{
		GatewayID: gwID,
		Name:      "pool",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   validTargets(),
	})
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

	_, err := creator.Create(context.Background(), appbackend.CreateInput{
		GatewayID: uuid.New(),
		Name:      "x",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   domain.Targets{},
	})
	if !errors.Is(err, domain.ErrNoTargets) {
		t.Fatalf("err = %v, want ErrNoTargets", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := appbackend.NewCreator(repo, newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), appbackend.CreateInput{
		GatewayID: uuid.New(),
		Name:      "dupe",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   validTargets(),
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
