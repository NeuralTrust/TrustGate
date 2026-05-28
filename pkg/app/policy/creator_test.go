package policy_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
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

func validPlugins() domain.Plugins {
	return domain.Plugins{
		{Name: "rate_limiter", Stage: domain.StagePreRequest, Enabled: true, Priority: 0},
	}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := uuid.New()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
			return p.GatewayID == gwID && p.Name == "default" && len(p.Plugins) == 1
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := apppolicy.NewCreator(repo, mgr, newTestLogger())

	p, err := creator.Create(context.Background(), apppolicy.CreateInput{
		GatewayID: gwID,
		Name:      "default",
		Plugins:   validPlugins(),
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.PolicyTTLName).Get(p.ID.String())
	if !ok {
		t.Fatal("created policy was not pre-warmed in the cache")
	}
	if cached.(*domain.Policy).ID != p.ID {
		t.Fatal("cached policy ID mismatch")
	}
}

func TestCreator_Create_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := apppolicy.NewCreator(repo, newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), apppolicy.CreateInput{
		GatewayID: uuid.New(),
		Name:      "",
		Plugins:   validPlugins(),
	})
	if !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := apppolicy.NewCreator(repo, newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), apppolicy.CreateInput{
		GatewayID: uuid.New(),
		Name:      "dupe",
		Plugins:   validPlugins(),
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
