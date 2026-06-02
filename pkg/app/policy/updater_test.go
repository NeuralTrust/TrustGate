package policy_test

import (
	"context"
	"errors"
	"testing"

	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewPolicy(ids.New[ids.GatewayKind](), "old", validPlugins())
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.ID == existing.ID && p.Name == "new"
	})).Return(nil).Once()

	updater := apppolicy.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:      existing.ID,
		Name:    "new",
		Plugins: validPlugins(),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" {
		t.Fatalf("Name = %q, want %q", got.Name, "new")
	}
}

func TestUpdater_Update_RejectsGatewayIDChange(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewPolicy(ids.New[ids.GatewayKind](), "x", validPlugins())
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := apppolicy.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:        existing.ID,
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "x",
		Plugins:   validPlugins(),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.PolicyKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := apppolicy.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:      id,
		Name:    "x",
		Plugins: validPlugins(),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
