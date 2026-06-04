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

func existingPolicy(t *testing.T) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(ids.New[ids.GatewayKind](), "old", "rate_limiter", true, 0, false, nil, nil, "old description")
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func validUpdateInput(id ids.PolicyID) apppolicy.UpdateInput {
	return apppolicy.UpdateInput{
		ID:          id,
		Name:        "new",
		Description: "new description",
		Slug:        "rate_limiter",
		Enabled:     true,
	}
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.ID == existing.ID && p.Name == "new" && p.Description == "new description"
	})).Return(nil).Once()

	updater := apppolicy.NewUpdater(repo, newRegistryMock(t, nil), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), validUpdateInput(existing.ID))
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" {
		t.Fatalf("Name = %q, want %q", got.Name, "new")
	}
	if got.Description != "new description" {
		t.Fatalf("Description = %q, want %q", got.Description, "new description")
	}
}

func TestUpdater_Update_RejectsGatewayIDChange(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := apppolicy.NewUpdater(repo, newRegistryMock(t, nil), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	in := validUpdateInput(existing.ID)
	in.GatewayID = ids.New[ids.GatewayKind]()
	_, err := updater.Update(context.Background(), in)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.PolicyKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := apppolicy.NewUpdater(repo, newRegistryMock(t, nil), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), validUpdateInput(id))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
