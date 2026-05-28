package backend_test

import (
	"context"
	"errors"
	"testing"

	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/backend/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.New(domain.CreateParams{
		GatewayID: uuid.New(),
		Name:      "old",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   validTargets(),
	})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Backend) bool {
		return b.ID == existing.ID && b.Name == "new"
	})).Return(nil).Once()

	updater := appbackend.NewUpdater(repo, newCacheManager(), newTestLogger())
	got, err := updater.Update(context.Background(), appbackend.UpdateInput{
		ID:        existing.ID,
		Name:      "new",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   validTargets(),
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
	existing, _ := domain.New(domain.CreateParams{
		GatewayID: uuid.New(),
		Name:      "x",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   validTargets(),
	})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appbackend.NewUpdater(repo, newCacheManager(), newTestLogger())
	_, err := updater.Update(context.Background(), appbackend.UpdateInput{
		ID:        existing.ID,
		GatewayID: uuid.New(),
		Name:      "x",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   validTargets(),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appbackend.NewUpdater(repo, newCacheManager(), newTestLogger())
	_, err := updater.Update(context.Background(), appbackend.UpdateInput{
		ID:        id,
		Name:      "x",
		Algorithm: domain.AlgorithmRoundRobin,
		Targets:   validTargets(),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
