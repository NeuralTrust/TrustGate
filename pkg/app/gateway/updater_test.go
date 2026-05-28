package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "old-desc", now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.ID == id && g.Name == "new" && g.Description == "new-desc"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	updater := appgateway.NewUpdater(repo, mgr, newTestLogger())

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:          id,
		Name:        "new",
		Description: "new-desc",
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" || got.Description != "new-desc" {
		t.Fatalf("unexpected gateway: %+v", got)
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get(id.String())
	if !ok {
		t.Fatal("updated gateway was not refreshed in cache")
	}
	if cached.(*domain.Gateway).Name != "new" {
		t.Fatal("cache holds stale name after update")
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), newTestLogger())
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:          id,
		Name:        "x",
		Description: "y",
	})
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdater_Update_RejectsInvalidName(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "old-desc", now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	// repo.Update must not be called.

	updater := appgateway.NewUpdater(repo, newCacheManager(), newTestLogger())
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:          id,
		Name:        "   ",
		Description: "y",
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}
