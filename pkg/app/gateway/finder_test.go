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

func TestFinder_FindByID_CacheHit(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	// repo.FindByID must NOT be called when cache hits.

	id := uuid.New()
	now := time.Now().UTC()
	mgr := newCacheManager()
	cached := domain.Rehydrate(id, "Prod", "cached", now, now)
	mgr.GetTTLMap(cache.GatewayTTLName).Set(id.String(), cached)

	finder := appgateway.NewFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got != cached {
		t.Fatal("FindByID returned a different pointer than the cached entry")
	}
}

func TestFinder_FindByID_CacheMiss_PopulatesCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	now := time.Now().UTC()
	fromDB := domain.Rehydrate(id, "Prod", "from-db", now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(fromDB, nil).Once()

	mgr := newCacheManager()
	finder := appgateway.NewFinder(repo, mgr, newTestLogger())

	got, err := finder.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got != fromDB {
		t.Fatal("FindByID did not return the entity loaded from the repository")
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get(id.String())
	if !ok {
		t.Fatal("cache was not populated after DB load")
	}
	if cached.(*domain.Gateway) != fromDB {
		t.Fatal("cached pointer does not match the entity returned by the repository")
	}
}

func TestFinder_FindByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	finder := appgateway.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := finder.FindByID(context.Background(), id)
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFinder_FindByID_PoisonedCache_FallsBackToDB(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	now := time.Now().UTC()
	fromDB := domain.Rehydrate(id, "Prod", "real", now, now)
	repo.EXPECT().FindByID(mock.Anything, id).Return(fromDB, nil).Once()

	mgr := newCacheManager()
	// Wrong type stored under the key — finder must drop it and load
	// from the DB rather than serving garbage.
	mgr.GetTTLMap(cache.GatewayTTLName).Set(id.String(), "not a gateway")

	finder := appgateway.NewFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got != fromDB {
		t.Fatal("finder did not fall back to the database on poisoned cache")
	}
	cached, _ := mgr.GetTTLMap(cache.GatewayTTLName).Get(id.String())
	if _, ok := cached.(*domain.Gateway); !ok {
		t.Fatal("cache was not refreshed with a proper entity after poison fallback")
	}
}

func TestFinder_List_Passthrough(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	filter := domain.ListFilter{NameContains: "prod", Page: 1, Size: 20}
	now := time.Now().UTC()
	items := []*domain.Gateway{
		domain.Rehydrate(uuid.New(), "Prod-eu", "", now, now),
		domain.Rehydrate(uuid.New(), "Prod-us", "", now, now),
	}
	repo.EXPECT().List(mock.Anything, filter).Return(items, 2, nil).Once()

	finder := appgateway.NewFinder(repo, newCacheManager(), newTestLogger())
	got, total, err := finder.List(context.Background(), filter)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("unexpected list result: total=%d items=%d", total, len(got))
	}
}
