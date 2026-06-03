package registry_test

import (
	"context"
	"errors"
	"testing"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func TestFinder_FindByID_CacheHit(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	gwID := ids.New[ids.GatewayKind]()
	cached := &domain.Registry{ID: id, GatewayID: gwID, Name: "cached"}

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.RegistryTTLName).Set(id.String(), cached)

	finder := appregistry.NewFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByID(context.Background(), gwID, id)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got != cached {
		t.Fatal("FindByID did not return cached instance")
	}
}

func TestFinder_FindByID_CacheMiss_PopulatesCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	gwID := ids.New[ids.GatewayKind]()
	want := &domain.Registry{ID: id, GatewayID: gwID, Name: "from-db"}
	repo.EXPECT().FindByID(mock.Anything, id).Return(want, nil).Once()

	mgr := newCacheManager()
	finder := appregistry.NewFinder(repo, mgr, newTestLogger())

	got, err := finder.FindByID(context.Background(), gwID, id)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got != want {
		t.Fatal("FindByID did not return repo result")
	}
	if _, ok := mgr.GetTTLMap(cache.RegistryTTLName).Get(id.String()); !ok {
		t.Fatal("cache was not populated on miss")
	}
}

func TestFinder_FindByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	finder := appregistry.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := finder.FindByID(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFinder_FindByID_WrongGateway(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	want := &domain.Registry{ID: id, GatewayID: ids.New[ids.GatewayKind](), Name: "other-gateway"}
	repo.EXPECT().FindByID(mock.Anything, id).Return(want, nil).Once()

	finder := appregistry.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := finder.FindByID(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway id", err)
	}
}

func TestFinder_List(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	want := []*domain.Registry{{ID: ids.New[ids.RegistryKind](), Name: "a"}}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.NameContains == "a"
		})).
		Return(want, 1, nil).
		Once()

	finder := appregistry.NewFinder(repo, newCacheManager(), newTestLogger())
	got, total, err := finder.List(context.Background(), domain.ListFilter{NameContains: "a"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("List returned total=%d len=%d", total, len(got))
	}
}
