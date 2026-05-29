package backend_test

import (
	"context"
	"errors"
	"testing"

	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/backend/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func TestFinder_FindByID_CacheHit(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	cached := &domain.Backend{ID: id, Name: "cached"}

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.BackendTTLName).Set(id.String(), cached)

	finder := appbackend.NewFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByID(context.Background(), id)
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
	id := uuid.New()
	want := &domain.Backend{ID: id, Name: "from-db"}
	repo.EXPECT().FindByID(mock.Anything, id).Return(want, nil).Once()

	mgr := newCacheManager()
	finder := appbackend.NewFinder(repo, mgr, newTestLogger())

	got, err := finder.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got != want {
		t.Fatal("FindByID did not return repo result")
	}
	if _, ok := mgr.GetTTLMap(cache.BackendTTLName).Get(id.String()); !ok {
		t.Fatal("cache was not populated on miss")
	}
}

func TestFinder_FindByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	finder := appbackend.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := finder.FindByID(context.Background(), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFinder_List(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	want := []*domain.Backend{{ID: uuid.New(), Name: "a"}}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.NameContains == "a"
		})).
		Return(want, 1, nil).
		Once()

	finder := appbackend.NewFinder(repo, newCacheManager(), newTestLogger())
	got, total, err := finder.List(context.Background(), domain.ListFilter{NameContains: "a"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("List returned total=%d len=%d", total, len(got))
	}
}
