package consumer_test

import (
	"context"
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func TestFinder_FindByID_CacheHit(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	mgr := newCacheManager()
	mgr.GetTTLMap(cache.ConsumerTTLName).Set(id.String(), &domain.Consumer{ID: id, GatewayID: gwID, Name: "cached"})

	f := appconsumer.NewFinder(repo, mgr, newTestLogger())
	got, err := f.FindByID(context.Background(), gwID, id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got.Name != "cached" {
		t.Fatalf("Name = %q, want %q", got.Name, "cached")
	}
}

func TestFinder_FindByID_CacheMiss_DelegatesToRepo(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: gwID, Name: "fresh"}, nil).Once()

	f := appconsumer.NewFinder(repo, newCacheManager(), newTestLogger())
	got, err := f.FindByID(context.Background(), gwID, id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got.Name != "fresh" {
		t.Fatalf("Name = %q, want %q", got.Name, "fresh")
	}
}

func TestFinder_FindByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, mock.Anything).Return(nil, domain.ErrNotFound).Once()

	f := appconsumer.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := f.FindByID(context.Background(), ids.New[ids.GatewayKind](), ids.New[ids.ConsumerKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFinder_FindByID_WrongGateway(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: ids.New[ids.GatewayKind](), Name: "other"}, nil).Once()

	f := appconsumer.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := f.FindByID(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway id", err)
	}
}

func TestFinder_List(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	items := []*domain.Consumer{{Name: "a"}, {Name: "b"}}
	repo.EXPECT().
		List(mock.Anything, mock.Anything).
		Return(items, 2, nil).
		Once()

	f := appconsumer.NewFinder(repo, newCacheManager(), newTestLogger())
	got, total, err := f.List(context.Background(), domain.ListFilter{Page: 1, Size: 10})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("total=%d len=%d", total, len(got))
	}
}
