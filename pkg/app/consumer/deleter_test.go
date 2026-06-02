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
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.ConsumerTTLName).Set(id.String(), &domain.Consumer{ID: id})

	d := appconsumer.NewDeleter(repo, mgr, cachetest.NoopPublisher(), newTestLogger())
	if err := d.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.ConsumerTTLName).Get(id.String()); ok {
		t.Fatal("cache entry should have been evicted")
	}
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	d := appconsumer.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	if err := d.Delete(context.Background(), ids.New[ids.GatewayKind](), id); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleter_Delete_WrongGateway(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	d := appconsumer.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	if err := d.Delete(context.Background(), ids.New[ids.GatewayKind](), id); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway delete", err)
	}
}

func TestDeleter_Delete_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, id).Return(domain.ErrAlreadyExists).Once()

	d := appconsumer.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	if err := d.Delete(context.Background(), gwID, id); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
