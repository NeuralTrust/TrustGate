package consumer_test

import (
	"context"
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.ConsumerTTLName).Set(id.String(), &domain.Consumer{ID: id})

	d := appconsumer.NewDeleter(repo, mgr, newTestLogger())
	if err := d.Delete(context.Background(), id); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.ConsumerTTLName).Get(id.String()); ok {
		t.Fatal("cache entry should have been evicted")
	}
}

func TestDeleter_Delete_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Delete(mock.Anything, mock.Anything).Return(domain.ErrNotFound).Once()

	d := appconsumer.NewDeleter(repo, newCacheManager(), newTestLogger())
	if err := d.Delete(context.Background(), uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
