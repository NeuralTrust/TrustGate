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

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.BackendTTLName).Set(id.String(), "junk")

	deleter := appbackend.NewDeleter(repo, mgr, newTestLogger())
	if err := deleter.Delete(context.Background(), id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.BackendTTLName).Get(id.String()); ok {
		t.Fatal("cache entry should be evicted after Delete")
	}
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().Delete(mock.Anything, id).Return(domain.ErrNotFound).Once()

	deleter := appbackend.NewDeleter(repo, newCacheManager(), newTestLogger())
	err := deleter.Delete(context.Background(), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
