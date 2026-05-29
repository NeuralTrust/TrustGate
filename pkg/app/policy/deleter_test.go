package policy_test

import (
	"context"
	"errors"
	"testing"

	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Policy{ID: id, GatewayID: uuid.New()}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.PolicyTTLName).Set(id.String(), "junk")

	deleter := apppolicy.NewDeleter(repo, mgr, cachetest.NoopPublisher(), newTestLogger())
	if err := deleter.Delete(context.Background(), id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.PolicyTTLName).Get(id.String()); ok {
		t.Fatal("cache entry should be evicted after Delete")
	}
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := uuid.New()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	deleter := apppolicy.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	err := deleter.Delete(context.Background(), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
