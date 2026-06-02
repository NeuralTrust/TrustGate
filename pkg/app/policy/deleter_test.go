package policy_test

import (
	"context"
	"errors"
	"testing"

	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.PolicyKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Policy{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.PolicyTTLName).Set(id.String(), "junk")

	deleter := apppolicy.NewDeleter(repo, mgr, cachetest.NoopPublisher(), newTestLogger())
	if err := deleter.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.PolicyTTLName).Get(id.String()); ok {
		t.Fatal("cache entry should be evicted after Delete")
	}
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.PolicyKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	deleter := apppolicy.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	err := deleter.Delete(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleter_Delete_WrongGateway(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.PolicyKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Policy{ID: id, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	deleter := apppolicy.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	err := deleter.Delete(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway delete", err)
	}
}
