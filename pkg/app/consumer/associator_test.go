package consumer_test

import (
	"context"
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	policymocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	backendmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func newAssociator(
	repo *repomocks.Repository,
	registryRepo *backendmocks.Repository,
	authRepo *authmocks.Repository,
	policyRepo *policymocks.Repository,
) appconsumer.Associator {
	return appconsumer.NewAssociator(
		repo, registryRepo, authRepo, policyRepo,
		newCacheManager(), cachetest.NoopPublisher(), newTestLogger(),
	)
}

func TestAssociator_AttachRegistry_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()
	repo.EXPECT().AttachRegistry(mock.Anything, consumerID, registryID).Return(nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByID(mock.Anything, registryID).
		Return(&registrydomain.Registry{ID: registryID, GatewayID: gwID}, nil).Once()

	a := newAssociator(repo, registryRepo, authmocks.NewRepository(t), policymocks.NewRepository(t))
	if err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID); err != nil {
		t.Fatalf("AttachRegistry error: %v", err)
	}
}

func TestAssociator_AttachRegistry_RejectsForeignConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policymocks.NewRepository(t))
	err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want consumer ErrNotFound", err)
	}
}

func TestAssociator_AttachRegistry_RejectsForeignRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByID(mock.Anything, registryID).
		Return(&registrydomain.Registry{ID: registryID, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	a := newAssociator(repo, registryRepo, authmocks.NewRepository(t), policymocks.NewRepository(t))
	err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID)
	if !errors.Is(err, registrydomain.ErrNotFound) {
		t.Fatalf("err = %v, want registry ErrNotFound", err)
	}
}

func TestAssociator_AttachPolicy_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	policyID := ids.New[ids.PolicyKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()
	repo.EXPECT().AttachPolicy(mock.Anything, consumerID, policyID).Return(nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().FindByID(mock.Anything, policyID).
		Return(&policydomain.Policy{ID: policyID, GatewayID: gwID}, nil).Once()

	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policyRepo)
	if err := a.AttachPolicy(context.Background(), gwID, consumerID, policyID); err != nil {
		t.Fatalf("AttachPolicy error: %v", err)
	}
}

func TestAssociator_AttachAuth_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	authID := ids.New[ids.AuthKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()
	repo.EXPECT().AttachAuth(mock.Anything, consumerID, authID).Return(nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByID(mock.Anything, authID).
		Return(&authdomain.Auth{ID: authID, GatewayID: gwID}, nil).Once()

	a := newAssociator(repo, backendmocks.NewRepository(t), authRepo, policymocks.NewRepository(t))
	if err := a.AttachAuth(context.Background(), gwID, consumerID, authID); err != nil {
		t.Fatalf("AttachAuth error: %v", err)
	}
}

func TestAssociator_DetachPolicy_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	policyID := ids.New[ids.PolicyKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()
	repo.EXPECT().DetachPolicy(mock.Anything, consumerID, policyID).Return(nil).Once()

	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policymocks.NewRepository(t))
	if err := a.DetachPolicy(context.Background(), gwID, consumerID, policyID); err != nil {
		t.Fatalf("DetachPolicy error: %v", err)
	}
}
