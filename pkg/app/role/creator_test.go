package role_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
)

type repositoryStub struct{}

func (repositoryStub) Save(context.Context, *domain.Role) error   { return nil }
func (repositoryStub) Update(context.Context, *domain.Role) error { return nil }
func (repositoryStub) Delete(context.Context, ids.RoleID) error   { return nil }
func (repositoryStub) FindByID(context.Context, ids.RoleID) (*domain.Role, error) {
	return nil, domain.ErrNotFound
}
func (repositoryStub) FindByIDs(context.Context, ids.GatewayID, []ids.RoleID) ([]*domain.Role, error) {
	return nil, nil
}
func (repositoryStub) List(context.Context, domain.ListFilter) ([]*domain.Role, int, error) {
	return nil, 0, nil
}
func (repositoryStub) ListByGateway(context.Context, ids.GatewayID) ([]*domain.Role, error) {
	return nil, nil
}
func (repositoryStub) AttachRegistry(context.Context, ids.RoleID, ids.RegistryID) error { return nil }
func (repositoryStub) DetachRegistry(context.Context, ids.RoleID, ids.RegistryID) error { return nil }
func (repositoryStub) DetachRegistryIfUnreferenced(context.Context, ids.GatewayID, ids.RoleID, ids.RegistryID) (*domain.Role, error) {
	return nil, nil
}

func TestCreator_Create_SavesRoleWithoutInitialModelPolicies(t *testing.T) {
	t.Parallel()
	creator := approle.NewCreator(
		repositoryStub{},
		cache.NewTTLMapManager(cache.RoleCacheTTL),
		cachetest.NoopPublisher(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	role, err := creator.Create(context.Background(), approle.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "analyst",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if len(role.ModelPolicies) != 0 {
		t.Fatalf("ModelPolicies = %v, want empty on create", role.ModelPolicies)
	}
}
