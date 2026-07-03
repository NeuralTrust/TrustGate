//go:build functional

package role_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/role"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newRegistryRepo(conn *database.Connection) *registryrepo.Repository {
	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		panic(err)
	}
	return registryrepo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn))
}

type fixture struct {
	repo     *repo.Repository
	gateway  *gatewayrepo.Repository
	registry *registryrepo.Repository
}

func setupRepo(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping role repository integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PG_TEST_URL: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pgxpool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping: %v", err)
	}

	conn := &database.Connection{Pool: pool}
	manager := database.NewMigrationsManager(pool)
	if err := manager.ApplyPending(ctx); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE role_registry, roles, registries, gateways CASCADE")
		pool.Close()
	})

	appender := outboxrepo.NewRepository(conn)
	return fixture{
		repo:     repo.NewRepository(conn, appender),
		gateway:  gatewayrepo.NewRepository(conn, appender),
		registry: newRegistryRepo(conn),
	}
}

func seedGateway(t *testing.T, gateway *gatewayrepo.Repository, name string) ids.GatewayID {
	t.Helper()
	g, err := gatewaydomain.New(name)
	if err != nil {
		t.Fatalf("gateway domain.New: %v", err)
	}
	if err := gateway.Save(context.Background(), g); err != nil {
		t.Fatalf("gateway Save: %v", err)
	}
	return g.ID
}

func seedRegistry(t *testing.T, registry *registryrepo.Repository, gatewayID ids.GatewayID, name string) ids.RegistryID {
	t.Helper()
	r, err := registrydomain.NewLLMRegistry(gatewayID, name, "", &registrydomain.LLMTarget{
		Provider: "openai",
		Auth:     registrydomain.NewAPIKeyAuth("sk-test"),
	})
	if err != nil {
		t.Fatalf("registry domain.NewLLMRegistry: %v", err)
	}
	if err := registry.Save(context.Background(), r); err != nil {
		t.Fatalf("registry Save: %v", err)
	}
	return r.ID
}

func validRole(t *testing.T, gatewayID ids.GatewayID, name string) *domain.Role {
	t.Helper()
	role, err := domain.New(domain.CreateParams{
		GatewayID: gatewayID,
		Name:      name,
	})
	if err != nil {
		t.Fatalf("role domain.New: %v", err)
	}
	return role
}

func saveWithRegistry(t *testing.T, f fixture, role *domain.Role, registryID ids.RegistryID) {
	t.Helper()
	ctx := context.Background()
	if err := f.repo.Save(ctx, role); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := f.repo.AttachRegistry(ctx, role.ID, registryID); err != nil {
		t.Fatalf("AttachRegistry: %v", err)
	}
}

func TestRepository_DetachRegistryIfUnreferenced_SucceedsWithoutModelPolicyReferences(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gatewayID := seedGateway(t, f.gateway, "role-guard-detach-ok")
	registryID := seedRegistry(t, f.registry, gatewayID, "role-guard-detach-ok-registry")
	role := validRole(t, gatewayID, "role-guard-detach-ok")
	saveWithRegistry(t, f, role, registryID)

	detached, err := f.repo.DetachRegistryIfUnreferenced(ctx, gatewayID, role.ID, registryID)
	if err != nil {
		t.Fatalf("DetachRegistryIfUnreferenced: %v", err)
	}
	if detached.ID != role.ID || detached.GatewayID != gatewayID {
		t.Fatalf("detached role = %+v, want id %s gateway %s", detached, role.ID, gatewayID)
	}
	got, err := f.repo.FindByID(ctx, role.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.RegistryIDs) != 0 {
		t.Fatalf("RegistryIDs = %v, want empty", got.RegistryIDs)
	}
}

func TestRepository_DetachRegistryIfUnreferenced_RejectsModelPolicyReferences(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gatewayID := seedGateway(t, f.gateway, "role-guard-detach-conflict")
	registryID := seedRegistry(t, f.registry, gatewayID, "role-guard-detach-conflict-registry")
	role := validRole(t, gatewayID, "role-guard-detach-conflict")
	role.ModelPolicies = domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}}
	saveWithRegistry(t, f, role, registryID)

	_, err := f.repo.DetachRegistryIfUnreferenced(ctx, gatewayID, role.ID, registryID)
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	got, err := f.repo.FindByID(ctx, role.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.RegistryIDs) != 1 || got.RegistryIDs[0] != registryID {
		t.Fatalf("RegistryIDs = %v, want [%s]", got.RegistryIDs, registryID)
	}
}

func TestRepository_Update_RejectsModelPolicyReferenceAfterDetach(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gatewayID := seedGateway(t, f.gateway, "role-guard-update-stale")
	registryID := seedRegistry(t, f.registry, gatewayID, "role-guard-update-stale-registry")
	role := validRole(t, gatewayID, "role-guard-update-stale")
	saveWithRegistry(t, f, role, registryID)
	if _, err := f.repo.DetachRegistryIfUnreferenced(ctx, gatewayID, role.ID, registryID); err != nil {
		t.Fatalf("DetachRegistryIfUnreferenced: %v", err)
	}

	role.ModelPolicies = domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}}
	role.UpdatedAt = time.Now().UTC()
	err := f.repo.Update(ctx, role)
	if !errors.Is(err, domain.ErrInvalidModelPolicy) {
		t.Fatalf("err = %v, want ErrInvalidModelPolicy", err)
	}
}
