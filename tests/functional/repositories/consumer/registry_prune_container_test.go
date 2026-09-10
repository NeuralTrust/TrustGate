//go:build functional

package consumer_test

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/container/modules"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pointContainerAtTestDatabase rewrites the DB_* environment the real config
// loader reads so modules.All builds its own graph against PG_TEST_URL.
func pointContainerAtTestDatabase(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping registry container wiring test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PG_TEST_URL: %v", err)
	}
	sslMode := "disable"
	if cfg.ConnConfig.TLSConfig != nil {
		sslMode = "require"
	}
	t.Setenv("DB_HOST", cfg.ConnConfig.Host)
	t.Setenv("DB_PORT", strconv.Itoa(int(cfg.ConnConfig.Port)))
	t.Setenv("DB_USER", cfg.ConnConfig.User)
	t.Setenv("DB_PASSWORD", cfg.ConnConfig.Password)
	t.Setenv("DB_NAME", cfg.ConnConfig.Database)
	t.Setenv("DB_SSL_MODE", sslMode)
	t.Setenv("SERVER_SECRET_KEY", "functional-container-secret-0123456789abcdef")
}

// RUN-1501: the hand-built repositories the other prune tests use pass even with
// the DI wiring deleted, so this one resolves registry.Repository out of the real
// modules.All("admin", false) graph and asserts a delete through it prunes a
// seeded consumer. A Registry module that stops receiving the consumer
// repository fails here (or fails container construction) instead of shipping a
// DELETE that answers 204 and leaves the references behind.
func TestContainerGraph_RegistryDelete_PrunesConsumerRouting(t *testing.T) {
	f := setupRepo(t)
	pointContainerAtTestDatabase(t)
	ctx := context.Background()

	gwID := seedGateway(t, f.gw, "gw-container-prune")
	keeper := seedRegistry(t, f.be, gwID, "container-keeper")
	victim := seedRegistry(t, f.be, gwID, "container-victim")
	c := smartRoutingConsumer(t, gwID, "container-consumer", keeper, victim,
		[]registrydomain.SmartRoutingTier{
			{MinScore: 0, RegistryID: keeper, Model: "gpt-4o"},
			{MinScore: 0.6, RegistryID: victim, Model: "gpt-4.1-nano"},
		})
	saveWithRegistries(t, f, c)

	graph, err := container.New(modules.All("admin", false)...)
	if err != nil {
		t.Fatalf("container.New(modules.All): %v", err)
	}
	if err := graph.Invoke(func(conn *database.Connection) {
		t.Cleanup(conn.Pool.Close)
	}); err != nil {
		t.Fatalf("resolve database connection: %v", err)
	}

	var report registrydomain.PruneReport
	if err := graph.Invoke(func(repo registrydomain.Repository) error {
		var deleteErr error
		report, deleteErr = repo.Delete(ctx, gwID, victim)
		return deleteErr
	}); err != nil {
		t.Fatalf("registry delete through the container graph: %v", err)
	}
	assertPrunedConsumer(t, report, c.ID,
		[]string{registrydomain.PrunedModelPolicies, registrydomain.PrunedLBConfig}, nil)

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if _, ok := got.ModelPolicies[victim]; ok {
		t.Fatalf("ModelPolicies still reference %s: %+v", victim, got.ModelPolicies)
	}
	if got.LBConfig == nil {
		t.Fatal("LBConfig was dropped even though the keeper member and floor tier remain")
	}
	for _, member := range got.LBConfig.Members {
		if member.RegistryID == victim {
			t.Fatalf("lb_config members still reference %s: %+v", victim, got.LBConfig.Members)
		}
	}
	if got.LBConfig.SmartRouting == nil || got.LBConfig.Algorithm != algorithm.SmartRouting {
		t.Fatalf("LBConfig = %+v, want the ladder kept", got.LBConfig)
	}
	for _, tier := range got.LBConfig.SmartRouting.Tiers {
		if tier.RegistryID == victim {
			t.Fatalf("smart_routing tiers still reference %s: %+v", victim, got.LBConfig.SmartRouting.Tiers)
		}
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("pruned consumer no longer validates: %v", err)
	}
}

// RUN-1501: the counterpart guarantee. Registry without Consumer must not build
// at all, so a future container variant cannot silently produce a registry
// repository with no prune hook.
func TestContainerGraph_RegistryWithoutConsumerModuleFailsToResolve(t *testing.T) {
	pointContainerAtTestDatabase(t)

	graph, err := container.New(
		container.WithModule(modules.Core),
		container.WithModule(modules.Cache),
		container.WithModule(modules.Registry),
	)
	if err != nil {
		t.Fatalf("container.New: %v", err)
	}
	err = graph.Invoke(func(repo registrydomain.Repository) {
		t.Fatal("registry.Repository resolved without the Consumer module, so the prune hook is unwired")
	})
	if err == nil {
		t.Fatal("Invoke = nil, want a missing-dependency error for the consumer repository")
	}
	var connCleanup *database.Connection
	if invokeErr := graph.Invoke(func(conn *database.Connection) {
		connCleanup = conn
	}); invokeErr == nil && connCleanup != nil {
		connCleanup.Pool.Close()
	}
	t.Logf("registry repository without the Consumer module: %v", err)
}
