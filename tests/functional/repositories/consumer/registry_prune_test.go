//go:build functional

package consumer_test

import (
	"context"
	"slices"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
)

func newPruningRegistryRepo(conn *database.Connection, consumers *repo.Repository) *registryrepo.Repository {
	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		panic(err)
	}
	return registryrepo.NewRepository(
		conn,
		cipher,
		outboxrepo.NewRepository(conn),
		registryrepo.WithDeleteHook(consumers.PruneRegistryReferencesTx),
	)
}

func assertPrunedConsumer(
	t *testing.T,
	report registrydomain.PruneReport,
	consumerID ids.ConsumerID,
	wantRewritten, wantNulled []string,
) {
	t.Helper()
	for _, prune := range report.Consumers {
		if prune.ConsumerID != consumerID {
			continue
		}
		if !slices.Equal(prune.Rewritten, wantRewritten) {
			t.Fatalf("Rewritten = %v, want %v", prune.Rewritten, wantRewritten)
		}
		if !slices.Equal(prune.Nulled, wantNulled) {
			t.Fatalf("Nulled = %v, want %v", prune.Nulled, wantNulled)
		}
		return
	}
	t.Fatalf("prune report %+v does not mention consumer %s", report.Consumers, consumerID)
}

func smartRoutingConsumer(
	t *testing.T,
	gwID ids.GatewayID,
	name string,
	keeper, victim ids.RegistryID,
	tiers []registrydomain.SmartRoutingTier,
) *domain.Consumer {
	t.Helper()
	c, err := domain.New(domain.CreateParams{
		GatewayID:   gwID,
		Name:        name,
		Type:        domain.TypeLLM,
		RegistryIDs: []ids.RegistryID{keeper, victim},
		ModelPolicies: domain.ModelPolicies{
			keeper: {Allowed: []string{"gpt-4o"}},
			victim: {Allowed: []string{"gpt-4.1-nano"}},
		},
		LBConfig: &domain.LBConfig{
			Enabled:   true,
			Algorithm: algorithm.SmartRouting,
			PoolAlias: "prune-pool",
			Members: []domain.LBPoolMember{
				{RegistryID: victim, Model: "gpt-4.1-nano"},
				{RegistryID: keeper, Model: "gpt-4o"},
			},
			SmartRouting: &registrydomain.SmartRoutingConfig{Tiers: tiers},
		},
	})
	if err != nil {
		t.Fatalf("consumer domain.New: %v", err)
	}
	return c
}

func TestRepository_DeleteRegistry_PrunesRoutingReferences(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "gw-prune-tier")
	keeper := seedRegistry(t, f.be, gwID, "prune-keeper")
	victim := seedRegistry(t, f.be, gwID, "prune-victim")

	c := smartRoutingConsumer(t, gwID, "tiered-consumer", keeper, victim,
		[]registrydomain.SmartRoutingTier{
			{MinScore: 0, RegistryID: keeper, Model: "gpt-4o"},
			{MinScore: 0.6, RegistryID: victim, Model: "gpt-4.1-nano"},
		})
	saveWithRegistries(t, f, c)

	registries := newPruningRegistryRepo(f.conn, f.repo)
	report, err := registries.Delete(ctx, gwID, victim)
	if err != nil {
		t.Fatalf("Delete: %v, want the routing references pruned", err)
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
	if got.LBConfig.SmartRouting == nil {
		t.Fatal("SmartRouting was dropped even though the floor tier remains")
	}
	for _, tier := range got.LBConfig.SmartRouting.Tiers {
		if tier.RegistryID == victim {
			t.Fatalf("smart_routing tiers still reference %s: %+v", victim, got.LBConfig.SmartRouting.Tiers)
		}
	}
	if got.LBConfig.Algorithm != algorithm.SmartRouting {
		t.Fatalf("Algorithm = %q, want it untouched while the ladder survives", got.LBConfig.Algorithm)
	}
	if len(got.RegistryIDs) != 1 || got.RegistryIDs[0] != keeper {
		t.Fatalf("RegistryIDs = %v, want [%s]", got.RegistryIDs, keeper)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("pruned consumer no longer validates: %v", err)
	}
}

// RUN-1501: deleting the registry the cheapest tier points at raises the
// ladder's floor, so keeping the ladder would re-target every score under the
// new floor to the pricier survivor. The ladder goes instead and the pool
// degrades to its plain algorithm.
func TestRepository_DeleteRegistry_DropsLadderThatLosesItsCheapestTier(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "gw-prune-floor")
	keeper := seedRegistry(t, f.be, gwID, "floor-keeper")
	victim := seedRegistry(t, f.be, gwID, "floor-victim")

	c := smartRoutingConsumer(t, gwID, "floor-consumer", keeper, victim,
		[]registrydomain.SmartRoutingTier{
			{MinScore: 0, RegistryID: victim, Model: "gpt-4.1-nano"},
			{MinScore: 0.6, RegistryID: keeper, Model: "gpt-4o"},
		})
	saveWithRegistries(t, f, c)

	registries := newPruningRegistryRepo(f.conn, f.repo)
	report, err := registries.Delete(ctx, gwID, victim)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertPrunedConsumer(t, report, c.ID,
		[]string{registrydomain.PrunedModelPolicies, registrydomain.PrunedLBConfig},
		[]string{registrydomain.PrunedSmartRouting})

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.LBConfig == nil {
		t.Fatal("LBConfig was dropped, losing the surviving member and the pool alias")
	}
	if got.LBConfig.SmartRouting != nil {
		t.Fatalf("SmartRouting = %+v, want nil", got.LBConfig.SmartRouting)
	}
	if got.LBConfig.Algorithm != algorithm.RoundRobin {
		t.Fatalf("Algorithm = %q, want %q", got.LBConfig.Algorithm, algorithm.RoundRobin)
	}
	if got.LBConfig.PoolAlias != "prune-pool" {
		t.Fatalf("PoolAlias = %q, want it preserved", got.LBConfig.PoolAlias)
	}
	if len(got.LBConfig.Members) != 1 || got.LBConfig.Members[0].RegistryID != keeper {
		t.Fatalf("Members = %+v, want only the keeper", got.LBConfig.Members)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("pruned consumer no longer validates: %v", err)
	}
}

func TestRepository_DeleteRegistry_PrunesInactiveConsumerFallback(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "gw-prune-fallback")
	keeper := seedRegistry(t, f.be, gwID, "fallback-keeper")
	victim := seedRegistry(t, f.be, gwID, "fallback-victim")

	c := validConsumer(t, gwID, "inactive-fallback-consumer", keeper)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{victim, keeper},
	}
	saveWithRegistries(t, f, c)
	if _, err := f.conn.Pool.Exec(ctx, "UPDATE consumers SET active = FALSE WHERE id = $1", c.ID); err != nil {
		t.Fatalf("deactivate consumer: %v", err)
	}

	registries := newPruningRegistryRepo(f.conn, f.repo)
	report, err := registries.Delete(ctx, gwID, victim)
	if err != nil {
		t.Fatalf("Delete: %v, want success on an inactive consumer", err)
	}
	assertPrunedConsumer(t, report, c.ID, []string{registrydomain.PrunedFallback}, nil)

	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Fallback == nil {
		t.Fatal("Fallback was dropped even though the keeper step remains")
	}
	if len(got.Fallback.Chain) != 1 || got.Fallback.Chain[0] != keeper {
		t.Fatalf("Chain = %v, want [%s]", got.Fallback.Chain, keeper)
	}
}

func TestRepository_DeleteRegistry_PruneKeepsUnrelatedGatewayConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwVictim := seedGateway(t, f.gw, "gw-prune-owner")
	gwOther := seedGateway(t, f.gw, "gw-prune-other")
	victim := seedRegistry(t, f.be, gwVictim, "cross-victim")
	otherReg := seedRegistry(t, f.be, gwOther, "cross-keeper")

	other := validConsumer(t, gwOther, "cross-gw-untouched", otherReg)
	other.ModelPolicies = domain.ModelPolicies{otherReg: {Allowed: []string{"gpt-4o"}}}
	saveWithRegistries(t, f, other)

	registries := newPruningRegistryRepo(f.conn, f.repo)
	report, err := registries.Delete(ctx, gwVictim, victim)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !report.Empty() {
		t.Fatalf("report = %+v, want no consumer changed", report.Consumers)
	}

	got, err := f.repo.FindByID(ctx, other.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if _, ok := got.ModelPolicies[otherReg]; !ok {
		t.Fatalf("ModelPolicies = %+v, want the other gateway's policy untouched", got.ModelPolicies)
	}
}
