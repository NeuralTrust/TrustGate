//go:build functional

package registry_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	consumerrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
)

func TestRegistryDeletePrunesSmartRoutingInMainTransaction(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cuts     []float64
		legacy   bool
		victim   int
		survives bool
	}{
		{"canonical_middle", []float64{0, .187, .45}, false, 1, true},
		{"canonical_top", []float64{0, .187, .45}, false, 2, false},
		{"legacy_nonzero_floor", []float64{.11, .27, .53, .81}, true, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, gw, conn := setupRepo(t)
			ctx := context.Background()
			gatewayID := seedGateway(t, gw, tc.name)
			params := consumer.CreateParams{GatewayID: gatewayID, Name: "router", Type: consumer.TypeLLM,
				ModelPolicies: consumer.ModelPolicies{}, LBConfig: &consumer.LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting,
					SmartRouting: &registry.SmartRoutingConfig{LegacyThresholds: tc.legacy, SR1: &registry.SR1Config{CacheTTLSeconds: 123, EscapeHatchEnabled: true}}}}
			for i, cut := range tc.cuts {
				b := validRegistry(t, gatewayID, string(rune('a'+i)))
				if err := r.Save(ctx, b); err != nil {
					t.Fatal(err)
				}
				model := string(rune('a' + i))
				params.RegistryIDs = append(params.RegistryIDs, b.ID)
				params.ModelPolicies[b.ID] = consumer.ModelPolicy{Allowed: []string{model}}
				params.LBConfig.Members = append(params.LBConfig.Members, consumer.LBPoolMember{RegistryID: b.ID, Model: model})
				params.LBConfig.SmartRouting.Tiers = append(params.LBConfig.SmartRouting.Tiers, registry.SmartRoutingTier{RegistryID: b.ID, Model: model, MinScore: cut})
			}
			c, err := consumer.New(params)
			if err != nil {
				t.Fatal(err)
			}
			cr := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn))
			if err := cr.Save(ctx, c); err != nil {
				t.Fatal(err)
			}
			original := append([]registry.SmartRoutingTier(nil), c.LBConfig.SmartRouting.Tiers...)
			victim := original[tc.victim].RegistryID
			if err := r.Delete(ctx, gatewayID, victim); err != nil {
				t.Fatal(err)
			}
			got, err := cr.FindByID(ctx, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("invalid persisted consumer: %v", err)
			}
			if _, exists := got.ModelPolicies[victim]; exists {
				t.Fatal("deleted policy retained")
			}
			if (got.LBConfig.SmartRouting != nil) != tc.survives {
				t.Fatalf("survival mismatch: %+v", got.LBConfig)
			}
			if !tc.survives {
				return
			}
			want := append(original[:tc.victim:tc.victim], original[tc.victim+1:]...)
			if !reflect.DeepEqual(got.LBConfig.SmartRouting.Tiers, want) {
				t.Fatal("survivor pins/cuts changed")
			}
			if got.LBConfig.SmartRouting.SR1.CacheTTLSeconds != 123 || !got.LBConfig.SmartRouting.SR1.EscapeEnabled() {
				t.Fatal("policy settings changed")
			}
			if !tc.legacy {
				return
			}
			for len(want) > 1 {
				if err := r.Delete(ctx, gatewayID, want[0].RegistryID); err != nil {
					t.Fatal(err)
				}
				want = want[1:]
				got, err = cr.FindByID(ctx, c.ID)
				if err != nil {
					t.Fatal(err)
				}
				if err := got.Validate(); err != nil {
					t.Fatal(err)
				}
				if len(want) == 1 {
					if got.LBConfig.Algorithm != algorithm.RoundRobin || got.LBConfig.SmartRouting != nil || len(got.LBConfig.Members) != 1 || got.LBConfig.Members[0].RegistryID != want[0].RegistryID || got.LBConfig.Members[0].RouteModel() != want[0].RouteModel() {
						t.Fatal("sole survivor not pinned")
					}
				} else if !got.LBConfig.SmartRouting.LegacyThresholds || !reflect.DeepEqual(got.LBConfig.SmartRouting.Tiers, want) {
					t.Fatal("legacy cuts lost after pruning")
				}
			}
		})
	}
}

func TestRegistryDeletePreservesMainFixedFallbackRestriction(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gatewayID := seedGateway(t, gw, "fixed-fallback")
	b := validRegistry(t, gatewayID, "fixed")
	if err := r.Save(ctx, b); err != nil {
		t.Fatal(err)
	}
	c, err := consumer.New(consumer.CreateParams{GatewayID: gatewayID, Name: "fixed", Type: consumer.TypeLLM,
		RegistryIDs: []ids.RegistryID{b.ID}, Fallback: &consumer.Fallback{Enabled: true, Triggers: []consumer.FallbackTrigger{consumer.TriggerHTTP5xx}, Chain: registry.Registries{b.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	cr := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn))
	if err := cr.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, gatewayID, b.ID); !errors.Is(err, registry.ErrHasDependents) {
		t.Fatalf("error=%v", err)
	}
	if _, err := r.FindByID(ctx, b.ID); err != nil {
		t.Fatal("registry was deleted")
	}
	got, err := cr.FindByID(ctx, c.ID)
	if err != nil || !reflect.DeepEqual(got.Fallback, c.Fallback) {
		t.Fatal("fixed fallback changed")
	}
}

func TestConsumerCreationWaitsForGatewayRoutingLock(t *testing.T) {
	_, gw, conn := setupRepo(t)
	ctx := context.Background()
	gatewayID := seedGateway(t, gw, "serialized")
	tx, err := conn.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := database.LockGatewayRouting(ctx, tx, gatewayID); err != nil {
		t.Fatal(err)
	}
	c, err := consumer.New(consumer.CreateParams{GatewayID: gatewayID, Name: "new", Type: consumer.TypeLLM})
	if err != nil {
		t.Fatal(err)
	}
	cr := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn))
	done := make(chan error, 1)
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	go func() { done <- cr.Save(requestCtx, c) }()
	select {
	case err := <-done:
		t.Fatalf("write bypassed gateway lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
