// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"context"
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type fakePolicies struct {
	items []*storeaccessdomain.Policy
	err   error
}

func (f *fakePolicies) ListPoliciesByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Policy, error) {
	return f.items, f.err
}

func policy(gw ids.GatewayID, typ storeaccessdomain.PrincipalType, id, mode string) *storeaccessdomain.Policy {
	p, err := storeaccessdomain.NewPolicy(gw, typ, id, mode)
	if err != nil {
		panic(err)
	}
	return p
}

// openGatewayCtx is a principal (with groups) on a gateway whose default is All.
func openGatewayCtx(sub string, groups ...string) context.Context {
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: sub, Claims: map[string]any{identity.ClaimGroups: groups},
	})
	return appgateway.WithGateway(ctx, &gatewaydomain.Gateway{})
}

// TestModeResolverLivePolicyOverridesDefaultAndClaim: the admin's policy is read
// on every request — it narrows a user on an All gateway at once, and beats a
// stale token claim minted before the admin changed their mind.
func TestModeResolverLivePolicyOverridesDefaultAndClaim(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	r := NewModeResolver(&fakePolicies{items: []*storeaccessdomain.Policy{
		policy(gw, storeaccessdomain.PrincipalUser, "ana", gatewaydomain.StoreModeCurated),
		policy(gw, storeaccessdomain.PrincipalGroup, "sre", gatewaydomain.StoreModeNone),
	}})
	if got := r.Mode(openGatewayCtx("ana"), gw); got != gatewaydomain.StoreModeCurated {
		t.Fatalf("own policy must narrow an All gateway, got %q", got)
	}
	if got := r.Mode(openGatewayCtx("bob", "sre"), gw); got != gatewaydomain.StoreModeNone {
		t.Fatalf("group policy must apply, got %q", got)
	}
	if got := r.Mode(openGatewayCtx("carol"), gw); got != gatewaydomain.StoreModeOpen {
		t.Fatalf("no policy → gateway default, got %q", got)
	}
	// A stale claim from an earlier login loses to the live policy…
	stale := appgateway.WithGateway(identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: "ana", Claims: map[string]any{identity.ClaimStoreAccess: gatewaydomain.StoreModeOpen},
	}), &gatewaydomain.Gateway{})
	if got := r.Mode(stale, gw); got != gatewaydomain.StoreModeCurated {
		t.Fatalf("live policy must beat a stale claim, got %q", got)
	}
	// …but still applies to a principal with no policy (legacy fallback).
	legacy := appgateway.WithGateway(identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: "dave", Claims: map[string]any{identity.ClaimStoreAccess: gatewaydomain.StoreModeNone},
	}), &gatewaydomain.Gateway{})
	if got := r.Mode(legacy, gw); got != gatewaydomain.StoreModeNone {
		t.Fatalf("claim must remain the fallback without a policy, got %q", got)
	}
}

func TestModeResolverFailsClosedOnLookupError(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	r := NewModeResolver(&fakePolicies{err: errors.New("db down")})
	if got := r.Mode(openGatewayCtx("ana"), gw); got != gatewaydomain.StoreModeCurated {
		t.Fatalf("a policy read error must fail closed to curated, got %q", got)
	}
}

func TestModeResolverWithoutPoliciesFallsBack(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	if got := NewModeResolver(nil).Mode(openGatewayCtx("ana"), gw); got != gatewaydomain.StoreModeOpen {
		t.Fatalf("no reader → EffectiveStoreMode (gateway default), got %q", got)
	}
	if got := NewModeResolver(nil).Mode(context.Background(), gw); got != gatewaydomain.StoreModeCurated {
		t.Fatalf("no gateway in context fails closed, got %q", got)
	}
}

// TestScoperUsesLivePolicy: an install exposed under All disappears the moment
// the admin sets the principal to Selected without a grant — no re-login.
func TestScoperUsesLivePolicy(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	policies := &fakePolicies{}
	sc, err := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "github")}},
		&fakeRegistries{items: []*registrydomain.Registry{githubRegistry()}},
		&fakeGrants{},
		WithScoperModes(NewModeResolver(policies)),
	)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	if scoped, _ := sc.Scope(openGatewayCtx("ana"), rc); len(scoped.Registries) != 1 {
		t.Fatal("under the All default the install must be exposed")
	}
	policies.items = []*storeaccessdomain.Policy{policy(gw, storeaccessdomain.PrincipalUser, "ana", gatewaydomain.StoreModeCurated)}
	if scoped, _ := sc.Scope(openGatewayCtx("ana"), rc); len(scoped.Registries) != 0 {
		t.Fatal("once the principal is Selected with no grant the install must vanish at once")
	}
}
