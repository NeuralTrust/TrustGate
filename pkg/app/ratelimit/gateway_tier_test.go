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

package ratelimit

import (
	"context"
	"errors"
	"testing"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
)

func stampedGatewayEntitlements(tier string, burst, quota, maxInst int) gatewaydomain.Entitlements {
	return gatewaydomain.Entitlements{
		Tier:          tier,
		BurstPerMin:   &burst,
		QuotaPerMonth: &quota,
		MaxInstances:  &maxInst,
	}
}

func TestGatewayTierLoader_PrefersContextGateway(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	loader := NewGatewayTierLoader(finder)

	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{
		ID:           gatewayID,
		Entitlements: stampedGatewayEntitlements("standard", 300, 100_000, 5),
	}
	ctx := appgateway.WithGateway(context.Background(), gw)

	limits, err := loader.Limits(ctx, gatewayID)
	if err != nil {
		t.Fatalf("Limits: %v", err)
	}
	want := stubTierLimits[domain.TierStandard]
	if limits != want {
		t.Fatalf("limits = %+v, want %+v", limits, want)
	}
	finder.AssertNotCalled(t, "FindByID")
}

func TestGatewayTierLoader_FallsBackToFinder(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{
		ID:           gatewayID,
		Entitlements: stampedGatewayEntitlements("enterprise", 1_000, 0, 5),
	}
	finder.EXPECT().FindByID(context.Background(), gatewayID).Return(gw, nil).Once()

	loader := NewGatewayTierLoader(finder)
	limits, err := loader.Limits(context.Background(), gatewayID)
	if err != nil {
		t.Fatalf("Limits: %v", err)
	}
	want := stubTierLimits[domain.TierEnterprise]
	if limits != want {
		t.Fatalf("limits = %+v, want %+v", limits, want)
	}
}

func TestGatewayTierLoader_UnstampedFromContextUnavailable(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	loader := NewGatewayTierLoader(finder)

	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{ID: gatewayID, Entitlements: gatewaydomain.Entitlements{Tier: "standard"}}
	ctx := appgateway.WithGateway(context.Background(), gw)

	_, err := loader.Limits(ctx, gatewayID)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	finder.AssertNotCalled(t, "FindByID")
}

func TestGatewayTierLoader_UsesStampedLimits(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	loader := NewGatewayTierLoader(finder)

	burst, quota, maxInst := 12, 34, 5
	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{
		ID: gatewayID,
		Entitlements: gatewaydomain.Entitlements{
			Tier:          "free",
			BurstPerMin:   &burst,
			QuotaPerMonth: &quota,
			MaxInstances:  &maxInst,
		},
	}
	ctx := appgateway.WithGateway(context.Background(), gw)

	limits, err := loader.Limits(ctx, gatewayID)
	if err != nil {
		t.Fatalf("Limits: %v", err)
	}
	if limits.BurstPerMin != 12 || limits.QuotaPerMonth != 34 || limits.MaxInstances != 5 {
		t.Fatalf("limits = %+v, want stamped 12/34/5", limits)
	}
}

func TestGatewayTierLoader_UnstampedFromFinderUnavailable(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{ID: gatewayID, Entitlements: gatewaydomain.Entitlements{Tier: "free"}}
	finder.EXPECT().FindByID(context.Background(), gatewayID).Return(gw, nil).Once()

	loader := NewGatewayTierLoader(finder)
	_, err := loader.Limits(context.Background(), gatewayID)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestGatewayTierLoader_FinderErrorPropagates(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	finder.EXPECT().FindByID(context.Background(), gatewayID).Return(nil, gatewaydomain.ErrNotFound).Once()

	loader := NewGatewayTierLoader(finder)
	_, err := loader.Limits(context.Background(), gatewayID)
	if !errors.Is(err, gatewaydomain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestGatewayTierLoader_NilContextGatewayIsNotFound(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	loader := NewGatewayTierLoader(finder)

	gatewayID := ids.New[ids.GatewayKind]()
	ctx := appgateway.WithGateway(context.Background(), nil)

	_, err := loader.Limits(ctx, gatewayID)
	if !errors.Is(err, gatewaydomain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	finder.AssertNotCalled(t, "FindByID")
}
