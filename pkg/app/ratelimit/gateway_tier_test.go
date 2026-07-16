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
)

func TestGatewayTierLoader_PrefersContextGateway(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	loader := NewGatewayTierLoader(finder)

	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{ID: gatewayID, Entitlements: gatewaydomain.Entitlements{Tier: " Standard "}}
	ctx := appgateway.WithGateway(context.Background(), gw)

	tier, err := loader.Tier(ctx, gatewayID)
	if err != nil {
		t.Fatalf("Tier: %v", err)
	}
	if tier != "Standard" {
		t.Fatalf("tier = %q, want trimmed %q", tier, "Standard")
	}
	finder.AssertNotCalled(t, "FindByID")
}

func TestGatewayTierLoader_FallsBackToFinder(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{ID: gatewayID, Entitlements: gatewaydomain.Entitlements{Tier: "enterprise"}}
	finder.EXPECT().FindByID(context.Background(), gatewayID).Return(gw, nil).Once()

	loader := NewGatewayTierLoader(finder)
	tier, err := loader.Tier(context.Background(), gatewayID)
	if err != nil {
		t.Fatalf("Tier: %v", err)
	}
	if tier != "enterprise" {
		t.Fatalf("tier = %q, want enterprise", tier)
	}
}

func TestGatewayTierLoader_FinderErrorPropagates(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	gatewayID := ids.New[ids.GatewayKind]()
	finder.EXPECT().FindByID(context.Background(), gatewayID).Return(nil, gatewaydomain.ErrNotFound).Once()

	loader := NewGatewayTierLoader(finder)
	_, err := loader.Tier(context.Background(), gatewayID)
	if !errors.Is(err, gatewaydomain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestGatewayTierLoader_NilContextGatewayIsNotFound(t *testing.T) {
	finder := gatewaymocks.NewFinder(t)
	loader := NewGatewayTierLoader(finder)

	gatewayID := ids.New[ids.GatewayKind]()
	ctx := appgateway.WithGateway(context.Background(), nil)

	_, err := loader.Tier(ctx, gatewayID)
	if !errors.Is(err, gatewaydomain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	finder.AssertNotCalled(t, "FindByID")
}
