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

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type availabilityGateways struct {
	gw  *gatewaydomain.Gateway
	err error
}

func (f availabilityGateways) FindByID(context.Context, ids.GatewayID) (*gatewaydomain.Gateway, error) {
	return f.gw, f.err
}

type availabilityInstances struct {
	scopes    []string
	instances []dataplane.Instance
	err       error
}

func (f *availabilityInstances) ListInstances(_ context.Context, scope string) ([]dataplane.Instance, error) {
	f.scopes = append(f.scopes, scope)
	return f.instances, f.err
}

func TestLLMAvailability(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	gatewayID := ids.New[ids.GatewayKind]()
	hybrid := &gatewaydomain.Gateway{ID: gatewayID, Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHybrid}}

	t.Run("hosted gateway never reads instances", func(t *testing.T) {
		t.Parallel()
		instances := &availabilityInstances{}
		svc := appstore.NewLLMAvailabilityService(availabilityGateways{gw: &gatewaydomain.Gateway{ID: gatewayID}}, instances, clock)
		got, err := svc.LLMAvailability(context.Background(), gatewayID)
		require.NoError(t, err)
		assert.Equal(t, dataplane.HostedStoreAvailability(), got)
		assert.Empty(t, instances.scopes)
	})

	t.Run("hybrid gateway reads its own scope", func(t *testing.T) {
		t.Parallel()
		instances := &availabilityInstances{instances: []dataplane.Instance{{State: "connected", LastSeen: now, Version: "v0.70.0"}}}
		svc := appstore.NewLLMAvailabilityService(availabilityGateways{gw: hybrid}, instances, clock)
		got, err := svc.LLMAvailability(context.Background(), gatewayID)
		require.NoError(t, err)
		assert.Equal(t, dataplane.StoreDataPlaneOutdated, got.Reason)
		assert.Equal(t, "v0.70.0", got.LowestVersion)
		assert.Equal(t, []string{gatewayID.String()}, instances.scopes)
	})

	t.Run("errors propagate", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		_, err := appstore.NewLLMAvailabilityService(availabilityGateways{err: boom}, &availabilityInstances{}, clock).LLMAvailability(context.Background(), gatewayID)
		require.ErrorIs(t, err, boom)
		_, err = appstore.NewLLMAvailabilityService(availabilityGateways{gw: hybrid}, &availabilityInstances{err: boom}, clock).LLMAvailability(context.Background(), gatewayID)
		require.ErrorIs(t, err, boom)
	})
}
