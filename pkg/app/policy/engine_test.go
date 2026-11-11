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

package policy_test

import (
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type enginesOf map[string]bool

func (e enginesOf) TrustGuardV2(_ context.Context, gatewayID string) bool { return e[gatewayID] }

func TestCreator_Create_RefusesTheOtherTrustGuard(t *testing.T) {
	t.Parallel()
	v1Gateway, v2Gateway := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	engines := enginesOf{v2Gateway.String(): true}
	cases := map[string]struct {
		gateway ids.GatewayID
		slug    string
		refused bool
	}{
		"v2 plugin on a v1 gateway": {v1Gateway, appplugins.SlugTrustGuardV2, true},
		"v1 plugin on a v2 gateway": {v2Gateway, appplugins.SlugTrustGuard, true},
		"v1 plugin on a v1 gateway": {v1Gateway, appplugins.SlugTrustGuard, false},
		"v2 plugin on a v2 gateway": {v2Gateway, appplugins.SlugTrustGuardV2, false},
		"any other plugin":          {v2Gateway, "rate_limiter", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			repo := repomocks.NewRepository(t)
			if !tc.refused {
				repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
			}
			creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), newTestLogger(), nil,
				apppolicy.WithGatewayEngines(engines))
			in := validCreateInput(tc.gateway)
			in.Slug = tc.slug

			_, err := creator.Create(context.Background(), in)
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, commonerrors.ErrValidation)
			require.ErrorIs(t, err, appplugins.ErrWrongTrustGuardEngine)
		})
	}
}

func TestUpdater_Update_RefusesTheOtherTrustGuard(t *testing.T) {
	t.Parallel()
	existing := existingPolicy(t)
	existing.Slug = appplugins.SlugTrustGuard
	engines := enginesOf{existing.GatewayID.String(): true}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Times(3)
	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil,
		apppolicy.WithGatewayEngines(engines))

	// Settings written on a v1 plugin of a v2 gateway.
	in := validUpdateInput(existing.ID)
	in.Slug = ptr(appplugins.SlugTrustGuard)
	in.Settings = ptr(map[string]any{"direction": "request"})
	_, err := updater.Update(context.Background(), in)
	require.ErrorIs(t, err, appplugins.ErrWrongTrustGuardEngine)

	// A slug change to the v1 plugin on a v2 gateway.
	existing.Slug = "rate_limiter"
	in = validUpdateInput(existing.ID)
	in.Slug = ptr(appplugins.SlugTrustGuard)
	_, err = updater.Update(context.Background(), in)
	require.ErrorIs(t, err, appplugins.ErrWrongTrustGuardEngine)
	require.ErrorIs(t, err, commonerrors.ErrValidation)

	// A v2 gateway's v2 plugin is fine, and a rename that writes no settings is not asked at all.
	existing.Slug = appplugins.SlugTrustGuard
	in = validUpdateInput(existing.ID)
	in.Slug = ptr(appplugins.SlugTrustGuardV2)
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).Return(nil).Once()
	updater = apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil,
		apppolicy.WithGatewayEngines(engines))
	_, err = updater.Update(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, appplugins.SlugTrustGuardV2, existing.Slug)
}
