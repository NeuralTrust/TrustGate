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
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// retiringPlugin declares settings keys it ignores.
type retiringPlugin struct {
	appplugins.Plugin
	retired []string
}

func (p retiringPlugin) RetiredSettings() []string { return p.retired }

func retiredRegistryMock(t *testing.T) *pluginmocks.Registry {
	t.Helper()
	reg := newValidatingRegistryMock(t, nil)
	reg.EXPECT().Get("guard").Return(retiringPlugin{
		Plugin:  pluginmocks.NewPlugin(t),
		retired: []string{"on_error", "timeout", "streaming.on_error", "streaming.guard_timeout"},
	}, true).Maybe()
	reg.EXPECT().Get("plain").Return(pluginmocks.NewPlugin(t), true).Maybe()
	return reg
}

func staleSettings() map[string]any {
	return map[string]any{
		"collector_id": "keep",
		"ON_ERROR":     "fail_closed",
		"Timeout":      "5m",
		"streaming": map[string]any{
			"enabled":       true,
			"On_Error":      "fail_closed",
			"GUARD_TIMEOUT": "1ms",
		},
	}
}

func cleanSettings() map[string]any {
	return map[string]any{
		"collector_id": "keep",
		"streaming":    map[string]any{"enabled": true},
	}
}

func TestCreator_Create_DropsRetiredSettings(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	var saved map[string]any
	repo.EXPECT().Save(mock.Anything, mock.Anything).
		Run(func(_ context.Context, p *domain.Policy) { saved = p.Settings }).
		Return(nil).Once()
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), retiredRegistryMock(t), newCacheManager(), newTestLogger(), nil)

	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Slug = "guard"
	in.Settings = staleSettings()
	_, err := creator.Create(context.Background(), in)

	require.NoError(t, err)
	assert.Equal(t, cleanSettings(), saved)
	assert.Contains(t, in.Settings, "ON_ERROR", "the caller's map is not edited")
}

func updateRetired(t *testing.T, existing *domain.Policy, in apppolicy.UpdateInput) map[string]any {
	t.Helper()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	var saved map[string]any
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).
		Run(func(_ context.Context, p *domain.Policy, _ bool) { saved = p.Settings }).
		Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).Return(nil).Maybe()
	in.ID = existing.ID
	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), retiredRegistryMock(t), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), in)
	require.NoError(t, err)
	return saved
}

func TestUpdater_Update_DropsRetiredSettings(t *testing.T) {
	t.Parallel()
	stale := staleSettings()
	saved := updateRetired(t, storedPolicy(t, "guard", map[string]any{"collector_id": "keep"}), apppolicy.UpdateInput{Settings: &stale})
	assert.Equal(t, cleanSettings(), saved)
}

func TestUpdater_Update_SlugChangeDropsRetiredSettingsFromTheStoredOnes(t *testing.T) {
	t.Parallel()
	saved := updateRetired(t, storedPolicy(t, "plain", staleSettings()), apppolicy.UpdateInput{Slug: ptr("guard")})
	assert.Equal(t, cleanSettings(), saved)
}

func TestUpdater_Update_KeepsKeysOfAPluginThatRetiresNone(t *testing.T) {
	t.Parallel()
	stale := staleSettings()
	saved := updateRetired(t, storedPolicy(t, "plain", nil), apppolicy.UpdateInput{Settings: &stale})
	assert.Equal(t, staleSettings(), saved)
}
