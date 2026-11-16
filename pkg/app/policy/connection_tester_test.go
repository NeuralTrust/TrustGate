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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testerKey = `{"type":"service_account","private_key":"TESTER-KEY-0123456789"}`

type probePlugin struct {
	credDestPlugin
	calls    int
	settings map[string]any
	result   appplugins.ProbeResult
}

func (p *probePlugin) ProbeConnection(_ context.Context, settings map[string]any) appplugins.ProbeResult {
	p.calls++
	p.settings = settings
	return p.result
}

type testerRig struct {
	tester   apppolicy.ConnectionTester
	repo     *repomocks.Repository
	gateways *gatewaymocks.Repository
	registry *pluginmocks.Registry
	plugin   *probePlugin
	logs     *bytes.Buffer
	gateway  ids.GatewayID
}

func newTesterRig(t *testing.T) *testerRig {
	t.Helper()
	r := &testerRig{
		repo:     repomocks.NewRepository(t),
		gateways: gatewaymocks.NewRepository(t),
		registry: pluginmocks.NewRegistry(t),
		logs:     &bytes.Buffer{},
		gateway:  ids.New[ids.GatewayKind](),
	}
	r.plugin = &probePlugin{
		credDestPlugin: credDestPlugin{
			credPlugin: credPlugin{Plugin: pluginmocks.NewPlugin(t), paths: []string{"credentials.service_account_json"}},
			dests:      []string{"location", "project"},
		},
		result: appplugins.ProbeResult{Code: appplugins.ProbeOK, Message: "fine", Latency: 42 * time.Millisecond},
	}
	r.registry.EXPECT().Get(armorSlug).Return(r.plugin, true).Maybe()
	r.registry.EXPECT().Validate(armorSlug, mock.Anything).Return(nil).Maybe()
	r.registry.EXPECT().ValidateSettingsWrite(armorSlug, mock.Anything, mock.Anything).Return(nil).Maybe()
	logger := slog.New(slog.NewTextHandler(r.logs, nil))
	r.tester = apppolicy.NewConnectionTester(r.repo, r.gateways, r.registry, logger)
	return r
}

func (r *testerRig) saasGateway() {
	r.gateways.EXPECT().FindByID(mock.Anything, r.gateway).Return(&gatewaydomain.Gateway{ID: r.gateway}, nil).Once()
}

func armorSettings(key string) map[string]any {
	return map[string]any{
		"project":     "acme",
		"location":    "europe-west4",
		"template":    "tmpl",
		"credentials": map[string]any{"service_account_json": key},
	}
}

func (r *testerRig) stored(t *testing.T, slug string) *domain.Policy {
	t.Helper()
	p := storedPolicy(t, slug, armorSettings(testerKey))
	p.GatewayID = r.gateway
	return p
}

func TestConnectionTesterProbesNewSettings(t *testing.T) {
	t.Parallel()
	r := newTesterRig(t)
	r.saasGateway()
	in := armorSettings(testerKey)

	res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: armorSlug, Settings: in})

	require.NoError(t, err)
	assert.True(t, res.OK)
	assert.Equal(t, appplugins.ProbeOK, res.Code)
	assert.Equal(t, 42*time.Millisecond, res.Latency)
	assert.Equal(t, 1, r.plugin.calls)
	assert.Equal(t, armorSettings(testerKey), in, "the caller's settings are not modified")
	assert.NotContains(t, r.logs.String(), "TESTER-KEY")
	assert.Contains(t, r.logs.String(), "code=ok")
	assert.Contains(t, r.logs.String(), "ok=true")
}

func TestConnectionTesterPassesProbeFailuresThrough(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		appplugins.ProbeInvalidCredentials, appplugins.ProbePermissionDenied, appplugins.ProbeAPIDisabled,
		appplugins.ProbeTemplateNotFound, appplugins.ProbeThrottled, appplugins.ProbeTimeout,
		appplugins.ProbeUnreachable, appplugins.ProbeInvalidConfig,
	} {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			r := newTesterRig(t)
			r.saasGateway()
			r.plugin.result = appplugins.ProbeResult{Code: code, Message: "m"}

			res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: armorSlug, Settings: armorSettings(testerKey)})

			require.NoError(t, err)
			assert.False(t, res.OK)
			assert.Equal(t, code, res.Code)
		})
	}
}

func TestConnectionTesterRefusesHybridGatewaysOnTheControlPlane(t *testing.T) {
	t.Parallel()
	r := newTesterRig(t)
	r.gateways.EXPECT().FindByID(mock.Anything, r.gateway).Return(&gatewaydomain.Gateway{
		ID: r.gateway, Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHybrid},
	}, nil).Once()

	_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: armorSlug, Settings: armorSettings(testerKey)})

	require.ErrorIs(t, err, domain.ErrTestRunsOnDataPlane)
	require.ErrorIs(t, err, commonerrors.ErrConflict)
	assert.Zero(t, r.plugin.calls)
}

func TestConnectionTesterDataPlaneSkipsTheHybridGate(t *testing.T) {
	t.Parallel()
	r := newTesterRig(t)

	res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
		GatewayID: r.gateway, Slug: armorSlug, Settings: armorSettings(testerKey), OnDataPlane: true,
	})

	require.NoError(t, err)
	assert.True(t, res.OK)
	r.gateways.AssertNotCalled(t, "FindByID", mock.Anything, mock.Anything)
}

func TestConnectionTesterRejectsUnknownAndUnsupportedPlugins(t *testing.T) {
	t.Parallel()

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()
		r.registry.EXPECT().Get("nope").Return(nil, false).Once()

		_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: "nope", Settings: map[string]any{}})

		require.ErrorIs(t, err, commonerrors.ErrValidation)
	})
	t.Run("no prober", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()
		r.registry.EXPECT().Get(azureSlug).Return(credPlugin{Plugin: pluginmocks.NewPlugin(t)}, true).Once()

		_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: azureSlug, Settings: map[string]any{}})

		require.ErrorIs(t, err, apppolicy.ErrConnectionTestUnsupported)
		require.ErrorIs(t, err, commonerrors.ErrValidation)
	})
}

func TestConnectionTesterRestoresTheStoredKey(t *testing.T) {
	t.Parallel()
	r := newTesterRig(t)
	r.saasGateway()
	stored := r.stored(t, armorSlug)
	r.repo.EXPECT().FindByID(mock.Anything, stored.ID).Return(stored, nil).Once()
	in := armorSettings(secret.Mask(testerKey))
	in["template"] = "other-template"

	res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
		GatewayID: r.gateway, PolicyID: &stored.ID, Slug: armorSlug, Settings: in,
	})

	require.NoError(t, err)
	assert.True(t, res.OK)
	got, _ := secret.SettingString(r.plugin.settings, "credentials.service_account_json")
	assert.Equal(t, testerKey, got)
	assert.Equal(t, "other-template", r.plugin.settings["template"])
	assert.Equal(t, secret.Mask(testerKey), in["credentials"].(map[string]any)["service_account_json"])
}

func TestConnectionTesterAsksToReenterWhenTheDestinationMoves(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"location", "project"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			r := newTesterRig(t)
			r.saasGateway()
			stored := r.stored(t, armorSlug)
			r.repo.EXPECT().FindByID(mock.Anything, stored.ID).Return(stored, nil).Once()
			in := armorSettings(secret.Mask(testerKey))
			in[field] = "us"

			res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
				GatewayID: r.gateway, PolicyID: &stored.ID, Slug: armorSlug, Settings: in,
			})

			require.NoError(t, err)
			assert.Equal(t, apppolicy.CodeReenterCredentials, res.Code)
			assert.False(t, res.OK)
			assert.Zero(t, r.plugin.calls)
		})
	}
}

func TestConnectionTesterStoredPolicyLookup(t *testing.T) {
	t.Parallel()

	type lookup func(r *testerRig, t *testing.T) ids.PolicyID
	missing := func(r *testerRig, _ *testing.T) ids.PolicyID {
		id := ids.New[ids.PolicyKind]()
		r.repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()
		return id
	}
	foreign := func(r *testerRig, t *testing.T) ids.PolicyID {
		p := r.stored(t, armorSlug)
		p.GatewayID = ids.New[ids.GatewayKind]()
		r.repo.EXPECT().FindByID(mock.Anything, p.ID).Return(p, nil).Once()
		return p.ID
	}
	otherPlugin := func(r *testerRig, t *testing.T) ids.PolicyID {
		p := r.stored(t, openaiSlug)
		r.repo.EXPECT().FindByID(mock.Anything, p.ID).Return(p, nil).Once()
		return p.ID
	}
	t.Run("other gateway on a data plane is not found", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		id := foreign(r, t)

		_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
			GatewayID: r.gateway, PolicyID: &id, Slug: armorSlug, Settings: armorSettings(secret.Mask(testerKey)), OnDataPlane: true,
		})

		require.ErrorIs(t, err, commonerrors.ErrNotFound)
		assert.Zero(t, r.plugin.calls)
	})
	t.Run("other gateway on the control plane is not found", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()
		id := foreign(r, t)

		_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
			GatewayID: r.gateway, PolicyID: &id, Slug: armorSlug, Settings: armorSettings(secret.Mask(testerKey)),
		})

		require.ErrorIs(t, err, commonerrors.ErrNotFound)
		assert.Zero(t, r.plugin.calls)
	})
	for name, find := range map[string]lookup{"missing": missing, "other plugin": otherPlugin} {
		t.Run(name+" on the control plane is not found", func(t *testing.T) {
			t.Parallel()
			r := newTesterRig(t)
			r.saasGateway()
			id := find(r, t)

			_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
				GatewayID: r.gateway, PolicyID: &id, Slug: armorSlug, Settings: armorSettings(secret.Mask(testerKey)),
			})

			require.ErrorIs(t, err, commonerrors.ErrNotFound)
			assert.Zero(t, r.plugin.calls)
		})
		t.Run(name+" on a data plane is not synced", func(t *testing.T) {
			t.Parallel()
			r := newTesterRig(t)
			id := find(r, t)

			res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
				GatewayID: r.gateway, PolicyID: &id, Slug: armorSlug, Settings: armorSettings(secret.Mask(testerKey)), OnDataPlane: true,
			})

			require.NoError(t, err)
			assert.Equal(t, apppolicy.CodeNotSynced, res.Code)
			assert.Zero(t, r.plugin.calls)
		})
	}
}

func TestConnectionTesterStaleMask(t *testing.T) {
	t.Parallel()
	staleMask := secret.Mask(`{"type":"service_account","private_key":"OLDER-KEY-9876"}`)

	t.Run("data plane snapshot behind the save", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		stored := r.stored(t, armorSlug)
		r.repo.EXPECT().FindByID(mock.Anything, stored.ID).Return(stored, nil).Once()

		res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
			GatewayID: r.gateway, PolicyID: &stored.ID, Slug: armorSlug, Settings: armorSettings(staleMask), OnDataPlane: true,
		})

		require.NoError(t, err)
		assert.Equal(t, apppolicy.CodeNotSynced, res.Code)
		assert.Zero(t, r.plugin.calls)
	})
	t.Run("control plane", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()
		stored := r.stored(t, armorSlug)
		r.repo.EXPECT().FindByID(mock.Anything, stored.ID).Return(stored, nil).Once()

		_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
			GatewayID: r.gateway, PolicyID: &stored.ID, Slug: armorSlug, Settings: armorSettings(staleMask),
		})

		require.ErrorIs(t, err, commonerrors.ErrValidation)
		assert.Zero(t, r.plugin.calls)
	})
	t.Run("masked key without a stored policy", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()

		_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
			GatewayID: r.gateway, Slug: armorSlug, Settings: armorSettings(staleMask),
		})

		require.ErrorIs(t, err, commonerrors.ErrValidation)
		assert.Zero(t, r.plugin.calls)
	})
}

func TestConnectionTesterValidatesBeforeProbing(t *testing.T) {
	t.Parallel()

	t.Run("plugin config", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()
		reg := pluginmocks.NewRegistry(t)
		reg.EXPECT().Get(armorSlug).Return(r.plugin, true).Maybe()
		reg.EXPECT().Validate(armorSlug, mock.Anything).Return(errors.New("template is required")).Once()
		tester := apppolicy.NewConnectionTester(r.repo, r.gateways, reg, nil)

		_, err := tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: armorSlug, Settings: armorSettings(testerKey)})

		require.ErrorIs(t, err, commonerrors.ErrValidation)
		assert.Zero(t, r.plugin.calls)
	})
	t.Run("settings write rules", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()
		reg := pluginmocks.NewRegistry(t)
		reg.EXPECT().Get(armorSlug).Return(r.plugin, true).Maybe()
		reg.EXPECT().Validate(armorSlug, mock.Anything).Return(nil).Once()
		reg.EXPECT().ValidateSettingsWrite(armorSlug, mock.Anything, map[string]any(nil)).Return(errors.New("token_uri must be Google's")).Once()
		tester := apppolicy.NewConnectionTester(r.repo, r.gateways, reg, nil)

		_, err := tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: armorSlug, Settings: armorSettings(testerKey)})

		require.ErrorIs(t, err, commonerrors.ErrValidation)
		assert.Zero(t, r.plugin.calls)
	})
	t.Run("case variant of a destination", func(t *testing.T) {
		t.Parallel()
		r := newTesterRig(t)
		r.saasGateway()
		in := armorSettings(testerKey)
		in["Location"] = "us"

		_, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{GatewayID: r.gateway, Slug: armorSlug, Settings: in})

		require.ErrorIs(t, err, commonerrors.ErrValidation)
		assert.Zero(t, r.plugin.calls)
	})
}

func TestConnectionTesterGivesTheStoredSettingsAsPrevious(t *testing.T) {
	t.Parallel()
	r := newTesterRig(t)
	r.saasGateway()
	stored := r.stored(t, armorSlug)
	r.repo.EXPECT().FindByID(mock.Anything, stored.ID).Return(stored, nil).Once()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().Get(armorSlug).Return(r.plugin, true).Maybe()
	reg.EXPECT().Validate(armorSlug, mock.Anything).Return(nil).Once()
	reg.EXPECT().ValidateSettingsWrite(armorSlug, mock.Anything, stored.Settings).Return(nil).Once()
	tester := apppolicy.NewConnectionTester(r.repo, r.gateways, reg, nil)

	res, err := tester.Test(context.Background(), apppolicy.TestConnectionInput{
		GatewayID: r.gateway, PolicyID: &stored.ID, Slug: armorSlug, Settings: armorSettings(secret.Mask(testerKey)),
	})

	require.NoError(t, err)
	assert.True(t, res.OK)
}

func TestConnectionTesterKeepsTheKeyOutOfFailures(t *testing.T) {
	t.Parallel()
	r := newTesterRig(t)
	r.saasGateway()
	stored := r.stored(t, armorSlug)
	r.repo.EXPECT().FindByID(mock.Anything, stored.ID).Return(stored, nil).Once()
	in := armorSettings(secret.Mask(testerKey))
	in["project"] = "elsewhere"

	res, err := r.tester.Test(context.Background(), apppolicy.TestConnectionInput{
		GatewayID: r.gateway, PolicyID: &stored.ID, Slug: armorSlug, Settings: in,
	})

	require.NoError(t, err)
	assert.Equal(t, apppolicy.CodeReenterCredentials, res.Code)
	assert.NotContains(t, res.Message, "TESTER-KEY")
	assert.NotContains(t, r.logs.String(), "TESTER-KEY")
	assert.Contains(t, r.logs.String(), "ok=false")
}
