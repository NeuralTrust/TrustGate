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

package googlemodelarmor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ambientCanary = "canary-sa@victim-project.iam.gserviceaccount.com"

// ambientRig is a plugin wired the way New wires it (real clientCache and
// tokenSourceFor) but with recording credential sources and a recording
// Model Armor server, so a refusal can be proven to have minted no token and
// sent no request.
type ambientRig struct {
	plugin *Plugin
	tokens atomic.Int64
	hits   atomic.Int64
}

func newAmbientRig(t *testing.T, allow bool) *ambientRig {
	t.Helper()
	r := &ambientRig{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(allowResponse))
	}))
	t.Cleanup(srv.Close)
	mint := func() (string, error) {
		r.tokens.Add(1)
		return "tok", nil
	}
	sources := &credentialSources{
		adc:         func(context.Context, string) (string, error) { return mint() },
		serviceAcct: func(context.Context, string, string) (string, error) { return mint() },
		impersonate: func(context.Context, string, string) (string, error) { return mint() },
	}
	r.plugin = &Plugin{
		registry:             adapter.NewRegistry(),
		clients:              newModelArmorClientCache(srv.URL, time.Second, sources),
		allowAmbientIdentity: allow,
	}
	return r
}

func withCredentials(settings map[string]any, creds map[string]any) map[string]any {
	if creds != nil {
		settings["credentials"] = creds
	}
	return settings
}

// ambientCases are the two credential paths that act as the shared pod identity.
func ambientCases() []struct {
	name  string
	creds map[string]any
	field string
} {
	return []struct {
		name  string
		creds map[string]any
		field string
	}{
		{"impersonate_service_account", map[string]any{"impersonate_service_account": ambientCanary}, "impersonate_service_account"},
		{"no credentials", nil, "service_account_json"},
		{"empty credentials block", map[string]any{}, "service_account_json"},
	}
}

func TestValidateConfigRefusesAmbientIdentityByDefault(t *testing.T) {
	t.Parallel()
	for _, tc := range ambientCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New(adapter.NewRegistry(), "", time.Second, false, nil)
			err := p.ValidateConfig(withCredentials(modelArmorSettings(), tc.creds))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.field)
			assert.Contains(t, err.Error(), "service account key")
			assert.NotContains(t, err.Error(), ambientCanary, "the error must never echo a value")
		})
	}
}

func TestValidateConfigAcceptsServiceAccountJSONWithoutAmbientIdentity(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", time.Second, false, nil)
	set := withCredentials(modelArmorSettings(), map[string]any{"service_account_json": "{}"})
	require.NoError(t, p.ValidateConfig(set))
}

func TestValidateConfigAllowsAmbientIdentityWhenEnabled(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", time.Second, true, nil)
	for _, tc := range ambientCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, p.ValidateConfig(withCredentials(modelArmorSettings(), tc.creds)))
		})
	}
}

func TestExecuteRefusesAmbientIdentityWithoutAnyOutboundCall(t *testing.T) {
	t.Parallel()
	for _, tc := range ambientCases() {
		t.Run(tc.name+"/enforce", func(t *testing.T) {
			t.Parallel()
			rig := newAmbientRig(t, false)
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, policy.ModeEnforce,
				withCredentials(modelArmorSettings(), tc.creds), reqCtx(openAIRequest()), nil)
			in.Event = event

			res, err := rig.plugin.Execute(context.Background(), in)

			assert.Nil(t, res)
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "err = %v", err)
			assert.Equal(t, http.StatusBadGateway, pe.StatusCode)
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, "failed_closed", data.Decision)
			assert.Equal(t, "config_invalid", data.FailureReason)
			assert.Zero(t, rig.tokens.Load(), "no token may be minted")
			assert.Zero(t, rig.hits.Load(), "no request may reach Model Armor")
		})
		t.Run(tc.name+"/observe", func(t *testing.T) {
			t.Parallel()
			rig := newAmbientRig(t, false)
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, policy.ModeObserve,
				withCredentials(modelArmorSettings(), tc.creds), reqCtx(openAIRequest()), nil)
			in.Event = event

			res, err := rig.plugin.Execute(context.Background(), in)

			assertPassThrough(t, res, err)
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, "failed_open", data.Decision)
			assert.Equal(t, "config_invalid", data.FailureReason)
			assert.Zero(t, rig.tokens.Load())
			assert.Zero(t, rig.hits.Load())
		})
	}
}

func TestInspectSegmentRefusesAmbientIdentityWithoutAnyOutboundCall(t *testing.T) {
	t.Parallel()
	for _, tc := range ambientCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rig := newAmbientRig(t, false)
			set := withCredentials(streamSettings(nil), tc.creds)

			got, err := rig.plugin.InspectSegment(context.Background(),
				streamInput(policy.ModeEnforce, set, nil), segment(1, "some streamed text"))

			assert.Nil(t, got)
			require.Error(t, err)
			assert.Contains(t, err.Error(), string(appplugins.FailureConfigInvalid))
			assert.Zero(t, rig.tokens.Load())
			assert.Zero(t, rig.hits.Load())
		})
	}
}

func TestExecuteServiceAccountJSONWorksWithoutAmbientIdentity(t *testing.T) {
	t.Parallel()
	rig := newAmbientRig(t, false)
	set := withCredentials(modelArmorSettings(), map[string]any{"service_account_json": "{}"})
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIRequest()), nil)

	res, err := rig.plugin.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	assert.EqualValues(t, 1, rig.tokens.Load())
	assert.EqualValues(t, 1, rig.hits.Load())
}

func TestExecuteAmbientIdentityUnchangedWhenEnabled(t *testing.T) {
	t.Parallel()
	for _, tc := range ambientCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rig := newAmbientRig(t, true)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce,
				withCredentials(modelArmorSettings(), tc.creds), reqCtx(openAIRequest()), nil)

			res, err := rig.plugin.Execute(context.Background(), in)

			assertPassThrough(t, res, err)
			assert.EqualValues(t, 1, rig.tokens.Load())
			assert.EqualValues(t, 1, rig.hits.Load())
		})
	}
}
