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

package bedrockguardrail

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func settingsIn(region string) map[string]any {
	set := bedrockSettings("block")
	set["credentials"] = map[string]any{
		"aws_region":        region,
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "secret",
	}
	return set
}

// In a region with the smallest on-demand quota (25 text units a second) a
// client can pad its last message until ApplyGuardrail throttles whatever it
// sends. A throttle is availability, so without a bound the padded message goes
// through uninspected. 300,000 characters is 300 text units, more than that
// region serves in a call's whole budget, so it must be refused as input before
// any call is made.
func TestAPaddedMessageThatTheRegionQuotaCannotServeIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{err: throttlingError(t)}
			p := pluginWith(client)
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, mode, settingsIn("eu-west-3"),
				chatRequestOf(t, strings.Repeat("padding words. ", 20000)), nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			assert.Zero(t, client.count(), "no call is made for a request the quota cannot serve")
			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, "input", extras.FailureClass)
			assert.Equal(t, appplugins.DetailChunkLimit, extras.FailureDetail)
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				require.True(t, isPE, "want a refusal, got res=%v err=%v", res, err)
				assert.Equal(t, http.StatusForbidden, pe.StatusCode)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
		})
	}
}
