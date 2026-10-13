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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// Model Armor documents three execution states: EXECUTION_STATE_UNSPECIFIED,
// EXECUTION_SUCCESS and EXECUTION_SKIPPED. Only a skip is something the content
// causes (a payload over the filter's token limit); an unspecified state is
// Model Armor's own, so it must not refuse traffic.
func TestOnlyASkippedFilterIsTheContentsFailure(t *testing.T) {
	t.Parallel()
	unspecifiedPI := `"pi_and_jailbreak":{"piAndJailbreakFilterResult":{"executionState":"EXECUTION_STATE_UNSPECIFIED","matchState":"NO_MATCH_FOUND"}}`
	unspecified := `{"sanitizationResult":{"invocationResult":"SUCCESS","filterResults":{` +
		noMatchSDP + `,` + noMatchRAI + `,` + unspecifiedPI + `,` + noMatchURIs + `,` + noMatchCSAM + `}}}`

	for _, tc := range []struct {
		name   string
		body   string
		input  bool
		detail string
	}{
		{"skipped", tokenLimitSkipResponse, true, appplugins.DetailFilterNotExecuted},
		{"unspecified", unspecified, false, "filter_state_unspecified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithStub(newModelArmorStub(t, http.StatusOK, tc.body))
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)
			if tc.input {
				_, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "got %v", err)
			} else {
				assertPassThrough(t, res, err)
			}
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, tc.detail, data.FailureDetail)
			if tc.input {
				assert.Equal(t, "input", data.FailureClass)
			} else {
				assert.Equal(t, "availability", data.FailureClass)
			}
		})
	}
}
