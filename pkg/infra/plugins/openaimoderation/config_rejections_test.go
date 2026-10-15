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

package openaimoderation

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// A 400 whose param is the model, or whose code says the key or the model is
// not usable, is the policy's configuration and not the input: a model this
// build still lists but OpenAI retired would otherwise refuse every call.
func TestConfigurationRejectionsAreAvailability(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
	}{
		{"model not found", `{"error":{"message":"The model omni-moderation-retired does not exist.","type":"invalid_request_error","param":"model","code":"model_not_found"}}`},
		{"invalid model", `{"error":{"message":"Invalid model: omni-moderation-retired","type":"invalid_request_error","param":"model","code":null}}`},
		{"bad key as a 400", `{"error":{"message":"Incorrect API key provided.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}`},
	} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				f := &fakeModerator{status: http.StatusBadRequest, rawBody: tc.body}
				srv := newModeratorServer(t, f)
				p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
				event, span := newEvent()
				in := execInput(policy.StagePreRequest, mode, blockSettings(), requestContext(), nil, event)

				res, err := p.Execute(context.Background(), in)
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, http.StatusOK, res.StatusCode)
				extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
				require.True(t, ok)
				assert.Equal(t, "failed_open", extras.Decision)
				assert.Equal(t, "availability", extras.FailureClass)
				assert.Equal(t, "config_invalid", extras.FailureReason)
			})
		}
	}
}
