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

package azurecontentsafety

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// A 400 that names the call's own configuration (the api-version in the
// endpoint, the categories the policy requests) is not about the text: no
// request can change it, so it must not refuse every call.
func TestConfigurationRejectionsAreAvailability(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
	}{
		{"unsupported api-version", `{"error":{"code":"InvalidParameter","message":"The api-version 2020-01-01 is not supported.","target":"api-version"}}`},
		{"unsupported api-version code", `{"error":{"code":"UnsupportedApiVersion","message":"The requested api version is not supported."}}`},
		{"invalid category", `{"error":{"code":"InvalidParameter","message":"The parameter categories is invalid.","target":"categories"}}`},
		{"invalid output type", `{"error":{"code":"InvalidParameter","message":"The parameter outputType is invalid.","target":"outputType"}}`},
	} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				f := &fakeAzure{status: http.StatusBadRequest, rawBody: tc.body}
				srv := newServer(t, f)
				p := New(adapter.NewRegistry(), nil)
				event, span := eventFor(t)
				in := execInput(policy.StagePreRequest, mode, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(openAIRequestBody()))
				in.Event = event

				res, err := p.Execute(context.Background(), in)
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, http.StatusOK, res.StatusCode)
				extras, ok := span.PluginAttrsCopy().Extras.(*Data)
				require.True(t, ok)
				assert.Equal(t, "failed_open", extras.Decision)
				assert.Equal(t, "availability", extras.FailureClass)
				assert.Equal(t, "config_invalid", extras.FailureReason)
			})
		}
	}
}

func TestValidateSettingsWriteRequiresAnAPIVersion(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	cat := map[string]int{CategoryHate: 2}
	const base = "https://acct.cognitiveservices.azure.com/contentsafety/text:analyze"
	require.Error(t, p.ValidateSettingsWrite(settings(base, cat), nil))
	require.Error(t, p.ValidateSettingsWrite(settings(base+"?api-version=", cat), nil))
	require.NoError(t, p.ValidateSettingsWrite(settings(base+"?api-version=2023-10-01", cat), nil))
	require.NoError(t, p.ValidateSettingsWrite(settings(base+"?API-Version=2023-10-01", cat), nil), "the parameter name is matched without regard to case")
}

// The api-version is only demanded of an endpoint that is new or changed: a
// stored policy saved before the rule keeps accepting edits to its other
// settings.
func TestValidateSettingsWriteChecksTheAPIVersionOnlyWhenTheEndpointChanges(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	const legacy = "https://acct.cognitiveservices.azure.com/contentsafety/text:analyze"
	const versioned = legacy + "?api-version=2023-10-01"
	stored := settings(legacy, map[string]int{CategoryHate: 2})

	edited := settings(legacy, map[string]int{CategoryHate: 4})
	require.NoError(t, p.ValidateSettingsWrite(edited, stored), "an edit that leaves the endpoint alone")

	moved := settings(legacy+"?foo=bar", map[string]int{CategoryHate: 2})
	require.Error(t, p.ValidateSettingsWrite(moved, stored), "a changed endpoint without an api-version")

	require.NoError(t, p.ValidateSettingsWrite(settings(versioned, map[string]int{CategoryHate: 2}), stored), "a changed endpoint with one")
	require.Error(t, p.ValidateSettingsWrite(edited, map[string]any{"endpoint": versioned}), "an endpoint changed from a versioned one")
}
