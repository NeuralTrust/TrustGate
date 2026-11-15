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

package watsonx

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func TestParseModelSpecs_LifecycleAndFunctions(t *testing.T) {
	body := `{"total_count":4,"resources":[
		{"model_id":"ibm/granite-4-h-small","label":"granite-4-h-small","functions":[{"id":"text_chat"},{"id":"text_generation"}],
		 "lifecycle":[{"id":"available","start_date":"2025-10-02"}]},
		{"model_id":"mistralai/mistral-medium-2505","label":"mistral-medium-2505","functions":[{"id":"text_chat"}],
		 "lifecycle":[{"id":"available","start_date":"2025-05-07"},{"id":"deprecated","start_date":"2026-05-05"},{"id":"withdrawn","start_date":"2027-01-12"}]},
		{"model_id":"old/withdrawn-model","label":"gone","functions":[{"id":"text_chat"}],
		 "lifecycle":[{"id":"available","start_date":"2024-01-01"},{"id":"withdrawn","start_date":"2026-01-01"}]},
		{"model_id":"ibm/slate-125m-english-rtrvr","label":"slate","functions":[{"id":"embedding"}]},
		{"model_id":"","label":"blank","functions":[{"id":"text_chat"}]}
	]}`

	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	models, err := parseModelSpecs([]byte(body), now)
	require.NoError(t, err)
	assert.Equal(t, []providers.LiveModel{
		{ID: "ibm/granite-4-h-small", DisplayName: "granite-4-h-small", ProviderModel: "ibm/granite-4-h-small"},
		{ID: "mistralai/mistral-medium-2505", DisplayName: "mistral-medium-2505 (deprecated)", ProviderModel: "mistralai/mistral-medium-2505"},
	}, models)

	afterWithdrawal := time.Date(2027, 1, 12, 0, 0, 0, 0, time.UTC)
	models, err = parseModelSpecs([]byte(body), afterWithdrawal)
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, "ibm/granite-4-h-small", models[0].ID)
}

func TestParseModelSpecs_BadBody(t *testing.T) {
	_, err := parseModelSpecs([]byte("not json"), time.Now())
	assert.ErrorIs(t, err, providers.ErrModelListingFailed)
}

func TestSpecsURL(t *testing.T) {
	opts, err := providers.DecodeWatsonxOptions(map[string]any{"region": "us-south", "project_id": testProject, "api_version": "2025-02-11"})
	require.NoError(t, err)
	assert.Equal(t,
		"https://us-south.ml.cloud.ibm.com/ml/v1/foundation_model_specs?filters=function_text_chat&limit=200&version=2025-02-11",
		specsURL(opts))
}
