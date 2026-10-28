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

package response_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/stretchr/testify/assert"
)

func TestTestConnectionResponse_OmitsWarningsWhenEmpty(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(response.FromTestConnectionResult(appregistry.TestConnectionResult{OK: true, Stage: "authentication"}))
	assert.NoError(t, err)
	assert.NotContains(t, string(raw), "warnings")
}

func TestTestConnectionResponse_CarriesWarnings(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(response.FromTestConnectionResult(appregistry.TestConnectionResult{
		OK: true, Warnings: []string{"Missing IAM permission bedrock:ListInferenceProfiles"},
	}))
	assert.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"stage":"","provider":"","latency_ms":0,"warnings":["Missing IAM permission bedrock:ListInferenceProfiles"]}`, string(raw))
}
