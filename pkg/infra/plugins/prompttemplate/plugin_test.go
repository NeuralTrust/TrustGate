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

package prompttemplate

import (
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Contract(t *testing.T) {
	t.Parallel()

	p := New()

	assert.Equal(t, PluginName, p.Name())
	assert.Equal(t, "prompt_template", p.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())
	assert.Contains(t, p.SupportedModes(), policy.ModeEnforce)
	assert.Contains(t, p.SupportedModes(), policy.ModeObserve)
}

func TestPlugin_ExecuteNoOp(t *testing.T) {
	t.Parallel()

	res, err := New().Execute(context.Background(), appplugins.ExecInput{Mode: policy.ModeEnforce})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.RequestBody)
	assert.Nil(t, res.Body)
}

func TestErrorTypeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "template_variable_unresolved", typeVariableUnresolved)
	assert.Equal(t, "template_variable_missing", typeVariableMissing)
	assert.Equal(t, "template_variable_invalid", typeVariableInvalid)
	assert.Equal(t, "template_not_found", typeNotFound)
	assert.Equal(t, "template_required", typeRequired)
}

func TestVarSourceConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, varSource("header"), sourceHeader)
	assert.Equal(t, varSource("jwt_claim"), sourceJWTClaim)
}
