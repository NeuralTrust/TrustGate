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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateClientVars(t *testing.T) {
	version := &templateVersion{
		RequiredVariables: map[string]requiredVar{
			"persona": {Type: "string", Enum: []string{"friendly", "formal"}, MaxLength: 10},
			"count":   {Type: "number"},
			"verbose": {Type: "boolean"},
		},
	}

	t.Run("valid passes", func(t *testing.T) {
		err := validateClientVars(version, map[string]any{"persona": "friendly", "count": float64(3), "verbose": true})
		assert.NoError(t, err)
	})

	t.Run("missing required", func(t *testing.T) {
		err := validateClientVars(version, map[string]any{"count": float64(3), "verbose": true})
		assertRejectType(t, err, http.StatusBadRequest, typeVariableMissing)
	})

	t.Run("wrong type", func(t *testing.T) {
		err := validateClientVars(version, map[string]any{"persona": "friendly", "count": "three", "verbose": true})
		assertRejectType(t, err, http.StatusBadRequest, typeVariableInvalid)
	})

	t.Run("not in enum", func(t *testing.T) {
		err := validateClientVars(version, map[string]any{"persona": "rude", "count": float64(3), "verbose": true})
		assertRejectType(t, err, http.StatusBadRequest, typeVariableInvalid)
	})

	t.Run("exceeds max_length", func(t *testing.T) {
		long := &templateVersion{RequiredVariables: map[string]requiredVar{"persona": {Type: "string", MaxLength: 3}}}
		err := validateClientVars(long, map[string]any{"persona": "friendly"})
		assertRejectType(t, err, http.StatusBadRequest, typeVariableInvalid)
	})

	t.Run("wrong boolean type", func(t *testing.T) {
		err := validateClientVars(version, map[string]any{"persona": "formal", "count": float64(1), "verbose": "yes"})
		assertRejectType(t, err, http.StatusBadRequest, typeVariableInvalid)
	})
}

func assertRejectType(t *testing.T, err error, status int, errType string) {
	t.Helper()
	pe := requirePluginError(t, err)
	require.Equal(t, status, pe.StatusCode)
	assert.Equal(t, errType, pe.Type)
}
