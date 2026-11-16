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

package pluginutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFailClosedFromRaw(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   map[string]any
		want bool
	}{
		{"nil", nil, false},
		{"absent", map[string]any{"x": 1}, false},
		{"closed", map[string]any{"failure_mode": "closed"}, true},
		{"any case and spaces", map[string]any{"Failure_Mode": " Closed "}, true},
		{"open", map[string]any{"failure_mode": "open"}, false},
		{"garbage", map[string]any{"failure_mode": "fail_closed"}, false},
		{"not a string", map[string]any{"failure_mode": true}, false},
	} {
		assert.Equal(t, tc.want, FailClosedFromRaw(tc.in), tc.name)
	}
}

func TestValidateFailureMode(t *testing.T) {
	t.Parallel()
	require.NoError(t, ValidateFailureMode("guard", FailureModeOpen))
	require.NoError(t, ValidateFailureMode("guard", FailureModeClosed))
	err := ValidateFailureMode("guard", "maybe")
	require.Error(t, err)
	assert.Equal(t, "guard: failure_mode must be one of open, closed", err.Error())
}

func TestFailureModeStamp(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "closed", FailureModeStamp(true))
	assert.Empty(t, FailureModeStamp(false))
}
