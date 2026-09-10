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

package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClampMaxOutputTokens(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		in        string
		limit     int
		wantField string
		wantVal   int
		requested int
		clamped   bool
	}{
		{name: "max_completion_tokens wins", in: `{"max_completion_tokens":32000,"max_tokens":1}`, limit: 16384, wantField: "max_completion_tokens", wantVal: 16384, requested: 32000, clamped: true},
		{name: "max_tokens when completion absent", in: `{"max_tokens":32000}`, limit: 16384, wantField: "max_tokens", wantVal: 16384, requested: 32000, clamped: true},
		{name: "max_output_tokens for responses", in: `{"max_output_tokens":64000}`, limit: 8192, wantField: "max_output_tokens", wantVal: 8192, requested: 64000, clamped: true},
		{name: "already within limit", in: `{"max_tokens":128}`, limit: 16384, wantField: "max_tokens", wantVal: 128, requested: 128, clamped: false},
		{name: "absent field", in: `{"messages":[]}`, limit: 16384, requested: 0, clamped: false},
		{name: "non positive skipped", in: `{"max_tokens":0}`, limit: 16384, requested: 0, clamped: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, requested, clamped := ClampMaxOutputTokens([]byte(tc.in), tc.limit)
			assert.Equal(t, tc.clamped, clamped)
			assert.Equal(t, tc.requested, requested)
			if !tc.clamped {
				assert.Equal(t, tc.in, string(out))
				return
			}
			var got map[string]any
			require.NoError(t, json.Unmarshal(out, &got))
			assert.EqualValues(t, tc.wantVal, got[tc.wantField])
		})
	}
}
