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

package a2a_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The A2A errors are written as the SDK's own server writes them, so its
// clients map them to the same exceptions.
func TestA2AErrorsMatchTheSDK(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		for fixture, got := range map[string]*a2a.RPCError{
			".task_not_found.response.json": a2a.TaskNotFound(v),
			".push.response.json":           a2a.PushNotificationNotSupported(v),
		} {
			var resp struct {
				Error map[string]any `json:"error"`
			}
			require.NoError(t, json.Unmarshal(readFixture(t, prefix+fixture), &resp))
			if resp.Error["data"] == nil {
				delete(resp.Error, "data")
			}
			want, err := json.Marshal(resp.Error)
			require.NoError(t, err)
			encoded, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, string(want), string(encoded), prefix+fixture)
		}
	}
}

func TestGatewayErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  *a2a.RPCError
		code int64
		data string
	}{
		{a2a.PolicyBlocked(a2a.ReasonMaskUnsupported, "trustguard"), -32090, `{"reason":"mask_unsupported","plugin":"trustguard"}`},
		{a2a.RateLimited(30), -32091, `{"retry_after":30}`},
		{a2a.GatewayFailure(a2a.ReasonPlanUnavailable), -32092, `{"reason":"plan_unavailable"}`},
		{a2a.IdentityRequired(), -32093, `{"reason":"identity_required"}`},
	} {
		assert.Equal(t, tc.code, tc.err.Code)
		assert.NotEmpty(t, tc.err.Message)
		assert.JSONEq(t, tc.data, string(tc.err.Data))
	}
}
