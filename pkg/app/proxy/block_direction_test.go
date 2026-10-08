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

package proxy

import (
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/stretchr/testify/assert"
)

// pluginErrorResult is the single renderer of a plugin's denial; the direction
// header the executor stamped on the error must reach the response untouched.
func TestPluginErrorResult_KeepsTheBlockDirectionHeader(t *testing.T) {
	t.Parallel()
	pe := appplugins.WithBlockDirection(
		&appplugins.PluginError{StatusCode: http.StatusForbidden, Type: "x_blocked", Message: "no"},
		appplugins.BlockDirectionInput)
	res := pluginErrorResult(pe)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Equal(t, []string{appplugins.BlockDirectionInput}, res.Headers[appplugins.BlockDirectionHeader])
	assert.Equal(t, []string{"application/json"}, res.Headers["Content-Type"])

	rate := pluginErrorResult(appplugins.WithBlockDirection(
		&appplugins.PluginError{StatusCode: http.StatusTooManyRequests, Message: "slow"},
		appplugins.BlockDirectionInput))
	assert.NotContains(t, rate.Headers, appplugins.BlockDirectionHeader)
}
