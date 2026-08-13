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

package vertex

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// The probe stops at credential acquisition: reaching a model would need a model name and would bill tokens.
func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	if _, err := providers.DecodeVertexOptions(config.Options); err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageConnectivity,
			Message: err.Error(),
		}
	}

	if _, err := c.bearerToken(ctx, config); err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageAuthentication,
			Message: err.Error(),
		}
	}

	return providers.ProbeResult{OK: true, Stage: providers.StageAuthentication}
}
