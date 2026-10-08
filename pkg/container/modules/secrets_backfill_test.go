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

package modules

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
)

func TestStartSecretsBackfill_DisabledReturnsAStopThatReturns(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Server.StoredSecretsEncryptionEnabled = false
	stop := StartSecretsBackfill(SecretsBackfillParams{Ctx: context.Background(), Config: cfg})
	stop()
}
