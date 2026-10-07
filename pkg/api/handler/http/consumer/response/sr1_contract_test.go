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

package response

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registry "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestSR1HTTPResponseReportsStoredConfigWithoutMigration(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	cfg := &registry.SmartRoutingConfig{SR1: &registry.SR1Config{CacheTTLSeconds: 30, EscapeHatchEnabled: true}, Tiers: []registry.SmartRoutingTier{{RegistryID: id, Model: "high", MinScore: .45}, {RegistryID: id, Model: "low", MinScore: 0}}}
	response := fromSmartRouting(cfg)
	if response.SR1 == nil || response.SR1.CacheTTLSeconds != 30 || !response.SR1.EscapeHatchEnabled {
		t.Fatal("response drops canonical preference")
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"sr1":{"cache_ttl_seconds":30,"escape_hatch_enabled":true}`) {
		t.Fatal(string(raw))
	}
	cfg.SR1 = nil
	cfg.Tiers[0].MinScore = .8
	raw, err = json.Marshal(fromSmartRouting(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"sr1"`) || !strings.Contains(string(raw), `"min_score":0.8`) || cfg.SR1 != nil || cfg.Tiers[0].Model != "high" {
		t.Fatal("response performs historical migration")
	}
}
