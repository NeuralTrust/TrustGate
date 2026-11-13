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

package loadbalancer

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestEmbeddingNeverCarriesASecretReference(t *testing.T) {
	t.Parallel()
	cfg := backendEmbeddingToDomain(&registry.EmbeddingConfig{Provider: "openai", Model: "m", Auth: &registry.APIKeyAuth{
		APIKey: "secret://vault/emb#k", HeaderName: "X-Key", HeaderValue: "SECRET://vault/emb#h",
	}})
	if cfg.Credentials.APIKey != "" || cfg.Credentials.HeaderValue != "" {
		t.Fatalf("credentials = %+v; a reference-shaped value must never reach the embedding client", cfg.Credentials)
	}
	cfg = backendEmbeddingToDomain(&registry.EmbeddingConfig{Provider: "openai", Model: "m", Auth: &registry.APIKeyAuth{APIKey: "sk-live"}})
	if cfg.Credentials.APIKey != "sk-live" {
		t.Fatal("a literal key is kept")
	}
}
