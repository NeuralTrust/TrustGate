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

package registry

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
)

func TestEmbeddingConfig_ResolveSecretsFrom(t *testing.T) {
	t.Parallel()
	prev := &EmbeddingConfig{Provider: "openai", Model: "text-embedding-3-small", Auth: &APIKeyAuth{APIKey: "stored"}}
	incoming := &EmbeddingConfig{Provider: "openai", Model: "text-embedding-3-large", Auth: &APIKeyAuth{APIKey: secret.Redacted}}

	incoming.ResolveSecretsFrom(prev)

	if incoming.Auth.APIKey != "stored" {
		t.Fatalf("api_key = %q, want preserved stored", incoming.Auth.APIKey)
	}
}

func TestEmbeddingConfig_Validate_RejectsRedactedSecret(t *testing.T) {
	t.Parallel()
	cfg := &EmbeddingConfig{Provider: "openai", Model: "text-embedding-3-small", Auth: &APIKeyAuth{APIKey: secret.Redacted}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want rejection of redaction placeholder")
	}
}
