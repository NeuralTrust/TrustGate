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
