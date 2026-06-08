package registry

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
)

func TestTargetAuth_ResolveSecretsFrom_APIKey(t *testing.T) {
	t.Parallel()
	prev := &TargetAuth{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: "stored"}}

	redacted := &TargetAuth{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: secret.Redacted}}
	redacted.ResolveSecretsFrom(prev)
	if redacted.APIKey.APIKey != "stored" {
		t.Fatalf("redacted api key = %q, want stored", redacted.APIKey.APIKey)
	}

	fresh := &TargetAuth{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: "rotated"}}
	fresh.ResolveSecretsFrom(prev)
	if fresh.APIKey.APIKey != "rotated" {
		t.Fatalf("fresh api key = %q, want rotated", fresh.APIKey.APIKey)
	}
}

func TestTargetAuth_ResolveSecretsFrom_AWS(t *testing.T) {
	t.Parallel()
	prev := &TargetAuth{Type: AuthTypeAWS, AWS: &AWSAuth{
		AccessKeyID:     "AKIA-stored",
		SecretAccessKey: "secret-stored",
		Region:          "us-east-1",
	}}
	incoming := &TargetAuth{Type: AuthTypeAWS, AWS: &AWSAuth{
		AccessKeyID:     secret.Redacted,
		SecretAccessKey: secret.Redacted,
		Region:          "eu-west-1",
	}}

	incoming.ResolveSecretsFrom(prev)

	if incoming.AWS.AccessKeyID != "AKIA-stored" {
		t.Fatalf("access_key_id = %q, want preserved AKIA-stored", incoming.AWS.AccessKeyID)
	}
	if incoming.AWS.SecretAccessKey != "secret-stored" {
		t.Fatalf("secret_access_key = %q, want preserved secret-stored", incoming.AWS.SecretAccessKey)
	}
	if incoming.AWS.Region != "eu-west-1" {
		t.Fatalf("region = %q, want updated eu-west-1", incoming.AWS.Region)
	}
}

func TestTargetAuth_Validate_RejectsRedactedSecret(t *testing.T) {
	t.Parallel()
	cases := map[string]*TargetAuth{
		"api_key": {Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: secret.Redacted}},
		"azure":   {Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", APIKey: secret.Redacted}},
		"aws":     {Type: AuthTypeAWS, AWS: &AWSAuth{AccessKeyID: secret.Redacted}},
		"oauth2":  {Type: AuthTypeOAuth2, OAuth: &TargetOAuthConfig{TokenURL: "https://t", GrantType: "client_credentials", ClientSecret: secret.Redacted}},
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := auth.Validate(); err == nil {
				t.Fatalf("Validate() = nil, want rejection of redaction placeholder")
			}
		})
	}
}

func TestTargetAuth_ResolveSecretsFrom_TypeChangeKeepsIncoming(t *testing.T) {
	t.Parallel()
	prev := &TargetAuth{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: "stored"}}
	incoming := &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{APIKey: secret.Redacted}}

	incoming.ResolveSecretsFrom(prev)

	if incoming.Azure.APIKey != secret.Redacted {
		t.Fatalf("azure api key = %q, want unchanged on type switch", incoming.Azure.APIKey)
	}
}
