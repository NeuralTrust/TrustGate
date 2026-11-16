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

package secretref

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

// TestEveryLocationSaysWhereItsValueGoes fails when a declared location has
// no host rule: a store with allowed destinations would refuse every
// reference written there, or, worse, a rule that names the wrong field
// would let an editor redirect the value.
func TestEveryLocationSaysWhereItsValueGoes(t *testing.T) {
	t.Parallel()
	for _, s := range registrySlots(everyLocation()) {
		if len(s.hosts) == 0 {
			t.Errorf("registry location %v has no host", s.path)
		}
	}
	consumerRefs := ConsumerRefs(&consumer.Consumer{LBConfig: &consumer.LBConfig{EmbeddingConfig: &registry.EmbeddingConfig{
		Provider: "openai", Auth: &registry.APIKeyAuth{APIKey: refStr("e#k"), HeaderValue: refStr("e#h")},
	}}})
	authRefs := AuthRefs(&auth.Auth{Config: auth.Config{OAuth2: &auth.OAuth2Config{
		TokenURL: "https://idp/token", ClientSecret: refStr("a#cs"), ExchangeClientSecret: refStr("a#ex"),
	}}})
	gatewayRefs := GatewayRefs(&gateway.Gateway{Telemetry: &telemetry.Telemetry{Exporters: []telemetry.ExporterConfig{
		{Name: "otel", Type: "otlp", Settings: map[string]any{"endpoint": "collector:4317", "headers": map[string]any{"A": refStr("g#h")}}},
		{Name: "pg", Type: "postgres", Settings: map[string]any{"dsn": refStr("g#d")}},
	}}})
	for _, refs := range []EntityRefs{consumerRefs, authRefs, gatewayRefs} {
		if len(refs.Uses) == 0 {
			t.Fatalf("%s fixture holds no reference", refs.Entity)
		}
		for _, u := range refs.Uses {
			if len(u.Hosts) == 0 && !u.SelfAddressed {
				t.Errorf("%s location %v has no host", refs.Entity, u.Path)
			}
		}
	}
}

func TestCredentialHostsFollowTheFieldThatSendsThem(t *testing.T) {
	t.Parallel()
	llm := &registry.LLMTarget{
		Provider: "openai",
		Auth: &registry.TargetAuth{
			OAuth: &registry.TargetOAuthConfig{TokenURL: "https://idp.attacker.example/token"},
			Azure: &registry.AzureAuth{Endpoint: "https://acme.openai.azure.com"},
		},
	}
	if got := llmHosts(llm, []string{"llm_target", "auth", "oauth", "client_secret"}); !slices.Equal(got, []string{"api.openai.com", "idp.attacker.example"}) {
		t.Errorf("oauth client secret hosts = %v, want the token endpoint too", got)
	}
	if got := llmHosts(llm, []string{"llm_target", "auth", "api_key", "api_key"}); !slices.Equal(got, []string{"api.openai.com"}) {
		t.Errorf("api key hosts = %v", got)
	}
	vertex := &registry.LLMTarget{Provider: "vertex", ProviderOptions: map[string]any{"location": "europe-west1"}}
	if got := llmHosts(vertex, []string{"llm_target", "auth", "gcp_service_account"}); !slices.Equal(got, []string{"europe-west1-aiplatform.googleapis.com", "oauth2.googleapis.com"}) {
		t.Errorf("vertex hosts = %v", got)
	}
	watsonx := &registry.LLMTarget{Provider: "watsonx", ProviderOptions: map[string]any{"region": " EU-DE ", "project_id": "p"}}
	if got := llmHosts(watsonx, []string{"llm_target", "auth", "api_key", "api_key"}); !slices.Equal(got, []string{"eu-de.ml.cloud.ibm.com", "iam.cloud.ibm.com"}) {
		t.Errorf("watsonx api key hosts = %v, want the region and IBM Cloud IAM", got)
	}
	watsonx.ProviderOptions["base_url"] = "https://private.eu-de.ml.cloud.ibm.com"
	if got := llmHosts(watsonx, []string{"llm_target", "auth", "api_key", "api_key"}); !slices.Equal(got, []string{"private.eu-de.ml.cloud.ibm.com", "iam.cloud.ibm.com"}) {
		t.Errorf("watsonx honors base_url: %v", got)
	}
	unknown := &registry.LLMTarget{Provider: "watsonx", ProviderOptions: map[string]any{"region": "eu-de.attacker.example"}}
	if got := llmHosts(unknown, []string{"llm_target", "auth", "api_key", "api_key"}); got != nil {
		t.Errorf("a region that serves no watsonx.ai must leave no host: %v", got)
	}
	azure := &registry.LLMTarget{Provider: "azure", ProviderOptions: map[string]any{"base_url": "https://api.openai.com"},
		Auth: &registry.TargetAuth{Azure: &registry.AzureAuth{Endpoint: "https://acme.attacker.example"}}}
	if got := llmHosts(azure, []string{"llm_target", "auth", "azure", "api_key"}); !slices.Equal(got, []string{"acme.attacker.example"}) {
		t.Errorf("azure ignores base_url, so its endpoint is the host: %v", got)
	}
	bedrock := &registry.LLMTarget{Provider: "bedrock", Auth: &registry.TargetAuth{AWS: &registry.AWSAuth{Region: "x.attacker.example#"}}}
	if got := llmHosts(bedrock, []string{"llm_target", "auth", "aws", "access_key_id"}); got != nil {
		t.Errorf("a region that is not a host label must leave no host: %v", got)
	}
	if got := llmHosts(&registry.LLMTarget{Provider: "openai_compatible"}, []string{"llm_target", "auth", "api_key", "api_key"}); got != nil {
		t.Errorf("a target without a base_url has no host, got %v", got)
	}
	agent := &registry.A2ATarget{
		URL: "https://agent.example/a2a", CardURL: "https://cards.attacker.example", CardAuth: registry.A2ACardAuthSame,
		Auth: &registry.MCPAuth{Mode: registry.MCPAuthModeStatic},
	}
	agent.Normalize()
	if got := a2aHosts(agent, []string{"a2a_target", "auth", "value"}); !slices.Contains(got, "cards.attacker.example") {
		t.Errorf("an auth that also reads the card is sent to the card host: %v", got)
	}
}

func TestDestinationAllowlistIsEnforced(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	catalog := &fakeCatalog{stores: map[string]*secretstore.Store{
		"vault": {Name: "vault", Type: secretstore.TypeHashiCorpVault, AllowedPaths: []string{"ai/"}, AllowedDestinations: []string{"api.openai.com"}},
	}}
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: catalog, Resolver: &markerResolver{}})
	openai := func(opts map[string]any, auth *registry.TargetAuth) *registry.Registry {
		return &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{Provider: "openai", ProviderOptions: opts, Auth: auth}}
	}
	allowed := openai(nil, registry.NewAPIKeyAuth(refStr("openai#key")))
	redirected := openai(map[string]any{"base_url": "https://api.attacker.example/v1"}, registry.NewAPIKeyAuth(refStr("openai#key")))
	tokenElsewhere := openai(nil, &registry.TargetAuth{Type: registry.AuthTypeOAuth2, OAuth: &registry.TargetOAuthConfig{TokenURL: "https://idp.attacker.example/token", ClientSecret: refStr("openai#cs")}})
	card := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, Type: registry.TypeA2A, A2ATarget: &registry.A2ATarget{
		URL: "https://api.openai.com/a2a", CardURL: "https://cards.attacker.example", CardAuth: registry.A2ACardAuthSame,
		Auth: &registry.MCPAuth{Mode: registry.MCPAuthModeStatic, Header: "X-Key", Value: refStr("agent#key")},
	}}
	card.A2ATarget.Normalize()
	out := m.Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{
		allowed.ID: allowed, redirected.ID: redirected, tokenElsewhere.ID: tokenElsewhere, card.ID: card,
	})
	if v := out[allowed.ID].LLMTarget.Auth.APIKey.APIKey; v == "" || out[allowed.ID].CredentialUnavailable() {
		t.Fatal("a value sent to an allowed host must resolve")
	}
	for name, r := range map[string]*registry.Registry{"base_url": out[redirected.ID], "token_url": out[tokenElsewhere.ID], "card_url": out[card.ID]} {
		if !r.CredentialUnavailable() {
			t.Errorf("%s: a value sent to a host outside the list must stay unresolved", name)
		}
	}
	if v := out[card.ID].A2ATarget.Auth.Value; v != "" {
		t.Errorf("card_url: the value must never be set, got %q", v)
	}
}

func TestDestinationClassOnValues(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	catalog := &fakeCatalog{stores: map[string]*secretstore.Store{
		"vault": {Name: "vault", Type: secretstore.TypeHashiCorpVault, AllowedPaths: []string{"ai/"}, AllowedDestinations: []string{"collector"}},
	}}
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: catalog, Resolver: &markerResolver{}})
	got := m.Values(context.Background(), gw, "", []Use{
		{Path: []string{"a"}, Raw: refStr("x"), Hosts: []string{"collector"}},
		{Path: []string{"b"}, Raw: refStr("x"), Hosts: []string{"elsewhere"}},
		{Path: []string{"c"}, Raw: refStr("x")},
		{Path: []string{"d"}, Raw: refStr("x"), SelfAddressed: true},
	})
	if got[0].Err != nil || got[3].Err != nil {
		t.Fatalf("allowed and self-addressed values must resolve: %v, %v", got[0].Err, got[3].Err)
	}
	for _, i := range []int{1, 2} {
		if !errors.Is(got[i].Err, secretstore.ErrDestinationNotAllowed) || got[i].Value != "" {
			t.Errorf("use %d: %+v, want destination_not_allowed", i, got[i])
		}
	}
	if !strings.Contains(got[2].Err.Error(), "unknown") {
		t.Errorf("a use with no host must say why: %v", got[2].Err)
	}
}

func TestHealthReportsTheLastOutcomeOfEachReference(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	resolver := &markerResolver{}
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: resolver})
	if h := m.Health(); h.Total != 0 {
		t.Fatalf("nothing resolved yet: %+v", h)
	}
	good := withKeyFor(gw, refStr("openai#key"))
	bad := withKeyFor(gw, "secret://vault/prod/key")
	m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{good.ID: good, bad.ID: bad})
	m.Values(context.Background(), gw, SourceAuths, []Use{{Path: []string{"config", "oauth2", "client_secret"}, Raw: refStr("idp"), Hosts: []string{"idp"}, Entity: "auth", ID: "a1"}})
	m.Values(context.Background(), gw, SourceAuthCredentials, []Use{{Path: []string{"config", "oauth2", "client_secret"}, Raw: refStr("idp"), Hosts: []string{"idp"}, Entity: "auth", ID: "a1"}})

	h := m.Health()
	if h.Total != 3 || h.Unresolved != 1 || len(h.Outcomes) != 3 {
		t.Fatalf("health = %+v; want three references, the auth counted once", h)
	}
	first := h.Outcomes[0]
	if first.Class != secretstore.ClassPathNotAllowed || first.ID != bad.ID.String() || first.Entity != "registry" || first.Store != "vault" || first.Path != "prod/key" || first.Reference != "secret://vault/prod/key" {
		t.Fatalf("failing outcome = %+v, want it first", first)
	}
	if _, ok := h.Find(gw, "registry", good.ID.String(), "llm_target.auth.api_key.api_key", "secret://vault/ai/openai#key"); !ok {
		t.Fatalf("resolved outcome missing: %+v", h.Outcomes)
	}

	m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{good.ID: good})
	if h := m.Health(); h.Total != 2 || h.Unresolved != 0 {
		t.Fatalf("a removed reference must leave the report: %+v", h)
	}
}

func withKeyFor(gw ids.GatewayID, key string) *registry.Registry {
	return &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{Provider: "openai", Auth: registry.NewAPIKeyAuth(key)}}
}
