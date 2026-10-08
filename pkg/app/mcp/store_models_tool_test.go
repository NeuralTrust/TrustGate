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

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type ownedKeysByOwner map[string]*authdomain.Auth

func (o ownedKeysByOwner) FindByOwner(_ context.Context, _ ids.GatewayID, owner string) (*authdomain.Auth, error) {
	if key, ok := o[owner]; ok {
		return key, nil
	}
	return nil, authdomain.ErrNotFound
}

type recordingModelLister struct {
	links  []appconsumer.StoreLink
	models []StoreModel
}

func (r *recordingModelLister) StoreModels(_ context.Context, links []appconsumer.StoreLink, _ *appconsumer.Data) ([]StoreModel, error) {
	r.links = links
	return r.models, nil
}

type modelsFixture struct {
	tool   StoreTool
	rc     *appconsumer.RoutableConsumer
	gw     *gatewaydomain.Gateway
	data   *appconsumer.Data
	key    *authdomain.Auth
	lister *recordingModelLister
}

func newModelsFixture(t *testing.T, models []StoreModel) *modelsFixture {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	key, err := authdomain.NewOwnedAPIKeyAuth(gw.ID, "alice", time.Now().Add(time.Hour), time.Now())
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Slug: "llm-store-all", Type: consumerdomain.TypeLLM,
		Audience: consumerdomain.AudiencePersonal, Active: true,
		AuthIDs:   []ids.AuthID{key.ID},
		AuthLinks: map[ids.AuthID]consumerdomain.AuthLink{key.ID: {Level: consumerdomain.GrantLevelUser, Priority: 1}},
	}}})
	lister := &recordingModelLister{models: models}
	tool, err := NewStoreToolWithInstaller(e2eCatalog{}, nil, nil, nil, nil, nil,
		WithStoreToolModels(ownedKeysByOwner{"alice": key}, lister, "llm.example"))
	if err != nil {
		t.Fatalf("new store tool: %v", err)
	}
	return &modelsFixture{tool: tool, rc: &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw.ID)}, gw: gw, data: data, key: key, lister: lister}
}

func (f *modelsFixture) call(t *testing.T, subject string) (string, map[string]any) {
	t.Helper()
	ctx := personalKeyCtx(f.gw, f.data)
	if subject != "alice" {
		ctx = personalKeyCtxAs(f.gw, f.data, subject)
	}
	raw, err := f.tool.Call(ctx, f.rc, "https://acme.mcp.example/store/mcp", StoreModelsToolName, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var result struct {
		Content           []struct{ Text string } `json:"content"`
		StructuredContent map[string]any          `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return result.Content[0].Text, result.StructuredContent
}

// The user's models, as their key's own /store/v1/models lists them, grouped
// by provider, with where to call them.
func TestStoreModels_ListsWhatTheKeyReachesByProvider(t *testing.T) {
	f := newModelsFixture(t, []StoreModel{
		{ID: "gpt6", Provider: "openai"}, {ID: "opus-5.5", Provider: "anthropic"}, {ID: "gpt-4.1", Provider: "openai"}, {ID: "gpt6", Provider: "openai"},
	})

	text, structured := f.call(t, "alice")

	if len(f.lister.links) != 1 || f.lister.links[0].Consumer.Consumer.Slug != "llm-store-all" {
		t.Fatalf("links = %+v, want the key's personal consumer", f.lister.links)
	}
	providers, _ := json.Marshal(structured["providers"])
	if string(providers) != `[{"models":["opus-5.5"],"provider":"anthropic"},{"models":["gpt-4.1","gpt6"],"provider":"openai"}]` {
		t.Fatalf("providers = %s", providers)
	}
	if structured["base_url"] != "https://acme.llm.example/store/v1" {
		t.Fatalf("base_url = %v", structured["base_url"])
	}
	if !strings.Contains(text, "3 models") || !strings.Contains(text, "- openai: gpt-4.1, gpt6") || strings.Contains(text, f.key.KeyHash) {
		t.Fatalf("text = %q", text)
	}
}

func TestStoreModels_SaysWhatIsMissing(t *testing.T) {
	f := newModelsFixture(t, nil)

	text, structured := f.call(t, "bob")
	if structured["has_key"] != false || !strings.Contains(text, StorePersonalKeyToolName) {
		t.Fatalf("no key: %q %+v", text, structured)
	}

	text, structured = f.call(t, "alice")
	if structured["key_active"] != true || !strings.Contains(text, "reaches no models yet") {
		t.Fatalf("no models: %q %+v", text, structured)
	}

	past := time.Now().Add(-time.Hour)
	f.key.ExpiresAt = &past
	text, structured = f.call(t, "alice")
	if structured["key_active"] != false || !strings.Contains(text, "expired") {
		t.Fatalf("expired key: %q %+v", text, structured)
	}
}

func TestStoreModels_IsOfferedOnlyWhereItCanAnswer(t *testing.T) {
	f := newModelsFixture(t, nil)
	if !hasToolNamed(t, f.tool.Definitions(personalKeyCtx(f.gw, nil), f.rc), StoreModelsToolName) {
		t.Fatal("the models tool must be listed")
	}
	without, rc, gw := personalKeyStoreTool(t, nil)
	if hasToolNamed(t, without.Definitions(personalKeyCtx(gw, nil), rc), StoreModelsToolName) {
		t.Fatal("a plane that cannot list models must not offer the tool")
	}
}

func hasToolNamed(t *testing.T, defs []Tool, name string) bool {
	t.Helper()
	for _, def := range defs {
		if marshalToolDef(t, def)["name"] == name {
			return true
		}
	}
	return false
}
