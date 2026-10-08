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
	"errors"
	"net/url"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type recordingPersonalKeyLinks struct {
	ticket appoauth.PersonalKeyTicket
	calls  int
}

func (r *recordingPersonalKeyLinks) CreateTicket(_ context.Context, t appoauth.PersonalKeyTicket) (string, error) {
	r.calls++
	r.ticket = t
	return "pk+ticket", nil
}

func personalKeyStoreTool(t *testing.T, links PersonalKeyLinks) (StoreTool, *appconsumer.RoutableConsumer, *gatewaydomain.Gateway) {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	var opts []StoreToolOption
	if links != nil {
		opts = append(opts, WithStoreToolPersonalKeys(links, "llm.example"))
	}
	tool, err := NewStoreToolWithInstaller(e2eCatalog{}, nil, nil, nil, nil, nil, opts...)
	if err != nil {
		t.Fatalf("new store tool: %v", err)
	}
	return tool, &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw.ID)}, gw
}

func personalKeyCtx(gw *gatewaydomain.Gateway, data *appconsumer.Data) context.Context {
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	ctx = appgateway.WithGateway(ctx, gw)
	if data != nil {
		ctx = appconsumer.WithData(ctx, data)
	}
	return ctx
}

func TestStorePersonalKey_IsOfferedOnlyWhereAKeyCanBeIssued(t *testing.T) {
	without, rc, gw := personalKeyStoreTool(t, nil)
	for _, def := range without.Definitions(personalKeyCtx(gw, nil), rc) {
		if marshalToolDef(t, def)["name"] == StorePersonalKeyToolName {
			t.Fatal("a plane that cannot issue keys must not offer the tool")
		}
	}
	with, rc, gw := personalKeyStoreTool(t, &recordingPersonalKeyLinks{})
	found := false
	for _, def := range with.Definitions(personalKeyCtx(gw, nil), rc) {
		if d := marshalToolDef(t, def); d["name"] == StorePersonalKeyToolName {
			found = true
			if desc, _ := d["description"].(string); !strings.Contains(desc, "never to you") {
				t.Fatalf("the description must say the key is not shown to the model, got %q", desc)
			}
		}
	}
	if !found {
		t.Fatal("the personal key tool must be listed")
	}
}

// The tool answers a link, never a key: the person signs in on the page and
// sees the key there. The link knows whose key it is and where their tools and
// models are served, for the page's usage.
func TestStorePersonalKey_HandsTheUserALinkToTheirPage(t *testing.T) {
	links := &recordingPersonalKeyLinks{}
	tool, rc, gw := personalKeyStoreTool(t, links)
	personal := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Slug: "llm-store-all", Type: consumerdomain.TypeLLM,
		Audience: consumerdomain.AudiencePersonal, Active: true,
	}}})

	raw, err := tool.Call(personalKeyCtx(gw, personal), rc, "https://acme.mcp.example/store/mcp", StorePersonalKeyToolName, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	if links.calls != 1 || links.ticket.PrincipalSub != "alice" || links.ticket.GatewayID != gw.ID.String() {
		t.Fatalf("ticket = %+v, want alice's on this gateway", links.ticket)
	}
	if links.ticket.MCPURL != "https://acme.mcp.example/store/mcp" || links.ticket.LLMURL != "https://acme.llm.example/store/v1" {
		t.Fatalf("ticket endpoints = %q / %q", links.ticket.MCPURL, links.ticket.LLMURL)
	}
	var result struct {
		Content           []struct{ Text string } `json:"content"`
		StructuredContent map[string]any          `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	link, _ := result.StructuredContent["personal_key_url"].(string)
	u, err := url.Parse(link)
	if err != nil || u.Path != appoauth.PersonalKeyPagePath || u.Query().Get("ticket") != "pk+ticket" || u.Host != "acme.mcp.example" {
		t.Fatalf("link = %q, want the page on this host with the ticket", link)
	}
	if result.StructuredContent["action"] != "user_confirmation_required" {
		t.Fatalf("structured = %+v", result.StructuredContent)
	}
	if !strings.Contains(result.Content[0].Text, "[Personal key]("+link+")") || !strings.Contains(result.Content[0].Text, "do not ask them to paste it") {
		t.Fatalf("text = %q", result.Content[0].Text)
	}
}

func TestStorePersonalKey_NamesNoModelsWhereTheKeyReachesNone(t *testing.T) {
	links := &recordingPersonalKeyLinks{}
	tool, rc, gw := personalKeyStoreTool(t, links)

	if _, err := tool.Call(personalKeyCtx(gw, appconsumer.NewData(gw.ID, nil)), rc, "https://acme.mcp.example", StorePersonalKeyToolName, nil); err != nil {
		t.Fatalf("call: %v", err)
	}
	if links.ticket.LLMURL != "" {
		t.Fatalf("LLM URL = %q, want none on a gateway without personal consumers", links.ticket.LLMURL)
	}
}

func TestStorePersonalKey_SaysAHybridGatewayHasNone(t *testing.T) {
	links := &recordingPersonalKeyLinks{}
	tool, rc, gw := personalKeyStoreTool(t, links)
	gw.Entitlements.DataPlane = gatewaydomain.DataPlaneHybrid

	raw, err := tool.Call(personalKeyCtx(gw, nil), rc, "https://acme.mcp.example", StorePersonalKeyToolName, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if links.calls != 0 || !strings.Contains(string(raw), "not available on this gateway") {
		t.Fatalf("a hybrid gateway must mint no link, got %s", raw)
	}
}

func TestStorePersonalKey_NeedsAPerson(t *testing.T) {
	tool, rc, _ := personalKeyStoreTool(t, &recordingPersonalKeyLinks{})
	if _, err := tool.Call(context.Background(), rc, "https://acme.mcp.example", StorePersonalKeyToolName, nil); !errors.Is(err, ErrNoPrincipal) {
		t.Fatalf("err = %v, want ErrNoPrincipal", err)
	}
}

func marshalToolDef(t *testing.T, tool Tool) map[string]any {
	t.Helper()
	raw, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}
