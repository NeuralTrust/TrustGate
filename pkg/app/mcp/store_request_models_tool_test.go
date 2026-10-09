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
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type scriptedModelConsole struct {
	answer *appoauth.ModelAccessAnswer
	err    error
	asked  []appoauth.ModelAccessQuery
	filed  []appoauth.ModelAccessFiling
}

func (c *scriptedModelConsole) Check(_ context.Context, q appoauth.ModelAccessQuery) (*appoauth.ModelAccessAnswer, error) {
	c.asked = append(c.asked, q)
	return c.answer, c.err
}

func (c *scriptedModelConsole) File(_ context.Context, f appoauth.ModelAccessFiling) (*appoauth.ModelAccessAnswer, error) {
	c.filed = append(c.filed, f)
	return c.answer, c.err
}

type recordingModelRequestLinks struct{ tickets []appoauth.ModelRequestTicket }

func (r *recordingModelRequestLinks) CreateTicket(_ context.Context, t appoauth.ModelRequestTicket) (string, error) {
	r.tickets = append(r.tickets, t)
	return "tkt-1", nil
}

type requestModelsFixture struct {
	tool    StoreTool
	rc      *appconsumer.RoutableConsumer
	gw      *gatewaydomain.Gateway
	console *scriptedModelConsole
	links   *recordingModelRequestLinks
}

func newRequestModelsFixture(t *testing.T, answer *appoauth.ModelAccessAnswer) *requestModelsFixture {
	t.Helper()
	gw := &gatewaydomain.Gateway{
		ID:       ids.New[ids.GatewayKind](),
		Slug:     "acme",
		Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: "team-1"},
	}
	console := &scriptedModelConsole{answer: answer}
	links := &recordingModelRequestLinks{}
	tool, err := NewStoreToolWithInstaller(e2eCatalog{}, nil, nil, nil, nil, nil, WithStoreToolModelRequests(console, links))
	if err != nil {
		t.Fatalf("new store tool: %v", err)
	}
	return &requestModelsFixture{
		tool:    tool,
		rc:      &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw.ID)},
		gw:      gw,
		console: console,
		links:   links,
	}
}

func (f *requestModelsFixture) call(t *testing.T, args string) (string, map[string]any) {
	t.Helper()
	raw, err := f.tool.Call(personalKeyCtx(f.gw, nil), f.rc, "https://acme.mcp.example/store/mcp", StoreRequestModelsToolName, json.RawMessage(args))
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

// The request is checked with the console for the caller, as the console's
// user, and the answer is the form where the person writes why: the tool
// takes no reason of the model's.
func TestStoreRequestModels_HandsTheFormForWhatTheConsoleResolved(t *testing.T) {
	f := newRequestModelsFixture(t, &appoauth.ModelAccessAnswer{
		Status: appoauth.ModelAccessOK, Name: "Mistral", Provider: "mistral", RegistryID: "reg-mistral",
	})

	text, structured := f.call(t, `{"provider":" Mistral "}`)

	if len(f.console.asked) != 1 || f.console.asked[0] != (appoauth.ModelAccessQuery{
		TeamID: "team-1", GatewayID: f.gw.ID.String(), UserID: "alice", Provider: "Mistral",
	}) {
		t.Fatalf("asked = %+v", f.console.asked)
	}
	if len(f.links.tickets) != 1 || f.links.tickets[0] != (appoauth.ModelRequestTicket{
		TeamID: "team-1", GatewayID: f.gw.ID.String(), PrincipalSub: "alice", Provider: "mistral", RegistryID: "reg-mistral", Name: "Mistral",
	}) {
		t.Fatalf("tickets = %+v", f.links.tickets)
	}
	want := "https://acme.mcp.example" + appoauth.ModelRequestPagePath + "?ticket=tkt-1"
	if structured["request_url"] != want || structured["requires_reason"] != true || structured["request_link_label"] != "Request access to Mistral models" {
		t.Fatalf("structured = %+v", structured)
	}
	if !strings.Contains(text, want) || !strings.Contains(text, "Do not write the reason for them") {
		t.Fatalf("text = %q", text)
	}
	if len(f.console.filed) != 0 {
		t.Fatal("nothing is filed until the person sends the form")
	}
}

func TestStoreRequestModels_SaysWhatTheConsoleRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		answer *appoauth.ModelAccessAnswer
		text   string
		flag   string
	}{
		"already reached": {
			answer: &appoauth.ModelAccessAnswer{Status: appoauth.ModelAccessHasAccess, Name: "Anthropic", Error: "You already have access to Anthropic models"},
			text:   "You already have access to Anthropic models. " + StoreModelsToolName + " lists them.",
			flag:   "has_access",
		},
		"already asked": {
			answer: &appoauth.ModelAccessAnswer{Status: appoauth.ModelAccessAlreadyAsked, Error: "A request for Mistral models is already waiting for an admin"},
			text:   "already waiting for an admin.",
			flag:   "already_requested",
		},
		"unknown": {
			answer: &appoauth.ModelAccessAnswer{Status: appoauth.ModelAccessUnknown, Providers: []appoauth.ModelAccessProvider{{Provider: "openai", Name: "OpenAI"}}},
			text:   "Its providers are: OpenAI (openai).",
			flag:   "unknown_provider",
		},
	} {
		f := newRequestModelsFixture(t, tc.answer)
		text, structured := f.call(t, `{"provider":"x"}`)
		if !strings.Contains(text, tc.text) || structured[tc.flag] != true {
			t.Fatalf("%s: text = %q, structured = %+v", name, text, structured)
		}
		if len(f.links.tickets) != 0 {
			t.Fatalf("%s: no form for a request that cannot be filed", name)
		}
	}
}

// Several registries the person does not reach: the choice goes back to the
// user, and the one they pick comes back as registry_id.
func TestStoreRequestModels_AsksWhichRegistry(t *testing.T) {
	f := newRequestModelsFixture(t, &appoauth.ModelAccessAnswer{
		Status: appoauth.ModelAccessChooseRegistry, Name: "Mistral", Provider: "mistral",
		Registries: []appoauth.ModelAccessChoice{{RegistryID: "reg-a", Name: "Mistral"}, {RegistryID: "reg-b", Name: "Mistral EU"}},
	})

	text, structured := f.call(t, `{"provider":"mistral"}`)
	if structured["requires_registry_choice"] != true || !strings.Contains(text, `Mistral EU — registry_id "reg-b"`) {
		t.Fatalf("text = %q, structured = %+v", text, structured)
	}

	f.console.answer = &appoauth.ModelAccessAnswer{Status: appoauth.ModelAccessOK, Name: "Mistral EU", Provider: "mistral", RegistryID: "reg-b"}
	f.call(t, `{"provider":"mistral","registry_id":"reg-b"}`)
	if got := f.console.asked[1].RegistryID; got != "reg-b" {
		t.Fatalf("registry_id = %q, want the one chosen", got)
	}
}

func TestStoreRequestModels_NothingToAskForOnAHybridGateway(t *testing.T) {
	f := newRequestModelsFixture(t, nil)
	f.gw.Entitlements.DataPlane = gatewaydomain.DataPlaneHybrid
	_, structured := f.call(t, `{"provider":"openai"}`)
	if structured["available"] != false || len(f.console.asked) != 0 {
		t.Fatalf("structured = %+v, asked = %d", structured, len(f.console.asked))
	}
}

func TestStoreRequestModels_FailsWhenTheConsoleCannotBeAsked(t *testing.T) {
	f := newRequestModelsFixture(t, nil)
	f.console.err = errors.New("console down")
	_, err := f.tool.Call(personalKeyCtx(f.gw, nil), f.rc, "https://acme.mcp.example/store/mcp", StoreRequestModelsToolName, json.RawMessage(`{"provider":"openai"}`))
	if !errors.Is(err, ErrStoreToolUnavailable) {
		t.Fatalf("err = %v, want ErrStoreToolUnavailable", err)
	}
}

func TestStoreRequestModels_IsOfferedOnlyWhereTheConsoleTakesRequests(t *testing.T) {
	f := newRequestModelsFixture(t, nil)
	without, err := NewStoreToolWithInstaller(e2eCatalog{}, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("new store tool: %v", err)
	}
	offered := func(tool StoreTool) bool {
		for _, def := range tool.Definitions(personalKeyCtx(f.gw, nil), f.rc) {
			if marshalToolDef(t, def)["name"] == StoreRequestModelsToolName {
				return true
			}
		}
		return false
	}
	if !offered(f.tool) || offered(without) {
		t.Fatal("the request tool is offered exactly where the console takes requests")
	}
}

// The models tool says where a provider it does not list is asked for: this
// tool where the Store offers it, the Portal otherwise.
func TestStoreModels_PointsAtTheRequestTool(t *testing.T) {
	f := newModelsFixture(t, []StoreModel{{ID: "gpt6", Provider: "openai"}})
	text, _ := f.call(t, "alice")
	if !strings.Contains(text, "ask for its models from the Portal") {
		t.Fatalf("without the request tool: %q", text)
	}

	tool, err := NewStoreToolWithInstaller(e2eCatalog{}, nil, nil, nil, nil, nil,
		WithStoreToolModels(ownedKeysByOwner{"alice": f.key}, f.lister, "llm.example"),
		WithStoreToolModelRequests(&scriptedModelConsole{}, &recordingModelRequestLinks{}))
	if err != nil {
		t.Fatalf("new store tool: %v", err)
	}
	f.tool = tool
	text, _ = f.call(t, "alice")
	if !strings.Contains(text, "ask for its models with "+StoreRequestModelsToolName) {
		t.Fatalf("with the request tool: %q", text)
	}
}
