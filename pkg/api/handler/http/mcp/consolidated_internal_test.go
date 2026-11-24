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
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// An install or an uninstall through trustgate_access changes the surface on
// the same terms as through the Store tools; connecting does not.
func TestChangesTheSurface_Access(t *testing.T) {
	t.Parallel()
	installed := json.RawMessage(`{"content":[],"structuredContent":{"code":"x","action":"install","status":"installed"}}`)
	adminSetup := json.RawMessage(`{"content":[],"structuredContent":{"code":"x","requires_admin_setup":true}}`)
	notInstalled := json.RawMessage(`{"content":[],"structuredContent":{"code":"x","uninstalled":false,"was_installed":false}}`)
	for label, tc := range map[string]struct {
		params string
		result json.RawMessage
		want   bool
	}{
		"install":              {params: `{"name":"trustgate_access","arguments":{"action":"install","target":"x"}}`, result: installed, want: true},
		"install, admin setup": {params: `{"name":"trustgate_access","arguments":{"action":"install","target":"x"}}`, result: adminSetup, want: false},
		"uninstall, nothing":   {params: `{"name":"trustgate_access","arguments":{"action":"uninstall","target":"x"}}`, result: notInstalled, want: false},
		"connect":              {params: `{"name":"trustgate_access","arguments":{"action":"connect","target":"x"}}`, result: installed, want: false},
	} {
		if got := changesTheSurface("tools/call", json.RawMessage(tc.params), tc.result); got != tc.want {
			t.Fatalf("%s: changesTheSurface = %v, want %v", label, got, tc.want)
		}
	}
}

func TestMCPRequestAttrs_GatewayCallNamesWhatItCalled(t *testing.T) {
	t.Parallel()
	_, tool, _, _ := mcpRequestAttrs("tools/call", json.RawMessage(`{"name":"trustgate_call","arguments":{"tool":"linear_save_issue","arguments":{}}}`))
	if tool != "linear_save_issue" {
		t.Fatalf("tool = %q", tool)
	}
	_, tool, _, _ = mcpRequestAttrs("tools/call", json.RawMessage(`{"name":"trustgate_call","arguments":{"agent":"research","message":"hi"}}`))
	if tool != "research" {
		t.Fatalf("agent = %q", tool)
	}
}

// The instructions a client reads at initialize name the tools it is offered.
func TestSurfaceInstructions(t *testing.T) {
	t.Parallel()
	since := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	gw := &gatewaydomain.Gateway{Metadata: map[string]string{gatewaydomain.MetadataMCPGatewayToolsSinceKey: since.Format(time.RFC3339)}}
	session := func(connected time.Time) context.Context {
		return identity.WithPrincipal(appgateway.WithGateway(context.Background(), gw), &identity.Principal{
			Subject: "alice",
			Method:  identity.MethodOAuth,
			Claims: map[string]any{
				identity.ClaimTokenUse:        identity.TokenUseMCPSession,
				identity.ClaimMCPSessionStart: float64(connected.Unix()),
			},
		})
	}
	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(ids.New[ids.GatewayKind]())}

	consolidated := surfaceInstructions(session(since.Add(time.Hour)), store)
	for _, name := range []string{appmcp.SearchToolName, appmcp.GatewayCallToolName, appmcp.AccessToolName} {
		if !strings.Contains(consolidated, name) {
			t.Fatalf("consolidated instructions do not name %s", name)
		}
	}
	for _, name := range []string{appmcp.InventoryToolName, appmcp.CallToolName, appmcp.StoreSearchToolName, appmcp.StoreInstallToolName, appmcp.ListAgentsToolName} {
		if strings.Contains(consolidated, name) {
			t.Fatalf("consolidated instructions name the earlier %s", name)
		}
	}
	if got, want := surfaceInstructions(session(since.Add(-time.Hour)), store), serverInstructions(store); got != want {
		t.Fatal("a client connected before the switch must read the instructions it always did")
	}
}
