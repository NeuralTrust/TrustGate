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

package trustguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// playgroundCapturingServer wraps a fakeGuard's real handler (token +
// evaluate) and additionally records the X-AG-Playground header value the
// /v1/evaluate call carried, so a test can assert on exactly what trustguard's
// own outbound client (client.go:127) sent toward the collector — the same
// signal a real TrustGuard deployment would use to categorize the request.
type playgroundCapturingServer struct {
	mu         sync.Mutex
	playground string
	hits       int
}

func (s *playgroundCapturingServer) start(t *testing.T, f *fakeGuard) *httptest.Server {
	t.Helper()
	inner := f.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == evaluatePath {
			s.mu.Lock()
			s.playground = r.Header.Get(playgroundOriginHeader)
			s.hits++
			s.mu.Unlock()
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (s *playgroundCapturingServer) get() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.playground, s.hits
}

// mcpRunnerWithPlugin wires the real production chain a tools/call actually
// takes — appmcp.PluginRunner over the real appplugins.Executor — with the
// real trustguard plugin registered, so the test exercises
// pkg/app/mcp/plugin_runner.go's buildRequestContext exactly as production
// does, not a hand-built RequestContext standing in for it.
func mcpRunnerWithPlugin(t *testing.T, p *Plugin) (*appmcp.PluginRunner, *appconsumer.RoutableConsumer) {
	t.Helper()
	reg := appplugins.NewRegistry()
	if err := reg.Register(p); err != nil {
		t.Fatalf("register trustguard plugin: %v", err)
	}
	exec := appplugins.NewExecutor(reg, nil)
	runner := appmcp.NewPluginRunner(exec, nil)
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{Type: consumerdomain.TypeMCP},
		Policies: []*policy.Policy{{
			Enabled:  true,
			Slug:     PluginName,
			Mode:     policy.ModeEnforce,
			Stages:   []policy.Stage{policy.StagePreRequest},
			Settings: settings("request_response"),
		}},
	}
	return runner, rc
}

// TestMCPToolCall_ForgedPlaygroundHeader_DoesNotReachTrustGuard is the
// red/green boundary test for the security fix that followed RUN-1674's
// header propagation: an MCP client is authenticated by MCPAuthMiddleware
// (mTLS/bearer/API key, pkg/api/middleware/mcp_auth.go) which never checks
// x-ag-playground-token, unlike the proxy/LLM plane's ChainedIdentityResolver
// (pkg/api/resolver/chained_resolver.go:55), which routes the header
// EXCLUSIVELY through a JWT verifier before a request carrying it ever reaches
// a plugin. So an authenticated MCP caller can set that header to anything.
//
// trustguard/plugin.go's requestHasPlaygroundToken checks only presence, and
// the resulting bool becomes the X-AG-Playground collector header
// (client.go:127) — a real security signal, not cosmetic. Propagating real
// inbound headers to MCP's RequestContext (this package's sibling change) must
// not let a forged token ride through: pkg/infra/context/inbound_headers.go's
// unverifiedOnMCP deny list strips it before any plugin ever sees it.
func TestMCPToolCall_ForgedPlaygroundHeader_DoesNotReachTrustGuard(t *testing.T) {
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	capture := &playgroundCapturingServer{}
	srv := capture.start(t, f)

	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
	runner, rc := mcpRunnerWithPlugin(t, p)
	call := appmcp.ToolCall{Exposed: "search", NativeTool: "search", Arguments: json.RawMessage(`{"query":"hello"}`)}

	ctx := infracontext.WithInboundHeaders(context.Background(), map[string][]string{
		"x-ag-playground-token": {"forged"},
	})

	_, err := runner.PreRequest(ctx, rc, call)
	if err != nil {
		t.Fatalf("PreRequest: %v", err)
	}

	playground, hits := capture.get()
	if hits == 0 {
		t.Fatal("fake collector never received the /v1/evaluate call — test did not exercise the real path")
	}
	if playground == "1" {
		t.Fatal("forged x-ag-playground-token reached TrustGuard as a verified playground marker; " +
			"MCPAuthMiddleware never verifies that header, so any authenticated MCP client could set it")
	}
}
