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

package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type recordingProtocolValidator struct {
	mu      sync.Mutex
	records []protocolValidationCall
}

type protocolValidationCall struct {
	class mcphttp.ValidationClass
	era   string
}

func (r *recordingProtocolValidator) Record(_ context.Context, class mcphttp.ValidationClass, era string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, protocolValidationCall{class: class, era: era})
}

func TestHandler_ProtocolHTTP400IncrementsBoundedClass(t *testing.T) {
	t.Parallel()
	rec := &recordingProtocolValidator{}
	var skipped bool
	app := newAppWithProtocolRecorder(t, rec, func(c *fiber.Ctx) {
		skipped, _ = c.Locals(string(infracontext.MCPSkipMetricsKey)).(bool)
	})
	status, _ := rpcCallWithHeaders(t, app,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		http.Header{"MCP-Protocol-Version": {"2026-07-28"}, "Mcp-Method": {"wrong"}},
	)
	require.Equal(t, fiber.StatusBadRequest, status)
	require.True(t, skipped)
	require.Equal(t, []protocolValidationCall{{class: mcphttp.ValidationClassHeaderMismatch, era: "modern"}}, rec.records)

	rec.records = nil
	status, _ = rpcCallWithHeaders(t, app, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, http.Header{"MCP-Protocol-Version": {"2099-01-01"}})
	require.Equal(t, fiber.StatusBadRequest, status)
	require.Equal(t, []protocolValidationCall{{class: mcphttp.ValidationClassUnsupportedVersion, era: "modern"}}, rec.records)
}

func TestHandler_AuthAndPathSkipProtocolCounter(t *testing.T) {
	t.Parallel()
	rec := &recordingProtocolValidator{}
	var skipped bool
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		err := c.Next()
		skipped, _ = c.Locals(string(infracontext.MCPSkipMetricsKey)).(bool)
		return err
	})
	handler := mcphttp.NewHandler(mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil), appmcp.NewRoleScoper(approle.NewOIDCResolver()), rec)
	app.Post(mcpPath, handler.Handle)
	app.Get(mcpPath, handler.MethodNotAllowed)

	status, _ := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Equal(t, fiber.StatusUnauthorized, status)
	require.True(t, skipped)
	require.Empty(t, rec.records)

	res, err := app.Test(httptest.NewRequest(fiber.MethodGet, mcpPath, nil), -1)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, fiber.StatusMethodNotAllowed, res.StatusCode)
	require.Empty(t, rec.records)
}

func newAppWithProtocolRecorder(t *testing.T, rec mcphttp.ProtocolValidationRecorder, after func(*fiber.Ctx)) *fiber.App {
	t.Helper()
	app := fiber.New()
	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gwID, Name: "virtual",
		Type: consumerdomain.TypeMCP, Slug: "virtual", Active: true, AuthIDs: []ids.AuthID{authID},
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{{Consumer: cons}})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		err := c.Next()
		if after != nil {
			after(c)
		}
		return err
	})
	handler := mcphttp.NewHandler(mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil), appmcp.NewRoleScoper(approle.NewOIDCResolver()), rec)
	app.Post(mcpPath, handler.Handle)
	return app
}

const modernToolsListBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`

func newAppWithMCPPolicy(
	t *testing.T,
	rec mcphttp.ProtocolValidationRecorder,
	composer appmcp.Composer,
	mcp *consumerdomain.MCPPolicy,
	after func(*fiber.Ctx),
) *fiber.App {
	t.Helper()
	app := fiber.New()
	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gwID, Name: "virtual",
		Type: consumerdomain.TypeMCP, Slug: "virtual", Active: true, AuthIDs: []ids.AuthID{authID},
		MCP: mcp,
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{{Consumer: cons}})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		err := c.Next()
		if after != nil {
			after(c)
		}
		return err
	})
	handler := mcphttp.NewHandler(mcphttp.NewRPCGateway(composer, noopRunner(), nil), appmcp.NewRoleScoper(approle.NewOIDCResolver()), rec)
	app.Post(mcpPath, handler.Handle)
	return app
}

func TestHandler_LegacyOnlyRejectsModern(t *testing.T) {
	t.Parallel()
	rec := &recordingProtocolValidator{}
	var skipped bool
	composer := mocks.NewComposer(t)
	app := newAppWithMCPPolicy(t, rec, composer, &consumerdomain.MCPPolicy{
		ProtocolAcceptance: consumerdomain.ProtocolAcceptanceLegacyOnly,
	}, func(c *fiber.Ctx) {
		skipped, _ = c.Locals(string(infracontext.MCPSkipMetricsKey)).(bool)
	})

	status, body := rpcCallWithHeaders(t, app, modernToolsListBody, modernHeadersFor("tools/list"))
	require.Equal(t, fiber.StatusBadRequest, status)
	require.True(t, skipped)
	require.Equal(t, []protocolValidationCall{{class: mcphttp.ValidationClassAcceptanceDenied, era: "modern"}}, rec.records)
	rpcErr, _ := body["error"].(map[string]any)
	require.Equal(t, float64(-32021), rpcErr["code"])
	composer.AssertNotCalled(t, "ListTools", mock.Anything, mock.Anything)
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandler_LegacyOnlyAcceptsLegacy(t *testing.T) {
	t.Parallel()
	rec := &recordingProtocolValidator{}
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{}, nil).Once()
	app := newAppWithMCPPolicy(t, rec, composer, &consumerdomain.MCPPolicy{
		ProtocolAcceptance: consumerdomain.ProtocolAcceptanceLegacyOnly,
	}, nil)

	status, _ := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Equal(t, fiber.StatusOK, status)
	require.Empty(t, rec.records)
}

func TestHandler_DefaultPreservesDualEra(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mcp  *consumerdomain.MCPPolicy
	}{
		{"unset", nil},
		{"empty policy", &consumerdomain.MCPPolicy{}},
		{"dual_era", &consumerdomain.MCPPolicy{ProtocolAcceptance: consumerdomain.ProtocolAcceptanceDualEra}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recordingProtocolValidator{}
			composer := mocks.NewComposer(t)
			var tool appmcp.Tool
			require.NoError(t, json.Unmarshal([]byte(`{"name":"gh_search","inputSchema":{"type":"object"}}`), &tool))
			composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{tool}, nil).Once()
			app := newAppWithMCPPolicy(t, rec, composer, tc.mcp, nil)

			status, _ := rpcCallWithHeaders(t, app, modernToolsListBody, modernHeadersFor("tools/list"))
			require.Equal(t, fiber.StatusOK, status)
			require.Empty(t, rec.records)
		})
	}
}
