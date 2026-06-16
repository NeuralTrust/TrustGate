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

package middleware_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	identitydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type stubIdentityResolver struct {
	identity middleware.Identity
	err      error
}

func (s stubIdentityResolver) Resolve(*fiber.Ctx) (middleware.Identity, error) {
	return s.identity, s.err
}

type stubGatewayFinder struct {
	gw *gatewaydomain.Gateway
}

func (s stubGatewayFinder) FindByID(context.Context, ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if s.gw == nil {
		return nil, errors.New("not found")
	}
	return s.gw, nil
}

func (s stubGatewayFinder) FindBySlug(context.Context, string) (*gatewaydomain.Gateway, error) {
	return s.FindByID(context.Background(), ids.GatewayID{})
}

func (s stubGatewayFinder) List(context.Context, gatewaydomain.ListFilter) ([]*gatewaydomain.Gateway, int, error) {
	return nil, 0, nil
}

type stubDataFinder struct {
	data *appconsumer.Data
}

func (s stubDataFinder) FindByGateway(context.Context, ids.GatewayID) (*appconsumer.Data, error) {
	if s.data == nil {
		return nil, errors.New("boom")
	}
	return s.data, nil
}

func newMCPAuthApp(t *testing.T, m *middleware.MCPAuthMiddleware, handler fiber.Handler) *fiber.App {
	t.Helper()
	app := fiber.New()
	app.Post("/*", m.Middleware(), handler)
	return app
}

func TestMCPAuthMiddleware_RejectsUnauthenticated(t *testing.T) {
	t.Parallel()
	m := middleware.NewMCPAuthMiddleware(
		stubIdentityResolver{err: errors.New("nope")},
		stubDataFinder{data: &appconsumer.Data{}},
		stubGatewayFinder{gw: &gatewaydomain.Gateway{}},
	)
	app := newMCPAuthApp(t, m, func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	res, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/dev/mcp", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, res.StatusCode)
}

func TestMCPAuthMiddleware_AttachesPrincipalAndGatewayScope(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	principal := &identitydomain.Principal{Subject: "user-1", Method: identitydomain.MethodJWT}
	m := middleware.NewMCPAuthMiddleware(
		stubIdentityResolver{identity: middleware.Identity{
			GatewayID: gatewayID,
			AuthID:    authID,
			Principal: principal,
		}},
		stubDataFinder{data: &appconsumer.Data{}},
		stubGatewayFinder{gw: &gatewaydomain.Gateway{ID: gatewayID}},
	)
	app := newMCPAuthApp(t, m, func(c *fiber.Ctx) error {
		got := identitydomain.PrincipalFromContext(c.UserContext())
		require.NotNil(t, got, "principal must be attached to the request context")
		require.Equal(t, "user-1", got.Subject)
		gotGatewayID, ok := appconsumer.GatewayIDFromContext(c.UserContext())
		require.True(t, ok)
		require.Equal(t, gatewayID, gotGatewayID)
		return c.SendStatus(fiber.StatusOK)
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/dev/mcp", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, res.StatusCode)
}
