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

package middleware

import (
	"log/slog"
	"maps"
	"slices"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/gofiber/fiber/v2"
)

// AgentAuthMiddleware guards the agent plane. It authenticates like the MCP
// plane, then admits the caller to the A2A consumer the path names. The
// handler reads that consumer with appconsumer.ConsumerFromContext and the
// caller with identity.PrincipalFromContext.
type AgentAuthMiddleware struct {
	resolver   IdentityResolver
	dataFinder appconsumer.DataFinder
	gateways   appgateway.Finder
}

// NewAgentAuthMiddleware builds the guard over a chain resolver scoped to
// agent paths.
func NewAgentAuthMiddleware(
	identityResolver IdentityResolver,
	dataFinder appconsumer.DataFinder,
	gateways appgateway.Finder,
) *AgentAuthMiddleware {
	return &AgentAuthMiddleware{resolver: identityResolver, dataFinder: dataFinder, gateways: gateways}
}

func (m *AgentAuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, err := m.resolver.Resolve(c)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
		}
		gw, err := m.gateways.FindByID(c.UserContext(), id.GatewayID)
		if err != nil {
			slog.LogAttrs(c.UserContext(), slog.LevelWarn, "agent auth: credential verified but its gateway is unreadable",
				slog.String("gateway_id", id.GatewayID.String()),
				slog.String("auth_id", id.AuthID.String()),
				slog.String("error", err.Error()))
			return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
		}
		data, err := m.dataFinder.FindByGateway(c.UserContext(), id.GatewayID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to load gateway data")
		}
		rc, ok := data.MatchAgentPath(c.Path())
		if !ok || rc.Consumer.Type != consumerdomain.TypeA2A {
			return fiber.NewError(fiber.StatusNotFound, "no agent application for this path")
		}
		if !slices.Contains(rc.Consumer.AuthIDs, id.AuthID) {
			return fiber.NewError(fiber.StatusForbidden, "credential not allowed for this consumer")
		}
		if !admitsPrincipal(rc.Consumer, id.Principal) {
			return fiber.NewError(fiber.StatusForbidden, "caller not allowed for this consumer")
		}
		principal, err := agentPrincipal(rc.Consumer, id.Principal, strings.TrimSpace(c.Get(consumerdomain.EndUserHeader)))
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		id.Principal = principal
		attachIdentity(c, id, gw, data)
		c.Locals(string(appconsumer.ConsumerKey), rc)
		c.SetUserContext(appconsumer.WithConsumer(c.UserContext(), rc))
		return c.Next()
	}
}

// admitsPrincipal applies the consumer's auth binding, as the MCP plane does:
// a bearer token must come from an allowed client and a certificate must
// carry an allowed subject.
func admitsPrincipal(cons *consumerdomain.Consumer, p *identity.Principal) bool {
	switch {
	case p == nil:
		return true
	case p.Method.IsBearerToken():
		return cons.AuthBinding.AllowsClient(p.Claims)
	case p.Method == identity.MethodMTLS:
		return cons.AuthBinding.AllowsCertificateClaims(p.Claims)
	default:
		return true
	}
}

// agentPrincipal is who the call runs as. A token keeps its own subject. An
// api key or a certificate proves only the application, so the call runs as
// the application, or as the end user it names in the end-user header,
// namespaced by the consumer. This mirrors the MCP plane.
func agentPrincipal(cons *consumerdomain.Consumer, caller *identity.Principal, endUser string) (*identity.Principal, error) {
	if caller == nil || (caller.Method != identity.MethodAPIKey && caller.Method != identity.MethodMTLS) {
		return caller, nil
	}
	if endUser == "" {
		p := *caller
		p.Subject = consumerdomain.AppSubject(cons.ID)
		p.Claims = maps.Clone(caller.Claims)
		if p.Claims == nil {
			p.Claims = map[string]any{}
		}
		p.Claims["consumer_id"] = cons.ID.String()
		if caller.Subject != "" {
			p.Claims[identity.ClaimCredentialSubject] = caller.Subject
		}
		return &p, nil
	}
	if err := consumerdomain.ValidateEndUser(endUser); err != nil {
		return nil, err
	}
	p := &identity.Principal{
		Subject: consumerdomain.EndUserSubject(cons.ID, endUser),
		Method:  caller.Method,
		Claims:  map[string]any{"end_user": endUser, "consumer_id": cons.ID.String()},
	}
	if caller.Subject != "" {
		p.Claims["app_subject"] = caller.Subject
	}
	return p, nil
}
