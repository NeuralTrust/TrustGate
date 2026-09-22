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
	"errors"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

// WhoAmIPath is served without a consumer slug, because resolving the slug is
// what it is for.
const WhoAmIPath = "/whoami"

// WhoAmIHandler answers what an api key reaches, so a client does not have to
// be told.
//
// Everything a client needs to start is behind one secret: which consumers
// this key is attached to, which plane each one is, and the URL to reach it
// on. Without this an agent's configuration carries slugs that were chosen in
// the console by somebody else — and, worse, a base URL per plane, because the
// planes do not share a host.
type WhoAmIHandler struct {
	gateways    resolver.GatewayResolver
	consumers   appconsumer.APIKeyConsumers
	proxyDomain string
}

// proxyDomain is GATEWAY_BASE_DOMAIN: the suffix the LLM plane is published
// under, which this plane cannot see from a request of its own.
func NewWhoAmIHandler(
	gateways resolver.GatewayResolver,
	consumers appconsumer.APIKeyConsumers,
	proxyDomain string,
) *WhoAmIHandler {
	return &WhoAmIHandler{gateways: gateways, consumers: consumers, proxyDomain: proxyDomain}
}

// WhoAmIConsumer is one consumer the key reaches, with the address to use it.
type WhoAmIConsumer struct {
	Slug string `json:"slug"`
	Name string `json:"name,omitempty"`
	// Type is the plane this consumer belongs to: MCP, LLM or A2A.
	Type   string `json:"type"`
	Active bool   `json:"active"`
	// URL is where this consumer is served — the MCP endpoint for an MCP
	// consumer, the provider-compatible base URL for an LLM one. Empty when
	// the gateway has no public host configured for that plane.
	URL string `json:"url,omitempty"`
}

// WhoAmIResponse is everything a client can learn from its own key.
type WhoAmIResponse struct {
	Gateway   string           `json:"gateway"`
	Consumers []WhoAmIConsumer `json:"consumers"`
}

// Handle godoc
// @Summary      Describe what an API key reaches
// @Description  Returns the consumers this API key is attached to, one per plane, each with the URL it is served on. A key is attached to consumers and a consumer has one type, so an agent that calls both tools and models holds an MCP consumer and an LLM one behind the same key; this is how a client learns their slugs and addresses instead of being configured with them. Carries no identifiers and no credentials. An unknown, disabled or foreign key is refused without saying which.
// @Tags         mcp
// @Produce      json
// @Success      200  {object}  WhoAmIResponse
// @Failure      401  {object}  httpio.ErrorBody
// @Router       /whoami [get]
func (h *WhoAmIHandler) Handle(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Locals(middleware.OAuthChallengeAllowedLocal, false)
	gateway, err := h.gateways.Resolve(c)
	if err != nil || gateway == nil {
		return writeWhoAmIError(c, fiber.StatusUnauthorized, "unknown gateway")
	}
	consumers, err := h.consumers.ForAPIKey(
		c.UserContext(), gateway.ID, resolver.APIKeyFromRequest(c),
	)
	if err != nil {
		if errors.Is(err, appconsumer.ErrAPIKeyUnknown) {
			return writeWhoAmIError(c, fiber.StatusUnauthorized, "invalid API key for this gateway")
		}
		return writeWhoAmIError(c, fiber.StatusInternalServerError, "failed to describe this API key")
	}

	out := WhoAmIResponse{Gateway: gateway.Slug, Consumers: make([]WhoAmIConsumer, 0, len(consumers))}
	for _, cons := range consumers {
		out.Consumers = append(out.Consumers, WhoAmIConsumer{
			Slug:   cons.Slug,
			Name:   cons.Name,
			Type:   string(cons.Type),
			Active: cons.Active,
			URL:    h.consumerURL(c, gateway, cons),
		})
	}
	return c.Status(fiber.StatusOK).JSON(out)
}

// consumerURL is where this consumer answers.
//
// An MCP consumer is served by the plane that is answering right now, so its
// address is built from the origin the caller already reached — whatever host,
// scheme or port that turned out to be. An LLM consumer lives on the proxy
// plane, which is a different host, and is the reason this endpoint returns
// URLs at all rather than slugs: a client cannot compose that one from what it
// has.
func (h *WhoAmIHandler) consumerURL(
	c *fiber.Ctx,
	gateway *gatewaydomain.Gateway,
	cons appconsumer.KeyConsumer,
) string {
	switch cons.Type {
	case consumerdomain.TypeMCP:
		return strings.TrimRight(c.BaseURL(), "/") + "/" + cons.Slug + "/mcp"
	case consumerdomain.TypeLLM:
		host := h.proxyHost(gateway)
		if host == "" {
			return ""
		}
		return c.Protocol() + "://" + host + "/" + cons.Slug + "/v1"
	default:
		return ""
	}
}

func (h *WhoAmIHandler) proxyHost(gateway *gatewaydomain.Gateway) string {
	if domain := strings.TrimSpace(gateway.Domain); domain != "" {
		return domain
	}
	base := strings.Trim(strings.TrimSpace(h.proxyDomain), ".")
	if base == "" || gateway.Slug == "" {
		return ""
	}
	return gateway.Slug + "." + base
}

func writeWhoAmIError(c *fiber.Ctx, status int, message string) error {
	code := "unauthenticated"
	if status >= 500 {
		code = "internal_error"
	}
	return c.Status(status).JSON(httpio.ErrorBody{Error: code, Message: message})
}
