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

package oauth

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

// EndUserConnectionsHandler serves the connections API an application uses for
// the end users it identifies itself (identity.source = app), on the MCP plane
// next to the consumer it belongs to:
//
//	POST /{slug}/connections/links  {end_user, provider?} → a connect link for that user
//	GET  /{slug}/connections?end_user=…                    → that user's connection states
//	GET  /{slug}/connections                               → the application's own
//
// All three authenticate with the consumer's API key, like the MCP requests the
// application makes. Omitting end_user asks about the other actor: the
// application acting as itself, which is the question a batch has to be able to
// ask before it starts, since nobody is present to open a connect link once it
// is running.
type EndUserConnectionsHandler struct {
	gateways      resolver.GatewayResolver
	connections   appoauth.EndUserConnectionsService
	limiter       appoauth.ConnectAttemptLimiter
	resolveSource ConnectSourceResolver
}

func NewEndUserConnectionsHandler(
	gateways resolver.GatewayResolver,
	connections appoauth.EndUserConnectionsService,
	limiter appoauth.ConnectAttemptLimiter,
	resolveSource ConnectSourceResolver,
) *EndUserConnectionsHandler {
	return &EndUserConnectionsHandler{
		gateways:      gateways,
		connections:   connections,
		limiter:       limiter,
		resolveSource: resolveSource,
	}
}

// EndUserLinkRequest names the end user (and optionally the server) to link.
type EndUserLinkRequest struct {
	EndUser  string `json:"end_user"`
	Provider string `json:"provider,omitempty"`
}

// EndUserLinkResponse is the link the application shows its user.
type EndUserLinkResponse struct {
	ConnectURL string    `json:"connect_url"`
	Ticket     string    `json:"ticket"`
	Provider   string    `json:"provider,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// EndUserConnectionResponse is one upstream connection state of an end user.
type EndUserConnectionResponse struct {
	Provider   string     `json:"provider"`
	Registry   string     `json:"registry,omitempty"`
	Code       string     `json:"code,omitempty"`
	Status     string     `json:"status"`
	AccountRef string     `json:"account_ref,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// EndUserConnectionsResponse lists the connection states of one actor: the end
// user named in end_user, or the application itself when none was.
type EndUserConnectionsResponse struct {
	// EndUser is empty when the states are the application's own.
	EndUser string `json:"end_user"`
	// Actor names whose connections these are: "end_user" or "application".
	// Without it an empty end_user would read as an unnamed user.
	Actor       string                      `json:"actor"`
	Connections []EndUserConnectionResponse `json:"connections"`
}

// Actors a connection listing can answer for.
const (
	actorEndUser     = "end_user"
	actorApplication = "application"
)

// Link godoc
// @Summary      Mint a connect link for an application's end user
// @Description  Returns the URL an application shows one of its end users to connect that person's own account on one of the consumer's servers (or on any of them when provider is omitted). Any MCP consumer may name an end user — who a request runs as is read from the request, not declared on the consumer. Authenticated with the consumer's API key.
// @Tags         connections
// @Accept       json
// @Produce      json
// @Param        slug   path  string                     true  "Consumer slug"
// @Param        body   body  EndUserLinkRequest         true  "End user to link"
// @Success      201    {object}  EndUserLinkResponse
// @Failure      400    {object}  httpio.ErrorBody
// @Failure      401    {object}  httpio.ErrorBody
// @Failure      429    {object}  httpio.ErrorBody
// @Router       /{slug}/connections/links [post]
func (h *EndUserConnectionsHandler) Link(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Locals(middleware.OAuthChallengeAllowedLocal, false)
	if err := h.checkSource(c); err != nil {
		return err
	}
	gateway, err := h.gateways.Resolve(c)
	if err != nil || gateway == nil {
		return writeConnectionsError(c, fiber.StatusUnauthorized, "unauthenticated", "unknown gateway")
	}
	var body EndUserLinkRequest
	if err := c.BodyParser(&body); err != nil {
		return writeConnectionsError(c, fiber.StatusBadRequest, "invalid_request", "invalid request body")
	}
	slug := c.Params("slug")
	link, err := h.connections.Link(c.UserContext(), gateway.ID, slug, resolver.APIKeyFromRequest(c), body.EndUser, body.Provider)
	if err != nil {
		return h.writeServiceError(c, err)
	}
	connectURL := c.BaseURL() + "/" + slug + "/mcp/connect?ticket=" + url.QueryEscape(link.Ticket)
	if link.Provider != "" {
		connectURL = c.BaseURL() + strings.TrimSuffix(ConnectStartPath, "*") + url.PathEscape(link.Provider) + "?ticket=" + url.QueryEscape(link.Ticket)
	}
	return c.Status(fiber.StatusCreated).JSON(EndUserLinkResponse{
		ConnectURL: connectURL,
		Ticket:     link.Ticket,
		Provider:   link.Provider,
		ExpiresAt:  link.ExpiresAt,
	})
}

// List godoc
// @Summary      Read connection states for an end user or for the application itself
// @Description  Reports, per connectable server, whether the actor is connected, needs to reconnect, or has not connected. Naming end_user asks about that person, under this application. Omitting it asks about the application acting as itself (app:<consumer_id>) — the preflight a batch runs before it starts, since nobody is there to follow a connect link once it is running. Both actors belong to every MCP consumer, so neither form is ever refused for being the wrong one. Authenticated with the consumer's API key.
// @Tags         connections
// @Produce      json
// @Param        slug      path   string  true   "Consumer slug"
// @Param        end_user  query  string  false  "End-user id the application uses; omit to ask about the application itself"
// @Success      200       {object}  EndUserConnectionsResponse
// @Failure      400       {object}  httpio.ErrorBody
// @Failure      401       {object}  httpio.ErrorBody
// @Router       /{slug}/connections [get]
func (h *EndUserConnectionsHandler) List(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Locals(middleware.OAuthChallengeAllowedLocal, false)
	if err := h.checkSource(c); err != nil {
		return err
	}
	gateway, err := h.gateways.Resolve(c)
	if err != nil || gateway == nil {
		return writeConnectionsError(c, fiber.StatusUnauthorized, "unauthenticated", "unknown gateway")
	}
	endUser := strings.TrimSpace(c.Query("end_user"))
	actor := actorEndUser
	var items []appoauth.EndUserConnection
	if endUser == "" {
		actor = actorApplication
		items, err = h.connections.AppConnections(
			c.UserContext(), gateway.ID, c.Params("slug"), resolver.APIKeyFromRequest(c))
	} else {
		items, err = h.connections.Connections(
			c.UserContext(), gateway.ID, c.Params("slug"), resolver.APIKeyFromRequest(c), endUser)
	}
	if err != nil {
		return h.writeServiceError(c, err)
	}
	out := EndUserConnectionsResponse{
		EndUser:     endUser,
		Actor:       actor,
		Connections: make([]EndUserConnectionResponse, 0, len(items)),
	}
	for _, item := range items {
		entry := EndUserConnectionResponse{
			Provider:   item.Provider,
			Registry:   item.Registry,
			Code:       item.Code,
			Status:     item.Status,
			AccountRef: item.AccountRef,
		}
		if !item.ExpiresAt.IsZero() {
			expires := item.ExpiresAt
			entry.ExpiresAt = &expires
		}
		out.Connections = append(out.Connections, entry)
	}
	return c.Status(fiber.StatusOK).JSON(out)
}

func (h *EndUserConnectionsHandler) checkSource(c *fiber.Ctx) error {
	if h.limiter == nil || h.resolveSource == nil {
		return nil
	}
	source := h.resolveSource(c.Context().RemoteAddr().String(), c.Get(fiber.HeaderXForwardedFor))
	if err := h.limiter.Check(c.UserContext(), appoauth.ConnectAttemptScopeSource, source); err != nil {
		return h.writeServiceError(c, err)
	}
	return nil
}

func (h *EndUserConnectionsHandler) writeServiceError(c *fiber.Ctx, err error) error {
	var exceeded *appoauth.ConnectRateLimitExceeded
	switch {
	case errors.As(err, &exceeded):
		return writeAPIKeyConnectRateLimited(c, exceeded)
	case errors.Is(err, appoauth.ErrConnectRateLimitUnavailable):
		return writeConnectionsError(c, fiber.StatusServiceUnavailable, "unavailable", "rate limiter unavailable")
	case errors.Is(err, appoauth.ErrAPIKeyConnectUnauthorized), errors.Is(err, appauth.ErrInvalidAuthRequest):
		return writeConnectionsError(c, fiber.StatusUnauthorized, "unauthenticated", "invalid API key for this consumer")
	case errors.Is(err, commonerrors.ErrValidation):
		return writeConnectionsError(c, fiber.StatusBadRequest, "invalid_request", err.Error())
	default:
		return writeConnectionsError(c, fiber.StatusInternalServerError, "internal_error", "failed to process the request")
	}
}

func writeConnectionsError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(httpio.ErrorBody{Error: code, Message: message})
}
