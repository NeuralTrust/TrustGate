package oauth

import (
	"errors"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const (
	ConnectStartPath    = "/oauth/connect/:provider"
	ConnectCallbackPath = "/oauth/callback/:provider"
	DisconnectPath      = "/oauth/disconnect/:provider"
)

type ConnectHandler struct {
	connect appoauth.ConnectService
}

func NewConnectHandler(connect appoauth.ConnectService) *ConnectHandler {
	return &ConnectHandler{connect: connect}
}

// Page godoc
// @Summary      Third-party account connect page
// @Description  Lists the forwarded-mode providers behind this virtual MCP with linked status and connect/revoke actions. Requires the ticket from the consent elicitation error.
// @Tags         oauth
// @Produce      html
// @Param        ticket  query  string  true  "consent ticket"
// @Success      200
// @Failure      401
// @Router       /{consumer_path}/connect [get]
func (h *ConnectHandler) Page(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if ticket == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the tool call to get a fresh connect link")
	}
	return h.showPage(c, ticket, "")
}

// Start godoc
// @Summary      Begin linking one provider
// @Description  Redirects the user to the third-party consent screen. The gateway is the OAuth client; tokens land in the vault, never in the agent.
// @Tags         oauth
// @Param        provider  path   string  true  "provider key (e.g. github)"
// @Param        ticket    query  string  true  "consent ticket"
// @Success      302
// @Router       /oauth/connect/{provider} [get]
func (h *ConnectHandler) Start(c *fiber.Ctx) error {
	location, err := h.connect.Start(c.UserContext(), c.BaseURL(), c.Query("ticket"), c.Params("provider"))
	if err != nil {
		return h.pageError(c, err)
	}
	return c.Redirect(location, fiber.StatusFound)
}

// Callback godoc
// @Summary      Provider consent callback
// @Description  Exchanges the provider code, stores the encrypted tokens in the vault for (gateway, principal, provider), and returns to the connect page.
// @Tags         oauth
// @Param        provider  path   string  true   "provider key"
// @Param        code      query  string  false  "authorization code"
// @Param        state     query  string  true   "opaque state"
// @Success      302
// @Router       /oauth/callback/{provider} [get]
func (h *ConnectHandler) Callback(c *fiber.Ctx) error {
	ticketID, err := h.connect.Callback(
		c.UserContext(), c.BaseURL(), c.Params("provider"),
		c.Query("state"), c.Query("code"), c.Query("error"), c.Query("error_description"),
	)
	if err != nil {
		if ticketID == "" {
			return h.pageError(c, err)
		}
		return h.showPage(c, ticketID, err.Error())
	}
	return h.showPage(c, ticketID, "")
}

// Disconnect godoc
// @Summary      Revoke a linked provider account
// @Tags         oauth
// @Param        provider  path   string  true  "provider key"
// @Param        ticket    query  string  true  "consent ticket"
// @Success      200
// @Router       /oauth/disconnect/{provider} [post]
func (h *ConnectHandler) Disconnect(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if err := h.connect.Disconnect(c.UserContext(), ticket, c.Params("provider")); err != nil {
		return h.pageError(c, err)
	}
	return h.showPage(c, ticket, "")
}

func (h *ConnectHandler) showPage(c *fiber.Ctx, ticket, flash string) error {
	page, err := h.connect.Page(c.UserContext(), ticket)
	if err != nil {
		return h.pageError(c, err)
	}
	return renderConnectPage(c, page, ticket, flash)
}

func (h *ConnectHandler) pageError(c *fiber.Ctx, err error) error {
	if errors.Is(err, appoauth.ErrTicketNotFound) {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	if errors.Is(err, appoauth.ErrProviderNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return err
}
