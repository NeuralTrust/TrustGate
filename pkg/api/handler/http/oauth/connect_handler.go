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

func (h *ConnectHandler) Page(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if ticket == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the tool call to get a fresh connect link")
	}
	return h.showPage(c, ticket, "")
}

func (h *ConnectHandler) Start(c *fiber.Ctx) error {
	location, err := h.connect.Start(c.UserContext(), c.BaseURL(), c.Query("ticket"), c.Params("provider"))
	if err != nil {
		return h.pageError(c, err)
	}
	return c.Redirect(location, fiber.StatusFound)
}

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
