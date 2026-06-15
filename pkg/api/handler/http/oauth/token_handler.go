package oauth

import (
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const TokenPath = "/oauth/token" // #nosec G101 -- route path, not a credential

type TokenHandler struct {
	proxy appoauth.AuthProxy
}

func NewTokenHandler(proxy appoauth.AuthProxy) *TokenHandler {
	return &TokenHandler{proxy: proxy}
}

func (h *TokenHandler) Handle(c *fiber.Ctx) error {
	req := appoauth.TokenRequest{
		GrantType:    c.FormValue("grant_type"),
		Code:         c.FormValue("code"),
		RedirectURI:  c.FormValue("redirect_uri"),
		ClientID:     c.FormValue("client_id"),
		CodeVerifier: c.FormValue("code_verifier"),
		RefreshToken: c.FormValue("refresh_token"),
		Resource:     c.FormValue("resource"),
	}
	token, err := h.proxy.Exchange(c.UserContext(), c.BaseURL(), req)
	if err != nil {
		return writeOAuthError(c, err)
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return helpers.WriteOK(c, token)
}

func writeOAuthError(c *fiber.Ctx, err error) error {
	var oe *appoauth.OAuthError
	if errors.As(err, &oe) {
		status := fiber.StatusBadRequest
		if oe.Code == "invalid_client" {
			status = fiber.StatusUnauthorized
		}
		return c.Status(status).JSON(oe)
	}
	if errors.Is(err, appoauth.ErrNoAuthorizationServer) || errors.Is(err, appoauth.ErrAmbiguousAuthorizationServer) {
		return c.Status(fiber.StatusNotFound).JSON(appoauth.OAuthError{Code: "invalid_request", Description: err.Error()})
	}
	return helpers.WriteError(c, err)
}
