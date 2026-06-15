package oauth

import (
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const AuthorizePath = "/oauth/authorize"

type AuthorizeHandler struct {
	proxy appoauth.AuthProxy
}

func NewAuthorizeHandler(proxy appoauth.AuthProxy) *AuthorizeHandler {
	return &AuthorizeHandler{proxy: proxy}
}

func (h *AuthorizeHandler) Handle(c *fiber.Ctx) error {
	req := appoauth.AuthorizeRequest{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		State:               c.Query("state"),
		Scope:               c.Query("scope"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		Resource:            c.Query("resource"),
	}
	location, err := h.proxy.Authorize(c.UserContext(), c.BaseURL(), req)
	if err != nil {
		return writeOAuthError(c, err)
	}
	return c.Redirect(location, fiber.StatusFound)
}
