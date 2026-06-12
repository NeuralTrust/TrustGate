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

// Handle godoc
// @Summary      OAuth 2.1 authorization endpoint (brokered)
// @Description  Parks the MCP client's authorize request (redirect_uri + PKCE) and redirects the user to the configured corporate IdP. The IdP only ever sees the gateway's own stable redirect URI.
// @Tags         oauth
// @Param        response_type          query  string  true   "must be code"
// @Param        client_id              query  string  false  "client id issued via /oauth/register"
// @Param        redirect_uri           query  string  true   "client callback (custom schemes and loopback allowed)"
// @Param        state                  query  string  false  "client state, relayed back"
// @Param        scope                  query  string  false  "requested scopes"
// @Param        code_challenge         query  string  true   "PKCE S256 challenge"
// @Param        code_challenge_method  query  string  false  "must be S256"
// @Param        resource               query  string  false  "RFC 8707 resource indicator (virtual MCP URL)"
// @Success      302
// @Failure      400  {object}  appoauth.OAuthError
// @Router       /oauth/authorize [get]
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
