package oauth

import (
	"net/url"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

type CallbackHandler struct {
	proxy appoauth.AuthProxy
}

func NewCallbackHandler(proxy appoauth.AuthProxy) *CallbackHandler {
	return &CallbackHandler{proxy: proxy}
}

// Handle godoc
// @Summary      OAuth IdP callback (brokered)
// @Description  The gateway's stable redirect URI registered at the corporate IdP. Exchanges the IdP code (gateway-held PKCE verifier + client secret when configured), mints a single-use gateway code, and redirects back to the MCP client's own callback.
// @Tags         oauth
// @Param        code   query  string  false  "IdP authorization code"
// @Param        state  query  string  true   "gateway flow state"
// @Param        error  query  string  false  "IdP error, relayed to the client"
// @Success      302
// @Failure      400  {object}  appoauth.OAuthError
// @Router       /oauth/callback [get]
func (h *CallbackHandler) Handle(c *fiber.Ctx) error {
	location, err := h.proxy.Callback(
		c.UserContext(),
		c.BaseURL(),
		c.Query("state"),
		c.Query("code"),
		c.Query("error"),
		c.Query("error_description"),
	)
	if err != nil {
		return writeOAuthError(c, err)
	}
	if u, perr := url.Parse(location); perr == nil && u.Scheme != "http" && u.Scheme != "https" {
		return renderDeepLinkPage(c, location)
	}
	return c.Redirect(location, fiber.StatusFound)
}
