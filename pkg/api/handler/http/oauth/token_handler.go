package oauth

import (
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// TokenPath is the gateway's OAuth 2.1 token endpoint for MCP clients.
const TokenPath = "/oauth/token" // #nosec G101 -- route path, not a credential

type TokenHandler struct {
	proxy appoauth.AuthProxy
}

func NewTokenHandler(proxy appoauth.AuthProxy) *TokenHandler {
	return &TokenHandler{proxy: proxy}
}

// Handle godoc
// @Summary      OAuth 2.1 token endpoint (brokered)
// @Description  Redeems a gateway-minted code (PKCE-verified) for the IdP token response, or proxies refresh_token grants to the IdP.
// @Tags         oauth
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        grant_type     formData  string  true   "authorization_code or refresh_token"
// @Param        code           formData  string  false  "gateway-minted code"
// @Param        redirect_uri   formData  string  false  "must match the authorize request"
// @Param        client_id      formData  string  false  "client id"
// @Param        code_verifier  formData  string  false  "PKCE verifier"
// @Param        refresh_token  formData  string  false  "refresh token"
// @Param        resource       formData  string  false  "RFC 8707 resource indicator (the virtual MCP URL); selects the IdP on refresh_token grants"
// @Success      200  {object}  map[string]any
// @Failure      400  {object}  appoauth.OAuthError
// @Router       /oauth/token [post]
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

// writeOAuthError renders RFC 6749 error responses: structured OAuth errors
// keep their code (400, or 401 for invalid_client); anything else is internal.
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
