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
	"net/url"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

type CallbackHandler struct {
	proxy appoauth.AuthProxy
}

func NewCallbackHandler(proxy appoauth.AuthProxy) *CallbackHandler {
	return &CallbackHandler{proxy: proxy}
}

func (h *CallbackHandler) Handle(c *fiber.Ctx) error {
	state := c.Query("state")
	// The binding is single-use: whatever happens next, the browser must start
	// over to get another one.
	bound := c.Cookies(stateCookieName(c))
	clearStateCookie(c)
	if err := requireStateBinding(bound, state); err != nil {
		return writeOAuthError(c, err)
	}
	location, err := h.proxy.Callback(
		c.UserContext(),
		c.BaseURL(),
		state,
		c.Query("code"),
		c.Query("error"),
		c.Query("error_description"),
		c.Query("iss"),
	)
	if err != nil {
		return writeOAuthError(c, err)
	}
	if u, perr := url.Parse(location); perr == nil && u.Scheme != "http" && u.Scheme != "https" {
		return renderDeepLinkPage(c, location)
	}
	return c.Redirect(location, fiber.StatusFound)
}
