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

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const (
	// UserHeadersSavePath is where the connect page posts a person's header
	// values for one server instance.
	UserHeadersSavePath = "/oauth/user-headers/:instance"
	// UserHeadersRemovePath is where it posts to remove them.
	UserHeadersRemovePath = "/oauth/user-headers-remove/:instance"
)

// maxUserHeaderFormBytes bounds the form a person posts with their keys.
const maxUserHeaderFormBytes = 64 << 10

// SaveUserHeaders stores the header values a person entered on the connect
// page, then shows the page again with what is now stored.
func (h *ConnectHandler) SaveUserHeaders(c *fiber.Ctx) error {
	enroll, err := h.userHeaderEnrollment(c)
	if err != nil {
		return err
	}
	if !isFormURLEncoded(c.Get(fiber.HeaderContentType)) {
		return fiber.NewError(fiber.StatusUnsupportedMediaType, "expected application/x-www-form-urlencoded")
	}
	if len(c.Body()) > maxUserHeaderFormBytes {
		return fiber.NewError(fiber.StatusRequestEntityTooLarge, "form too large")
	}
	form, err := url.ParseQuery(string(c.Body()))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "malformed form")
	}
	values := make(map[string]string, len(form))
	for name, vs := range form {
		if len(vs) > 0 {
			values[name] = vs[0]
		}
	}
	ticket := c.Query("ticket")
	if err := enroll.SaveUserHeaders(c.UserContext(), ticket, c.Params("instance"), values); err != nil {
		return h.userHeaderError(c, ticket, err)
	}
	return h.showPage(c, ticket, "")
}

// RemoveUserHeaders deletes the header values a person holds for one server.
func (h *ConnectHandler) RemoveUserHeaders(c *fiber.Ctx) error {
	enroll, err := h.userHeaderEnrollment(c)
	if err != nil {
		return err
	}
	ticket := c.Query("ticket")
	if err := enroll.RemoveUserHeaders(c.UserContext(), ticket, c.Params("instance")); err != nil {
		return h.userHeaderError(c, ticket, err)
	}
	return h.showPage(c, ticket, "")
}

// userHeaderEnrollment refuses a write that did not come from the gateway's
// own page, and one this plane's connect service cannot serve.
func (h *ConnectHandler) userHeaderEnrollment(c *fiber.Ctx) (appoauth.UserHeaderEnrollment, error) {
	c.Set(fiber.HeaderCacheControl, "no-store")
	if !sentFromOwnPage(c) {
		return nil, h.pageError(c, errConnectNotFromPage)
	}
	enroll, ok := h.connect.(appoauth.UserHeaderEnrollment)
	if !ok {
		return nil, fiber.NewError(fiber.StatusNotFound, "per-user keys are not available here")
	}
	if strings.TrimSpace(c.Query("ticket")) == "" {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "missing ticket: re-run the tool call to get a fresh connect link")
	}
	return enroll, nil
}

func (h *ConnectHandler) userHeaderError(c *fiber.Ctx, ticket string, err error) error {
	switch {
	case errors.Is(err, appoauth.ErrUserHeaderInvalid):
		// The message names the header, never the value; the person fixes it
		// on the same page.
		return h.showPage(c, ticket, err.Error())
	case errors.Is(err, appoauth.ErrUserHeaderServerNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	default:
		return h.pageError(c, err)
	}
}
