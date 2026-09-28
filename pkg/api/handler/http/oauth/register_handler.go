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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const RegisterPath = appoauth.RegisterBasePath

// RegisterClientPath is a single client's RFC 7592 management URI, the address
// the registration response hands back as registration_client_uri.
const RegisterClientPath = RegisterPath + "/:client_id"

type RegisterHandler struct {
	metadata appoauth.MetadataService
}

func NewRegisterHandler(metadata appoauth.MetadataService) *RegisterHandler {
	return &RegisterHandler{metadata: metadata}
}

func (h *RegisterHandler) Handle(c *fiber.Ctx) error {
	var req appoauth.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid client registration request")
	}
	res, err := h.metadata.RegisterClient(c.UserContext(), c.BaseURL(), req)
	if err != nil {
		return h.writeError(c, err)
	}
	return httpio.WriteCreated(c, res)
}

// Read serves the RFC 7592 read of one registration.
func (h *RegisterHandler) Read(c *fiber.Ctx) error {
	res, err := h.metadata.ReadClient(c.UserContext(), c.BaseURL(), c.Params("client_id"), registrationToken(c))
	if err != nil {
		return h.writeError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(res)
}

// Update replaces the metadata of one registration.
func (h *RegisterHandler) Update(c *fiber.Ctx) error {
	var req appoauth.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid client registration request")
	}
	// RFC 7592 section 2.2 requires the body to name the client it addresses.
	// A mismatch is a client-side error, not a licence to update whatever the
	// path named.
	if body := strings.TrimSpace(req.ClientID); body != "" && body != c.Params("client_id") {
		return fiber.NewError(fiber.StatusBadRequest, "client_id does not match the registration being updated")
	}
	res, err := h.metadata.UpdateClient(c.UserContext(), c.BaseURL(), c.Params("client_id"), registrationToken(c), req)
	if err != nil {
		return h.writeError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(res)
}

// Delete withdraws one registration.
func (h *RegisterHandler) Delete(c *fiber.Ctx) error {
	if err := h.metadata.DeleteClient(c.UserContext(), c.Params("client_id"), registrationToken(c)); err != nil {
		return h.writeError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// writeError maps registration failures onto the statuses RFC 7592 expects. A
// missing registration and a token that does not match it both answer 401: a
// 404 for one and a 401 for the other would tell an unauthenticated caller
// which client ids exist.
func (h *RegisterHandler) writeError(c *fiber.Ctx, err error) error {
	var oauthErr *appoauth.OAuthError
	switch {
	case errors.Is(err, appoauth.ErrClientNotFound), errors.Is(err, appoauth.ErrRegistrationForbidden):
		return fiber.NewError(fiber.StatusUnauthorized, "invalid registration access token")
	case errors.Is(err, appoauth.ErrRegistrationUnavailable), errors.As(err, &oauthErr):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	default:
		return httpio.WriteError(c, err)
	}
}

func registrationToken(c *fiber.Ctx) string {
	token, ok := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(token)
}
