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

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const RegisterPath = "/oauth/register"

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
	res, err := h.metadata.RegisterClient(c.UserContext(), req)
	if err != nil {
		var oauthErr *appoauth.OAuthError
		if errors.Is(err, appoauth.ErrRegistrationUnavailable) || errors.As(err, &oauthErr) {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, res)
}
