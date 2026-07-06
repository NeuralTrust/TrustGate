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

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const WellKnownAuthorizationServerPath = "/.well-known/oauth-authorization-server"

type AuthorizationServerHandler struct {
	metadata appoauth.MetadataService
}

func NewAuthorizationServerHandler(metadata appoauth.MetadataService) *AuthorizationServerHandler {
	return &AuthorizationServerHandler{metadata: metadata}
}

func (h *AuthorizationServerHandler) Handle(c *fiber.Ctx) error {
	doc, err := h.metadata.AuthorizationServer(c.UserContext(), c.BaseURL())
	if err != nil {
		if errors.Is(err, appoauth.ErrNoAuthorizationServer) || errors.Is(err, appoauth.ErrAmbiguousAuthorizationServer) {
			return fiber.NewError(fiber.StatusNotFound, err.Error())
		}
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, doc)
}
